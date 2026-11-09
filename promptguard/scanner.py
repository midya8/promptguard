from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
from typing import Iterable

from .models import Finding, SEVERITY_ORDER, ScanResult

TEXT_EXTENSIONS = {".md", ".markdown", ".txt", ".prompt", ".json", ".yaml", ".yml"}
SKIP_DIRS = {".git", ".hg", ".svn", "__pycache__", "node_modules", ".venv", "venv"}
MAX_FILE_BYTES = 1_000_000

SECRET_ASSIGNMENT = re.compile(r"(?i)\b(api[_-]?key|secret|token|password)\b\s*[:=]\s*['\"]?([A-Za-z0-9_./+=-]{12,})")
OPENAI_KEY = re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")
AWS_KEY = re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")
PRIVATE_KEY = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----")
EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
PHONE = re.compile(r"(?<!\d)(?:\+?1[\s.-]?)?(?:\(\d{3}\)|\d{3})[\s.-]\d{3}[\s.-]\d{4}(?!\d)")
CARD = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")
GITHUB_TOKEN = re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{22,}\b")
SLACK_TOKEN = re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")
GOOGLE_KEY = re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")
JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\b")

TOKEN_RULES = (
    ("SECRET_GITHUB_TOKEN", GITHUB_TOKEN, "critical", "GitHub token material found"),
    ("SECRET_SLACK_TOKEN", SLACK_TOKEN, "critical", "Slack token material found"),
    ("SECRET_GOOGLE_KEY", GOOGLE_KEY, "critical", "Google API key material found"),
    ("SECRET_JWT", JWT, "high", "JSON Web Token material found"),
)

INJECTION_RULES = (
    ("INJECTION_IGNORE", re.compile(r"(?i)\b(?:ignore|disregard|forget)\b[^\n]{0,40}\b(?:previous|above|prior)\b[^\n]{0,30}\binstructions\b"), "prompt tells the model to ignore earlier instructions"),
    ("INJECTION_REVEAL", re.compile(r"(?i)\b(?:reveal|print|show|leak)\b[^\n]{0,40}\b(?:system|developer)\s+prompt\b"), "prompt asks for hidden system or developer instructions"),
    ("INJECTION_BYPASS", re.compile(r"(?i)\b(?:bypass|disable|circumvent)\b[^\n]{0,40}\b(?:safety|security|policy|guardrails?)\b"), "prompt asks to bypass safety or security controls"),
    ("INJECTION_EXFILTRATE", re.compile(r"(?i)\b(?:exfiltrate|steal|upload|send)\b[^\n]{0,50}\b(?:api[_ -]?keys?|secrets?|passwords?|credentials?|private data)\b"), "prompt asks to exfiltrate credentials or private data"),
    ("ROLE_CONFUSION", re.compile(r"(?i)\b(?:you are now|act as|pretend to be)\b[^\n]{0,50}\b(?:DAN|unrestricted|jailbroken|root)\b"), "prompt attempts role or privilege confusion"),
)


def _digest(material: str) -> str:
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _line_excerpt(text: str) -> str:
    return " ".join(text.strip().split())[:180]


def _redact(text: str) -> str:
    text = OPENAI_KEY.sub(lambda m: m.group(0)[:7] + "...REDACTED", text)
    text = AWS_KEY.sub(lambda m: m.group(0)[:4] + "...REDACTED", text)
    text = GITHUB_TOKEN.sub(lambda m: m.group(0)[:8] + "...REDACTED", text)
    text = SLACK_TOKEN.sub(lambda m: m.group(0)[:8] + "...REDACTED", text)
    text = GOOGLE_KEY.sub(lambda m: m.group(0)[:7] + "...REDACTED", text)
    text = JWT.sub(lambda m: m.group(0)[:12] + "...REDACTED", text)
    text = SECRET_ASSIGNMENT.sub(lambda m: f"{m.group(1)}=<redacted>", text)
    text = EMAIL.sub("<email>", text)
    text = PHONE.sub("<phone>", text)
    text = CARD.sub(lambda m: "<card>" if _luhn_ok(re.sub(r"\D", "", m.group(0))) else m.group(0), text)
    return text


def _luhn_ok(number: str) -> bool:
    if not 13 <= len(number) <= 19:
        return False
    total = 0
    double = False
    for char in reversed(number):
        value = int(char)
        if double:
            value *= 2
            if value > 9:
                value -= 9
        total += value
        double = not double
    return total % 10 == 0


def _frontmatter_findings(path: Path, text: str) -> Iterable[Finding]:
    if path.suffix.lower() not in {".md", ".markdown", ".prompt"}:
        return ()
    display = str(path)
    if not text.startswith("---\n"):
        first = text.splitlines()[0] if text.splitlines() else ""
        redacted = _redact(first)
        # Keep rotated material distinguishable without exposing it in the excerpt.
        digest = _digest(first) if redacted != first else None
        return (
            Finding("STRUCTURE_FRONTMATTER", "info", display, 1, "prompt file has no metadata frontmatter", _line_excerpt(redacted), digest),
        )
    end = text.find("\n---", 4)
    if end == -1:
        return (
            Finding("STRUCTURE_FRONTMATTER", "low", display, 1, "metadata frontmatter is not closed", "---"),
        )
    header = text[4:end]
    findings = []
    for field in ("name", "description", "version"):
        if not re.search(rf"^\s*{re.escape(field)}\s*:", header, re.MULTILINE):
            findings.append(Finding("STRUCTURE_FIELD", "low", display, 1, f"metadata frontmatter missing `{field}`", "---"))
    return tuple(findings)


def scan_text(path: Path, text: str) -> tuple[Finding, ...]:
    findings: list[Finding] = []
    display = str(path)
    lines = text.splitlines()
    for number, line in enumerate(lines, 1):
        excerpt = _line_excerpt(_redact(line))
        for match in SECRET_ASSIGNMENT.finditer(line):
            findings.append(Finding("SECRET_ASSIGNMENT", "high", display, number, "possible secret assigned in prompt or config", excerpt, _digest(match.group(2))))
        for match in OPENAI_KEY.finditer(line):
            findings.append(Finding("SECRET_OPENAI_KEY", "critical", display, number, "OpenAI-style API key material found", excerpt, _digest(match.group(0))))
        for match in AWS_KEY.finditer(line):
            findings.append(Finding("SECRET_AWS_KEY", "critical", display, number, "AWS-style access key material found", excerpt, _digest(match.group(0))))
        for match in PRIVATE_KEY.finditer(line):
            # Bind to the first body line as well, since the header alone is
            # identical for every private key.
            body = ""
            for candidate in lines[number:number + 4]:
                stripped = candidate.strip()
                if stripped and not stripped.startswith("-----"):
                    body = stripped
                    break
            findings.append(Finding("SECRET_PRIVATE_KEY", "critical", display, number, "private key material found", excerpt, _digest(match.group(0) + "\n" + body)))
        for rule_id, pattern, severity, message in TOKEN_RULES:
            for match in pattern.finditer(line):
                findings.append(Finding(rule_id, severity, display, number, message, excerpt, _digest(match.group(0))))
        for match in EMAIL.finditer(line):
            findings.append(Finding("PII_EMAIL", "medium", display, number, "email address found", excerpt, _digest(match.group(0).lower())))
        for match in PHONE.finditer(line):
            findings.append(Finding("PII_PHONE", "low", display, number, "phone number found", excerpt, _digest(re.sub(r"\D", "", match.group(0)))))
        for card in CARD.finditer(line):
            digits = re.sub(r"\D", "", card.group(0))
            if _luhn_ok(digits):
                findings.append(Finding("PII_PAYMENT_CARD", "critical", display, number, "payment-card number found", excerpt, _digest(digits)))
        for rule_id, pattern, message in INJECTION_RULES:
            if pattern.search(line):
                findings.append(Finding(rule_id, "high", display, number, message, excerpt))
    findings.extend(_frontmatter_findings(path, text))
    return tuple(findings)


def _iter_files(paths: Iterable[str]) -> tuple[list[Path], list[str]]:
    files: list[Path] = []
    errors: list[str] = []
    for raw in paths:
        path = Path(raw)
        if not path.exists():
            errors.append(f"path not found: {raw}")
            continue
        if path.is_file():
            files.append(path)
            continue
        for root, dirs, names in os.walk(path, onerror=lambda exc: errors.append(f"cannot traverse {path}: {exc}")):
            dirs[:] = sorted(name for name in dirs if name not in SKIP_DIRS)
            for name in sorted(names):
                candidate = Path(root) / name
                if candidate.suffix.lower() in TEXT_EXTENSIONS:
                    files.append(candidate)
    unique = sorted(dict.fromkeys(files), key=lambda item: str(item))
    return unique, errors


def scan_paths(paths: Iterable[str], *, min_severity: str = "info") -> ScanResult:
    files, errors = _iter_files(paths)
    findings: list[Finding] = []
    scanned = 0
    for path in files:
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                errors.append(f"skipped large file over {MAX_FILE_BYTES} bytes: {path}")
                continue
            raw = path.read_bytes()
            if b"\0" in raw[:4096]:
                errors.append(f"skipped binary file: {path}")
                continue
            text = raw.decode("utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            errors.append(f"cannot read {path}: {exc}")
            continue
        scanned += 1
        findings.extend(scan_text(path, text))
    threshold = SEVERITY_ORDER[min_severity]
    return ScanResult(
        files_scanned=scanned,
        findings=tuple(sorted((item for item in findings if SEVERITY_ORDER[item.severity] >= threshold), key=lambda item: (-SEVERITY_ORDER[item.severity], item.path, item.line, item.rule_id))),
        errors=tuple(errors),
    )
