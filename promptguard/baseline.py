from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .models import Finding, ScanResult

SCHEMA_VERSION = 1


def fingerprint(finding: Finding) -> str:
    """Stable identity for a finding, independent of its line number.

    The digest uses the rule, normalized path, message and the already-redacted
    excerpt, so baseline files never contain raw credential material and a
    finding keeps its identity when unrelated lines shift above it.
    """
    normalized = " ".join(finding.path.replace("\\", "/").split())
    material = "\n".join((finding.rule_id, normalized, finding.message, finding.excerpt))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


class BaselineError(ValueError):
    pass


def load_baseline(path: Path) -> frozenset[str]:
    """Read a baseline file into a set of finding fingerprints.

    A missing file yields an empty baseline so CI can enable the flag before
    the first baseline is recorded; malformed content raises BaselineError.
    """
    path = Path(path)
    if not path.exists():
        return frozenset()
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BaselineError(f"cannot read baseline {path}: {exc}") from exc
    if not isinstance(payload, dict) or payload.get("schema_version") != SCHEMA_VERSION:
        raise BaselineError(f"baseline {path} has an unsupported schema version")
    fingerprints = payload.get("fingerprints")
    if not isinstance(fingerprints, list) or not all(isinstance(item, str) for item in fingerprints):
        raise BaselineError(f"baseline {path} has an invalid fingerprints list")
    return frozenset(fingerprints)


def write_baseline(path: Path, findings: tuple[Finding, ...]) -> int:
    """Record the given findings as the baseline; returns the count written."""
    payload = {
        "schema_version": SCHEMA_VERSION,
        "fingerprints": sorted({fingerprint(finding) for finding in findings}),
    }
    Path(path).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return len(payload["fingerprints"])


def apply_baseline(result: ScanResult, fingerprints: frozenset[str]) -> tuple[ScanResult, int]:
    """Split a scan result into unsuppressed findings plus a suppressed count."""
    if not fingerprints:
        return result, 0
    kept = tuple(finding for finding in result.findings if fingerprint(finding) not in fingerprints)
    suppressed = len(result.findings) - len(kept)
    return ScanResult(files_scanned=result.files_scanned, findings=kept, errors=result.errors), suppressed
