from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from .models import Finding, ScanResult

SCHEMA_VERSION = 1


def fingerprint(finding: Finding) -> str:
    """Stable identity for a finding, independent of its line number.

    For rules that match sensitive material, the fingerprint binds to the
    rule, the normalized path and a SHA-256 digest of the raw matched value.
    A rotated or newly introduced credential on a baselined line therefore
    surfaces as a new finding, while the same credential re-found in the same
    file stays suppressed. The digest is one-way over high-entropy material
    and the baseline file never contains raw credential values.

    Findings without sensitive material (injection patterns, metadata
    structure) fall back to the rule, path, message and redacted excerpt.
    """
    normalized = " ".join(finding.path.replace("\\", "/").split())
    if finding.material_digest:
        material = "\n".join((finding.rule_id, normalized, "material", finding.material_digest))
    else:
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
        def unique(items):
            out = {}
            for key, value in items:
                if key in out:
                    raise BaselineError(f"baseline {path} has duplicate JSON keys")
                out[key] = value
            return out
        payload = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise BaselineError(f"cannot read baseline {path}: {exc}") from exc
    if not isinstance(payload, dict) or type(payload.get("schema_version")) is not int or payload.get("schema_version") != SCHEMA_VERSION:
        raise BaselineError(f"baseline {path} has an unsupported schema version")
    fingerprints = payload.get("fingerprints")
    if not isinstance(fingerprints, list) or not all(isinstance(item, str) and re.fullmatch(r"[0-9a-f]{64}", item) for item in fingerprints):
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
