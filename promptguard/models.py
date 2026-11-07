from __future__ import annotations

from dataclasses import dataclass, field

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    path: str
    line: int
    message: str
    excerpt: str

    def to_dict(self) -> dict[str, object]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "path": self.path,
            "line": self.line,
            "message": self.message,
            "excerpt": self.excerpt,
        }


@dataclass(frozen=True)
class ScanResult:
    files_scanned: int
    findings: tuple[Finding, ...] = field(default_factory=tuple)
    errors: tuple[str, ...] = field(default_factory=tuple)

    @property
    def max_severity(self) -> str | None:
        if not self.findings:
            return None
        return max(self.findings, key=lambda item: SEVERITY_ORDER[item.severity]).severity

    def at_or_above(self, severity: str) -> tuple[Finding, ...]:
        threshold = SEVERITY_ORDER[severity]
        return tuple(item for item in self.findings if SEVERITY_ORDER[item.severity] >= threshold)

    def to_dict(self) -> dict[str, object]:
        counts = {name: 0 for name in SEVERITY_ORDER}
        for finding in self.findings:
            counts[finding.severity] += 1
        return {
            "schema_version": 1,
            "files_scanned": self.files_scanned,
            "finding_count": len(self.findings),
            "max_severity": self.max_severity,
            "severity_counts": counts,
            "findings": [finding.to_dict() for finding in self.findings],
            "errors": list(self.errors),
        }
