from __future__ import annotations

from html import escape
import json
from typing import Any
import xml.etree.ElementTree as ET

from .models import Finding, ScanResult

_STYLES = """
body{font-family:Inter,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;margin:40px;background:#f6f8fb;color:#182230}
main{max-width:1100px;margin:auto}h1{margin-bottom:4px}.muted{color:#667085}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px;margin:24px 0}.card,table{background:#fff;border:1px solid #e4e7ec;border-radius:12px;box-shadow:0 1px 3px #1018280f}.card{padding:18px}.value{font-size:30px;font-weight:750}table{border-collapse:separate;border-spacing:0;width:100%;overflow:hidden}th,td{padding:10px 12px;border-bottom:1px solid #e4e7ec;text-align:left;vertical-align:top}th{background:#f9fafb;font-size:12px;text-transform:uppercase;color:#475467}tr:last-child td{border-bottom:0}.sev{display:inline-block;border-radius:999px;padding:3px 8px;font-weight:700;font-size:12px}.critical{background:#fee4e2;color:#b42318}.high{background:#fef0c7;color:#b54708}.medium{background:#e0f2fe;color:#026aa2}.low{background:#e9d7fe;color:#6941c6}.info{background:#eaecf0;color:#344054}code{white-space:pre-wrap;word-break:break-word}
"""


def render_report(result: ScanResult) -> str:
    payload = result.to_dict()
    rows = []
    for item in result.findings:
        rows.append(
            "<tr>"
            f"<td><span class=\"sev {escape(item.severity)}\">{escape(item.severity)}</span></td>"
            f"<td>{escape(item.rule_id)}</td>"
            f"<td>{escape(item.path)}:{item.line}</td>"
            f"<td>{escape(item.message)}</td>"
            f"<td><code>{escape(item.excerpt)}</code></td>"
            "</tr>"
        )
    findings_html = "\n".join(rows) or '<tr><td colspan="5">No findings at the selected severity threshold.</td></tr>'
    errors = "".join(f"<li>{escape(error)}</li>" for error in result.errors)
    errors_html = f"<h2>Scan errors</h2><ul>{errors}</ul>" if errors else ""
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>PromptGuard report</title><style>{_STYLES}</style></head>
<body><main>
<h1>PromptGuard report</h1><p class="muted">Local-first prompt, secret and prompt-injection linting for AI systems.</p>
<section class="cards"><div class="card"><div class="value">{payload['files_scanned']}</div><div>files scanned</div></div><div class="card"><div class="value">{payload['finding_count']}</div><div>findings</div></div><div class="card"><div class="value">{escape(str(payload['max_severity'] or 'none'))}</div><div>max severity</div></div></section>
<h2>Findings</h2><table><thead><tr><th>Severity</th><th>Rule</th><th>Location</th><th>Message</th><th>Excerpt</th></tr></thead><tbody>{findings_html}</tbody></table>
{errors_html}
</main></body></html>
"""


def render_junit(result: ScanResult) -> str:
    """Render findings as a JUnit XML suite for CI test viewers."""
    findings = list(result.findings)
    errors = list(result.errors)
    tests = len(findings) + len(errors)
    if tests == 0:
        tests = result.files_scanned
    suite = ET.Element(
        "testsuite",
        {
            "name": "promptguard",
            "tests": str(tests),
            "failures": str(len(findings)),
            "errors": str(len(errors)),
        },
    )
    if not findings and not errors:
        ET.SubElement(
            suite,
            "testcase",
            {
                "classname": "promptguard.clean",
                "name": f"{result.files_scanned} file(s) scanned with no findings",
            },
        )
    for index, finding in enumerate(findings, start=1):
        testcase = ET.SubElement(
            suite,
            "testcase",
            {
                "classname": f"promptguard.{finding.severity}",
                "name": f"{finding.rule_id} {finding.path}:{finding.line}",
            },
        )
        failure = ET.SubElement(
            testcase,
            "failure",
            {
                "type": finding.severity,
                "message": finding.message,
            },
        )
        failure.text = f"{finding.rule_id} at {finding.path}:{finding.line}\n{finding.excerpt}"
    for error in errors:
        testcase = ET.SubElement(
            suite,
            "testcase",
            {"classname": "promptguard.scan_error", "name": error},
        )
        element = ET.SubElement(testcase, "error", {"message": error})
        element.text = error
    ET.indent(suite, space="  ")
    return "<?xml version='1.0' encoding='utf-8'?>\n" + ET.tostring(suite, encoding="unicode") + "\n"

_SARIF_LEVELS = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def _sarif_rule(finding: Finding) -> dict[str, Any]:
    return {
        "id": finding.rule_id,
        "name": finding.rule_id.replace("_", " ").title().replace(" ", ""),
        "shortDescription": {"text": finding.message},
        "defaultConfiguration": {"level": _SARIF_LEVELS[finding.severity]},
        "properties": {"promptguard_severity": finding.severity},
    }


def render_sarif(result: ScanResult, *, version: str) -> str:
    """Render findings as SARIF 2.1.0 for code-scanning integrations."""
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for finding in result.findings:
        rules.setdefault(finding.rule_id, _sarif_rule(finding))
        results.append(
            {
                "ruleId": finding.rule_id,
                "level": _SARIF_LEVELS[finding.severity],
                "message": {"text": f"{finding.message} ({finding.severity})"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.path.replace("\\", "/")},
                            "region": {
                                "startLine": finding.line,
                                "snippet": {"text": finding.excerpt},
                            },
                        }
                    }
                ],
            }
        )
    notifications = [
        {"level": "warning", "message": {"text": error}}
        for error in result.errors
    ]
    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "PromptGuard",
                        "version": version,
                        "informationUri": "https://github.com/midya8/promptguard",
                        "rules": [rules[key] for key in sorted(rules)],
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": not result.errors,
                        "toolExecutionNotifications": notifications,
                    }
                ],
            }
        ],
    }
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def _md_cell(value: object) -> str:
    """Escape a value for a GitHub-flavoured Markdown table cell."""
    text = str(value)
    return text.replace("\\", "\\\\").replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def render_markdown(result: ScanResult) -> str:
    """Render findings as a Markdown report suited to CI job summaries."""
    payload = result.to_dict()
    counts = payload["severity_counts"]
    lines = [
        "# PromptGuard scan",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| Files scanned | {payload['files_scanned']} |",
        f"| Findings | {payload['finding_count']} |",
        f"| Max severity | {_md_cell(payload['max_severity'] or 'none')} |",
        f"| Scan errors | {len(result.errors)} |",
        "",
        "## Severity counts",
        "",
        "| Severity | Findings |",
        "|---|---|",
    ]
    for severity in ("critical", "high", "medium", "low", "info"):
        lines.append(f"| {severity} | {counts[severity]} |")
    lines.extend(["", "## Findings", ""])
    if result.findings:
        lines.extend(
            [
                "| Severity | Rule | Location | Message | Excerpt |",
                "|---|---|---|---|---|",
            ]
        )
        for finding in result.findings:
            lines.append(
                "| {severity} | {rule} | {location} | {message} | {excerpt} |".format(
                    severity=_md_cell(finding.severity),
                    rule=_md_cell(finding.rule_id),
                    location=_md_cell(f"{finding.path}:{finding.line}"),
                    message=_md_cell(finding.message),
                    excerpt=_md_cell(finding.excerpt),
                )
            )
    else:
        lines.append("No findings at the selected severity threshold.")
    if result.errors:
        lines.extend(["", "## Scan errors", ""])
        for error in result.errors:
            lines.append(f"- {_md_cell(error)}")
    return "\n".join(lines) + "\n"
