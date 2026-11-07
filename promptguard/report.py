from __future__ import annotations

from html import escape

from .models import ScanResult

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
