#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
tmp="$(mktemp -d)";trap 'rm -rf "$tmp"' EXIT
python -m pip wheel --no-deps --wheel-dir "$tmp/dist" "$root" > "$tmp/build.log"
python -m venv "$tmp/env"
"$tmp/env/bin/python" -m pip install --no-deps "$tmp"/dist/*.whl > "$tmp/install.log"
cd "$tmp"
"$tmp/env/bin/python" -I "$root/tools/verify_installed.py" "$root"
"$tmp/env/bin/promptguard" audit --spec "$root/examples/audit.json" --json audit.json
"$tmp/env/bin/promptguard" scan "$root/examples/prompts/risky.md" --json findings.json --html report.html --sarif report.sarif --junit report.xml --markdown report.md --audit witness.json --write-baseline baseline.json
"$tmp/env/bin/promptguard" scan "$root/examples/prompts/risky.md" --baseline baseline.json --fail-on high --json suppressed.json --audit suppressed-witness.json
"$tmp/env/bin/promptguard" scan "$root/examples/prompts/safe.md" --fail-on high
if "$tmp/env/bin/promptguard" scan "$root/examples/prompts/risky.md" --fail-on high; then exit 1; else test "$?" = 1; fi
if "$tmp/env/bin/promptguard" scan missing-file.txt --audit incomplete.json; then exit 1; else test "$?" = 2; fi
"$tmp/env/bin/python" -I - "$root" <<'PY'
import json,sys,pathlib,xml.etree.ElementTree as ET
from promptguard.audit import audit_spec
root=pathlib.Path(sys.argv[1]);assert json.load(open('audit.json'))==audit_spec(json.load(open(root/'examples/audit.json')))
assert json.load(open('findings.json'))['finding_count']==8
assert json.load(open('suppressed.json'))['finding_count']==0
assert json.load(open('suppressed-witness.json'))['counts']['suppressed']==8
assert json.load(open('incomplete.json'))['gates']['exit_code']==2
assert json.load(open('report.sarif'))['version']=='2.1.0';ET.parse('report.xml');assert pathlib.Path('report.md').read_text().startswith('# PromptGuard');assert '<html' in pathlib.Path('report.html').read_text()
print('Installed scan/audit/baseline/strict incomplete gate and JSON/HTML/SARIF/JUnit/Markdown pass')
PY
