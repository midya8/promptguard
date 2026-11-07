#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
out_dir="${TMPDIR:-/tmp}/promptguard-demo-$$"
mkdir -p "$out_dir"
python3 -m promptguard scan examples/prompts/safe.md --json "$out_dir/safe.json" --html "$out_dir/safe.html" --sarif "$out_dir/safe.sarif" --junit "$out_dir/safe.xml" --markdown "$out_dir/safe.md" --fail-on medium
python3 -m promptguard scan examples/prompts/risky.md --json "$out_dir/risky.json" --html "$out_dir/risky.html" --sarif "$out_dir/risky.sarif" --junit "$out_dir/risky.xml" --markdown "$out_dir/risky.md"
python3 -m promptguard scan examples/prompts/tokens.md --json "$out_dir/tokens.json" --markdown "$out_dir/tokens-summary.md"
python3 -m json.tool "$out_dir/safe.sarif" >/dev/null
python3 -m json.tool "$out_dir/risky.sarif" >/dev/null
python3 - <<PY
import json
import xml.etree.ElementTree as ET
safe = ET.parse("$out_dir/safe.xml").getroot()
risky = ET.parse("$out_dir/risky.xml").getroot()
assert safe.attrib["failures"] == "0"
assert safe.attrib["errors"] == "0"
assert int(risky.attrib["failures"]) > 0
assert risky.findall("testcase/failure")
safe_md = open("$out_dir/safe.md", encoding="utf-8").read()
risky_md = open("$out_dir/risky.md", encoding="utf-8").read()
assert safe_md.startswith("# PromptGuard scan\n")
assert "| Findings | 0 |" in safe_md
assert "No findings at the selected severity threshold." in safe_md
assert "| Files scanned | 1 |" in risky_md
assert "INJECTION_IGNORE" in risky_md
assert "| Severity | Rule | Location | Message | Excerpt |" in risky_md
tokens = json.load(open("$out_dir/tokens.json", encoding="utf-8"))
assert {item["rule_id"] for item in tokens["findings"]} == {
    "SECRET_GITHUB_TOKEN", "SECRET_SLACK_TOKEN", "SECRET_GOOGLE_KEY", "SECRET_JWT",
}
assert all("REDACTED" in item["excerpt"] for item in tokens["findings"])
tokens_md = open("$out_dir/tokens-summary.md", encoding="utf-8").read()
assert "| Findings | 4 |" in tokens_md
assert "SECRET_JWT" in tokens_md
PY
if python3 -m promptguard scan examples/prompts/risky.md --fail-on high >"$out_dir/gate.txt" 2>&1; then
  echo "expected risky prompt gate to fail" >&2
  exit 1
fi
cat "$out_dir/gate.txt"
printf 'demo artifacts: %s\n' "$out_dir"
