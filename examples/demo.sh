#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
out_dir="${TMPDIR:-/tmp}/promptguard-demo-$$"
mkdir -p "$out_dir"
python3 -m promptguard scan examples/prompts/safe.md --json "$out_dir/safe.json" --html "$out_dir/safe.html" --sarif "$out_dir/safe.sarif" --junit "$out_dir/safe.xml" --markdown "$out_dir/safe.md" --fail-on medium
python3 -m promptguard scan examples/prompts/risky.md --json "$out_dir/risky.json" --html "$out_dir/risky.html" --sarif "$out_dir/risky.sarif" --junit "$out_dir/risky.xml" --markdown "$out_dir/risky.md"
GH_TOKEN="ghp_EXAMPLE1234567890""EXAMPLE1234567890abcd"
SLACK_TOKEN="xoxb-123456""789012-abcdefghijklmnop"
GOOGLE_KEY="AIzaSyEXAMPLE1234567890""EXAMPLE123456789"
JWT_TOKEN="eyJhbGciOiJIUzI1NiJ9.""eyJzdWIiOiIxMjM0NTY3ODkwIn0.""SflKxwRJSMeKKF2QT4""fwpMeJf36POk6yJVadQssw5c"
cat > "$out_dir/tokens.md" <<FIXTURE
---
name: leaked-tokens-example
description: fixture with recognizable token formats for scanner demos
version: 0.1.0
---

The leaked GitHub credential $GH_TOKEN appeared in a shared log line.
A stale Slack bot token $SLACK_TOKEN was committed last week.
The demo Google API key $GOOGLE_KEY is still active.
An old session JWT $JWT_TOKEN was pasted into a ticket.
FIXTURE
python3 -m promptguard scan "$out_dir/tokens.md" --json "$out_dir/tokens.json" --markdown "$out_dir/tokens-summary.md"
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
BASELINE="$out_dir/baseline.json"
python3 -m promptguard scan examples/prompts/risky.md --write-baseline "$BASELINE" >/dev/null
python3 -m promptguard scan examples/prompts/risky.md --baseline "$BASELINE" --json "$out_dir/risky-baselined.json" --markdown "$out_dir/risky-baselined.md" --fail-on high >/dev/null
if grep -Eq 'AKIA|sk-[A-Za-z0-9]|xox|ghp_|AIza|eyJ' "$BASELINE"; then
  echo "baseline file leaked credential material" >&2
  exit 1
fi
if python3 -m promptguard scan "$out_dir/tokens.md" --baseline "$BASELINE" --fail-on high >/dev/null 2>&1; then
  echo "expected new token findings to fail the gate despite the baseline" >&2
  exit 1
fi
python3 - <<PY
import json
baselined = json.load(open("$out_dir/risky-baselined.json", encoding="utf-8"))
assert baselined["finding_count"] == 0
assert baselined["suppressed_count"] == 8
bl_md = open("$out_dir/risky-baselined.md", encoding="utf-8").read()
assert "| Suppressed by baseline | 8 |" in bl_md
PY
if python3 -m promptguard scan examples/prompts/risky.md --fail-on high >"$out_dir/gate.txt" 2>&1; then
  echo "expected risky prompt gate to fail" >&2
  exit 1
fi
cat "$out_dir/gate.txt"
printf 'demo artifacts: %s\n' "$out_dir"
