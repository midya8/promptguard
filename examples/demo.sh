#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
out_dir="${TMPDIR:-/tmp}/promptguard-demo-$$"
mkdir -p "$out_dir"
python3 -m promptguard scan examples/prompts/safe.md --json "$out_dir/safe.json" --html "$out_dir/safe.html" --sarif "$out_dir/safe.sarif" --junit "$out_dir/safe.xml" --fail-on medium
python3 -m promptguard scan examples/prompts/risky.md --json "$out_dir/risky.json" --html "$out_dir/risky.html" --sarif "$out_dir/risky.sarif" --junit "$out_dir/risky.xml"
python3 -m json.tool "$out_dir/safe.sarif" >/dev/null
python3 -m json.tool "$out_dir/risky.sarif" >/dev/null
python3 - <<PY
import xml.etree.ElementTree as ET
safe = ET.parse("$out_dir/safe.xml").getroot()
risky = ET.parse("$out_dir/risky.xml").getroot()
assert safe.attrib["failures"] == "0"
assert safe.attrib["errors"] == "0"
assert int(risky.attrib["failures"]) > 0
assert risky.findall("testcase/failure")
PY
if python3 -m promptguard scan examples/prompts/risky.md --fail-on high >"$out_dir/gate.txt" 2>&1; then
  echo "expected risky prompt gate to fail" >&2
  exit 1
fi
cat "$out_dir/gate.txt"
printf 'demo artifacts: %s\n' "$out_dir"
