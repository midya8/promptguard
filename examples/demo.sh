#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
out_dir="${TMPDIR:-/tmp}/promptguard-demo-$$"
mkdir -p "$out_dir"
python3 -m promptguard scan examples/prompts/safe.md --json "$out_dir/safe.json" --html "$out_dir/safe.html" --fail-on medium
python3 -m promptguard scan examples/prompts/risky.md --json "$out_dir/risky.json" --html "$out_dir/risky.html"
if python3 -m promptguard scan examples/prompts/risky.md --fail-on high >"$out_dir/gate.txt" 2>&1; then
  echo "expected risky prompt gate to fail" >&2
  exit 1
fi
cat "$out_dir/gate.txt"
printf 'demo artifacts: %s\n' "$out_dir"
