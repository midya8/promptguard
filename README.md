# promptguard

A linter for prompt files. It scans your prompts, Markdown, JSON and YAML for things that shouldn't be there before they get committed or shipped: API keys and other secrets, emails and phone numbers, and the usual prompt injection phrasing ("ignore all previous instructions", "reveal the system prompt"). It also checks that prompt files have `name`, `description` and `version` frontmatter. Standard library only, works offline, so nothing gets sent anywhere.

```
$ python -m promptguard scan examples/prompts
scanned 2 file(s), 8 finding(s), max severity critical
CRITICAL SECRET_OPENAI_KEY examples/prompts/risky.md:9 OpenAI-style API key material found :: api_key=<redacted>"
HIGH INJECTION_IGNORE examples/prompts/risky.md:6 prompt tells the model to ignore earlier instructions :: ...
HIGH INJECTION_EXFILTRATE examples/prompts/risky.md:7 prompt asks to exfiltrate credentials or private data :: ...
MEDIUM PII_EMAIL examples/prompts/risky.md:8 email address found :: Contact the test owner at <email> or <phone>.
...
```

(The keys in `risky.md` are fake, it's there to trip every rule.) Matches are redacted in every output format.

## Using it in CI

```bash
python -m promptguard scan prompts/ --fail-on high
python -m promptguard scan prompts/ --min-severity medium --max-findings 20
python -m promptguard scan prompts/ --json findings.json --sarif findings.sarif --junit findings.xml --html report.html
```

SARIF works with GitHub code scanning. If you're adding this to an existing repo with known findings, record a baseline and only fail on new ones:

```bash
python -m promptguard scan prompts/ --write-baseline .promptguard-baseline.json
python -m promptguard scan prompts/ --baseline .promptguard-baseline.json --fail-on high
```

Exit codes: 0 clean, 1 a gate failed, 2 the scan couldn't complete. `--audit all-findings.json` writes every finding including the ones that were filtered or baselined away, if you want to see why something didn't fail the build.

There's also a quota mode for baselines (QUOTAS.md) and a browser page that replays the filter/baseline/gate steps on sample data: https://midya8.github.io/promptguard/

## Caveats

It's pattern matching. It'll miss secrets in formats it doesn't know and injection phrased in ways it hasn't seen, and it'll flag some harmless text. A baseline means "we've seen this", not "this is safe". Baseline files store hashes of findings, which can still leak low-entropy values, so keep them private.

Tests: `python -m unittest discover -s tests` (102 tests).
