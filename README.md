# PromptGuard

Local-first prompt linting with a full-stage baseline and CI-gate witness.

[Interactive policy inspector](https://midya8.github.io/promptguard/) | [Definitions and reproduction](EVIDENCE.md) | [Original README](docs/original-readme.md)

## Silence is not a clean scan

A finding can disappear at the severity filter or baseline before a gate sees it. PromptGuard now records every current finding, its SHA-256 identity, eligibility, baseline match, disposition, reported payload, and final gate decision. The browser independently recomputes bounded synthetic finding records using JavaScript and WebCrypto. It does not scan prompts, call a model, or measure detection effectiveness.

```bash
python -m pip install .
promptguard scan prompts/ --min-severity low --baseline baseline.json \
  --fail-on high --max-findings 10 --audit witness.json --json findings.json
promptguard audit --spec examples/audit.json --json audit.json
```

`scan --audit` retains below-filter and suppressed rows while ordinary reports still contain only reported findings. Incomplete scans return 2 and cannot write a new baseline. Gate failures return 1; a completed scan with passing configured gates returns 0. `audit` returns 0 for a valid computation, even when its computed scan-policy witness says 1 or 2. Invalid audit input returns 2.

Native fixes redact full lines before truncation, redact metadata excerpts, retain every recognized sensitive match on a line, count successfully read files, report traversal failures, and reject malformed baseline identities, duplicate JSON keys and invalid encoding. Metadata identities now bind the original first line privately when redaction changes it, so rotated sensitive material cannot hide behind identical redacted metadata. Existing metadata baseline entries can therefore surface again and require review. These changes add no new detection patterns.

A fingerprint is not anonymity. Low-entropy values may be guessed. Real baselines, paths, errors and full witnesses can carry private context: keep them private. Existing identity aliases remain visible: line and severity are not bound, slash and whitespace normalization can alias distinct paths. A baseline records suppression, not safety.

All original 68 tests, fixed fixtures and offline demo remain unchanged. The original fixtures contain documented dummy credentials; this extension adds only reserved-domain contacts, abstract `fixture:` tags and mocked noncredential patterns. No protection bypass is required or supported.

## Reproduce the evidence

```bash
python -m unittest discover -s tests -v
python tools/build_audits.py
npm test
bash tools/wheel_smoke.sh
bash examples/demo.sh
```

87 Python tests include 13,320 exhaustive small policy controls. Independent JavaScript checks compare all 27 reports (735 numeric and 1,443 other leaves). Actual Chrome checks every displayed row, fingerprint table, gate field, selected full record, export and stage mark: 50 current rows, 17 prior rows, 16 unique baseline entries across cases, 50 full records and 181 circles. Mobile containment is checked at 320, 390 and 1280 pixels. The isolated wheel checks all 27 reports and eight installed module origins outside the checkout.

---

## Original scanner commands and context

Local-first prompt, secret and prompt-injection linting for AI systems.

PromptGuard scans prompt, Markdown, JSON and YAML files for credential material (including OpenAI, AWS, GitHub, Slack and Google tokens and JWTs), personal data, prompt-injection patterns and missing prompt metadata. It produces redacted terminal output, machine-readable JSON, SARIF 2.1.0 output for code-scanning tools, JUnit XML for CI test viewers, Markdown reports for CI job summaries, and a standalone escaped HTML report. It is dependency-free and works offline, so it can run in local checks and CI without sending prompts or secrets to a service.

## Why

Prompt files are production configuration. They often mix instructions, examples, tool policies and user data, but they rarely get the same review discipline as application code. PromptGuard turns common AI-security review checks into a repeatable gate:

- finds OpenAI-style keys, AWS-style keys, private key headers and assigned secrets;
- finds email addresses, phone numbers and payment-card numbers with Luhn validation;
- finds prompt-injection language that asks a model to ignore prior instructions, reveal hidden prompts, bypass controls or exfiltrate secrets;
- checks prompt metadata frontmatter for `name`, `description` and `version`;
- redacts secrets and contact details in terminal, JSON, SARIF, JUnit XML, Markdown and HTML findings;
- fails CI on a selected severity or finding-count threshold.

## Commands

Scan one file or a directory:

```bash
python3 -m promptguard scan examples/prompts
```

Write JSON, SARIF, JUnit XML, Markdown and HTML reports:

```bash
python3 -m promptguard scan examples/prompts/risky.md \
  --json findings.json \
  --html report.html \
  --sarif findings.sarif \
  --junit findings.xml \
  --markdown findings.md
```

Fail CI on high-severity findings:

```bash
python3 -m promptguard scan prompts/ --fail-on high
```

Limit output to medium or higher and cap total findings:

```bash
python3 -m promptguard scan prompts/ --min-severity medium --max-findings 20
```

Record known findings as a baseline, then gate only on new ones:

```bash
python3 -m promptguard scan prompts/ --write-baseline .promptguard-baseline.json
python3 -m promptguard scan prompts/ --baseline .promptguard-baseline.json --fail-on high
```

Baselines store per-finding SHA-256 fingerprints. For secret and
personal-data rules the fingerprint binds to a one-way digest of the matched
value itself plus the rule and path, so a rotated or newly introduced
credential surfaces as a new finding even on a baselined line, while the same
credential re-found in the same file stays suppressed. The baseline file
contains no raw credential material. Findings without sensitive material
(prompt-injection language, metadata structure) use a content fingerprint
built from the rule, path, message and redacted excerpt. Suppressed findings
stay out of reports and gate decisions; the JSON payload and Markdown summary
report the suppressed count, and a malformed baseline fails closed with exit
code 2.

## Rules

| Rule family | Severity | What it catches |
| --- | --- | --- |
| Secret assignment | high | `api_key`, `token`, `password` or `secret` assigned to credential-like values |
| OpenAI/AWS/GitHub/Slack/Google keys and private keys | critical | recognizable API key, access token and private key material |
| JSON Web Tokens | high | signed JWT credentials embedded in prompts or configs |
| PII | low to critical | emails, phone numbers and payment-card numbers validated with Luhn |
| Prompt injection | high | ignore-instructions, reveal-system-prompt, bypass-control and exfiltration language |
| Role confusion | high | unrestricted, jailbroken or privileged-role framing |
| Structure | info/low | missing or incomplete prompt metadata frontmatter |

Rules are deterministic pattern checks, not a model judgment. They are intended as a fast local gate and do not replace human security review.

## Offline demo

The demo uses fixed local prompt fixtures. It scans a safe prompt, scans a risky prompt without a gate, then verifies that a high-severity gate rejects the risky prompt:

```bash
bash examples/demo.sh
```

The risky fixture uses fake example credentials and contact details. Demo output demonstrates rule and gate behavior; it is not a claim that deterministic linting catches every prompt-injection technique.

## Development

```bash
python3 -m unittest discover -s tests -v
bash examples/demo.sh
```

The test suite runs fully offline. CI runs the same checks on Python 3.10 through 3.13.

## Design notes

- **Local by default:** scanning uses only the filesystem and standard library.
- **Redaction by default:** findings preserve enough context for review without copying full credentials into reports.
- **Actionable output:** every finding carries a rule ID, severity, file, line, message and redacted excerpt; SARIF output maps findings to code-scanning rule metadata and locations; JUnit XML exposes findings to ordinary CI test viewers; Markdown summaries fit native CI job-summary surfaces with escaped table cells.
- **Scriptable gates:** severity and finding-count thresholds provide meaningful CI exit codes.
- **Safe reports:** HTML output escapes file paths, messages and excerpts and needs no JavaScript; JUnit XML is serialized with standard-library XML escaping.


## Opt-in occurrence quotas

A separate actual-scanner baseline mode suppresses at most the declared occurrence count. Exact path, severity, rule and material/content identity are bound; the original v1 set baseline and scanner patterns stay unchanged. One declared allowance suppresses one of three equal-identity occurrences, while the legacy set suppresses all three. Every consumption, unused entry and gate decision is visible in the [quota inspector](https://midya8.github.io/promptguard/quota.html).

100 Python tests retain all87 originals; seven Node/actual-Chrome tests retain allthree originals.4,374 exhaustive occurrence-rank controls and200 seeded full native/browser comparisons;24 complete reports,52currentrows32priorrows22entries104SVGmarks, trusted downloads/native replay and isolated API/module/console reproduction. Equal-identity rows remain interchangeable, not historically tracked; exact paths are not repository IDs. Manual quotas, hashes and passing gates are not safety or authorization. [Contract, limits, sources and reproduction](QUOTAS.md).
