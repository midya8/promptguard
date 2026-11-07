# PromptGuard

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

Baselines store per-finding SHA-256 fingerprints built from the rule, path,
message and already-redacted excerpt, so the file contains no credential
material and a finding keeps its identity when unrelated lines shift above it.
Suppressed findings stay out of reports and gate decisions; the JSON payload
and Markdown summary report the suppressed count, and a malformed baseline
fails closed with exit code 2.

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
