# PromptGuard evidence contract

## What is implemented

The native scanner still performs deterministic local pattern checks. The new full-stage witness explains filtering, suppression and gate arithmetic. Independent browser recomputation accepts abstract findings, not raw prompts or real secrets. These are software-policy controls, not a security benchmark or evidence of detection quality.

### Identity and stage order

Native SHA-256 binds rule ID and normalized path to either a material digest or message and excerpt. Line and severity are excluded. Slashes and whitespace normalize. Thus moving a finding, raising severity or changing an aliased path may preserve identity. Prior rows remain visible but duplicate prior identities collapse to one baseline entry. Duplicate current identities remain separate findings. Below-filter rows are not suppressed, even if their identity is in the baseline. Used baseline identities are eligible matches; all others remain unused.

Only reported rows reach gates. A severity gate fails on any reported severity at or above the threshold. A count gate fails strictly above its cap, not at it. No configured gate means reported findings alone do not fail the scan. Scan errors dominate with exit 2, otherwise gate failure is 1, otherwise 0. A passing gate says nothing about completeness of the detector, prompt safety or security effectiveness.

### Native corrections and migration

Known sensitive matches are redacted over the full line before excerpt truncation, including missing-frontmatter excerpts. Sensitive rules enumerate all occurrences instead of stopping at the first occurrence per line. Injection rules retain one finding per rule per line. All original regex patterns are retained. Successfully read and decoded files determine `files_scanned`; unreadable, binary, oversized, missing and traversal errors prevent a successful exit and new baseline creation.

The metadata identity privately binds its original first line when redaction changes that line. This is an intentional migration: old metadata baseline entries can become new findings requiring review. Other existing identity semantics remain unchanged. Baseline loading now rejects Boolean schema values, malformed non-lowercase-hex SHA-256 identities, duplicate JSON keys and invalid encoding. Missing baseline files still mean an empty baseline. Baseline files are not claimed to be fully resource bounded.

### Abstract input boundary

Exact root fields: `current`, `prior`, `errors`, `files_scanned`, `policy`. At most 16 current and 16 prior rows, eight synthetic error labels, and 16 files. Each row requires rule_id, severity, path, line, message, excerpt, material_tag. Text is printable ASCII, at most 180 characters; rule and path are nonempty. Lines are integers 1..1,000,000. Material tags are null or `fixture:` followed by 1..32 ASCII letters, numbers, dots or hyphens. Policy min_severity is required; fail_on and max_findings may be null. Count caps are integers 0..1,000,000. Python accepts integral JSON numbers such as 1.0 consistently with JavaScript, rejects Booleans and nonfinite values, and normalizes native integer fields. Native audit files are limited to 128KiB and reject duplicate keys. Browser JSON.parse does not detect duplicate keys; it computes the parsed record only.

The inspector clears and disables stale results on edits or invalid input and prevents an older asynchronous digest computation from restoring stale output. Full JSON export contains the current complete record. SVG labels are shortened for layout; full values remain in scrollable tables and records.

### Privacy and limits

Digesting is not encryption or anonymization. Low-entropy contacts, paths and labels may be guessed. A full witness includes redacted excerpts and unredacted paths/error descriptions, which can themselves be private. Keep real baseline and witness files private. Redaction covers recognized patterns only, not all possible private information. Do not paste private records into the public inspector. No new credential-shaped fixture corpus, prompt corpus, external model, paid API or network scanner was added.

## Tests and preserved controls

- Original 68 tests, original fixtures and demo are unchanged; SHA-256 archive manifest: `docs/original-sha256.json`.
- Total 87 Python tests on Python 3.10, 3.11, 3.12 and 3.13.
- 13,320 exhaustive small policy controls cover zero to two findings, all severities, baseline patterns, minimum severities, severity gates and count caps. Expected index lists and exit precedence are derived separately.
- 27 complete native/independent-JavaScript reports: 735 numeric and 1,443 other leaves, including aliases, duplicate identities, rotation, below-filter matches, error precedence, strict cap boundaries and all-stage controls.
- Actual Chrome: 50 current rows, 17 prior rows, 16 unique entries across cases, 50 inspected full records, 181 stage circles with exact positions; all table/card/payload/gate fields, stale handling, invalid input, async race, export, and 320/390/1280 containment.
- Isolated wheel outside checkout: eight module origins, all 27 reports, scan/audit/baseline, incomplete exit, JSON/HTML/SARIF/JUnit/Markdown and console entry point.
- Original analysis and HTML remain visible in `docs/original-analysis.json` and `docs/original-report.html`. Changes to native metadata and error behavior are documented above, not hidden by rewriting the old controls.

```bash
python -m unittest discover -s tests -v
python tools/build_audits.py
npm test
bash tools/wheel_smoke.sh
bash examples/demo.sh
```

## Prior work

Hashes, deterministic filters, baselines and gates are established methods. Implementation, synthetic controls and inspector by Midya Rahmani. No external scanner code or secret corpus copied. This witness is not SARIF suppression compatibility, a certification or an injection-defense benchmark.

- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html): sensitive-data exclusions, encoding, protection and failure testing. Returning exit 2 for this security CLI is this project's contract, not a universal OWASP instruction to terminate applications on logging failures.
- [CWE-532](https://cwe.mitre.org/data/definitions/532.html): sensitive information in logs.
- [CWE-117](https://cwe.mitre.org/data/definitions/117.html): improper output neutralization.
- [Microsoft SARIF tutorial](https://github.com/microsoft/sarif-tutorials/blob/main/docs/3-Beyond-basics.md) and [suppression example](https://github.com/microsoft/sarif-tutorials/blob/main/samples/Suppressions.sarif): execution status and suppression are distinct reporting concepts. This extension does not implement SARIF suppression interoperability.
- [GitHub secret-scanning scope](https://docs.github.com/en/code-security/reference/secret-security/secret-scanning-scope) and [supported patterns](https://docs.github.com/en/code-security/reference/secret-security/supported-secret-scanning-patterns): pattern and token-version limitations. This project does not inherit GitHub's coverage or validity checks.
