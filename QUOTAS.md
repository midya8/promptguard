# Occurrence-limited baselines

PromptGuard adds a separate opt-in quota baseline for the actual scanner, plus an independent synthetic policy inspector. The original scanner patterns, v1 fingerprint set, prior audit API and report adapters remain unchanged. The package and SARIF version stay 0.2.0 to retain their existing version contract; the new quota schema has its own identifier.

[Open the quota inspector](https://midya8.github.io/promptguard/quota.html) · [Original inspector](https://midya8.github.io/promptguard/)

## One accepted occurrence is not three

The default abstract control has three equal-identity current occurrences and one eligible prior occurrence. A legacy set suppresses all three. The quota suppresses the first and reports the next two. With a medium severity gate, the declared scan-policy exit is 1. This is a constructed policy example, not an attack, real secret scan, detection benchmark or proof of improved security.

```sh
# Actual scanner: deliberately record current eligible occurrences.
promptguard scan prompts/ --min-severity medium \
  --write-quota-baseline accepted-quota.json

# Later scans reuse counts without changing the baseline.
promptguard scan prompts/ --min-severity medium \
  --quota-baseline accepted-quota.json --fail-on high \
  --audit private-witness.json --json private-findings.json

# Synthetic replay: no scanning or credential input.
python -m promptguard.quota_audit --input examples/quota.json
promptguard-quota-audit --input examples/quota.json
```

A successful write records findings but does not suppress that scan. Gates still apply and may return 1 after the baseline was written. Review the findings before recording them. Explicitly re-running the write command replaces the quota with current eligible counts, including new identities or larger counts. There is no accept-new review guard, automatic pruning, migration, expiry, signature or approval provenance. Do not confuse a manually editable baseline with authorization or safety.

## Exact identity

The quota identity is SHA-256 of the ASCII UTF-8 bytes of compact `ensure_ascii=True` JSON for:

```text
["promptguard-occurrence-quota/v1", rule_id, exact_path, severity, basis]
```

`basis` is `["material", material_digest]` when the scanner supplied a nonempty material digest; otherwise it is `["content", message, excerpt]`. No raw matched material is included. The finding's line number is intentionally omitted. Material-backed message/excerpt changes do not change identity; rule, exact path, severity or material-digest changes do. Content-backed message or excerpt changes do change identity.

This is a separate domain and format from the legacy newline-framed fingerprint. JSON array framing avoids delimiter ambiguity. Exact path spelling is retained, including backslashes and whitespace, rather than applying v1 slash/whitespace normalization. Severity is now bound. The legacy implementation and semantics are untouched.

An exact path is not a repository ID, canonical filesystem identity or containment proof. Different invocation spelling, working directory, symlink spelling or path representation can resurface findings. Two repositories with the same path and finding fields can share the same quota identity. Scope the baseline operationally to the intended repository and invocation. No automatic inference or cross-repository protection is claimed.

A hash is not anonymity or encryption. Low-entropy source values can be guessed. Quota files, full witnesses, paths, errors and redacted excerpts may carry private context. Keep real scan evidence private. The public examples use only synthetic `fixture:` tags and abstract records; actual scanner controls use reserved-domain contacts, not credential-shaped test strings.

## Finite consumption

For each eligible current occurrence, in the scanner's returned order:

1. Compute its quota identity and read remaining allowance, or zero if absent.
2. If allowance is positive, suppress this occurrence and decrement by one.
3. Otherwise report it. Below-filter findings never consume allowance.

The witness preserves every normalized current row, exact identity, eligibility, declared count, remaining before/after, consumed flag and disposition. Each declared entry exposes declared, used and remaining counts, including wholly unused entries. Reading a quota never mutates the file or caller's dictionary. Each invocation starts with the same declared counts.

Equal-identity occurrences are interchangeable, not historically tracked. Reordering them may change which line is reported. Line movement alone is not new evidence under this identity. Counting occurrences can detect an excess relative to a declaration, but cannot prove that a surviving occurrence is the previously accepted one. It does not count unique secrets, files, vulnerabilities, attacks or affected people.

The native engine uses a mutable remaining-count dictionary. The independent browser computes each occurrence's rank by examining preceding eligible rows, then compares rank with declared prior multiplicity. Its WebCrypto SHA-256 and separate report construction agree on complete reports, not just totals.

## Gates and actual scanner integration

The actual `scan` command still scans all severities, filters by the requested minimum, and applies severity/count gates only to reported findings. Quota mode changes only suppression selection and its witness. JSON, escaped HTML, JUnit XML, Markdown and SARIF adapters receive the same filtered `ScanResult` type as before.

- Scan errors return 2 even when all known findings were suppressed; incomplete scans never write a quota baseline.
- Reported severity or count failures return 1. Count fails only when strictly greater than the limit.
- A complete passing scan returns 0. A passing gate says only that the supplied policy passed, not that the content is safe.
- `--quota-baseline` cannot be combined with `--write-quota-baseline` or either legacy baseline flag. Ambiguous modes fail before scanning or writing output.
- Missing, unreadable or malformed quota files fail closed with exit 2. This deliberately differs from v1's missing-file-as-empty behavior.
- A quota write serializes completely before a same-directory temporary write, flush/fsync and atomic replacement. An injected replacement failure leaves previous bytes intact and cleans the temporary file. This is process-level atomic replacement, not a transaction across output files or a guarantee against every filesystem/power-loss scenario.

The new replay CLI returns 0 for a valid computation even when the computed scan-policy exit is 1 or 2. Invalid replay input returns 2 with stderr and no JSON stdout. This distinction matches the original audit's computation-versus-policy separation.

## Strict file and replay schemas

Actual baseline JSON has exactly `schema` and `entries`, with schema `promptguard-occurrence-quota/v1`. Each entry has exactly lowercase 64-hex `identity` and integer `count` in 1..1,000,000. At most 4,096 entries and 1 MiB. Duplicate keys/identities, unsupported schemas, extra fields, invalid UTF-8, nonfinite/decimal/exponent counts and boolean counts are rejected. Empty entries are valid. JSON count `-0` is zero and is rejected by the positive-count constraint. Writers sort entries by identity.

The separate synthetic replay input has exactly `current`, `prior`, `errors`, `files_scanned`, `policy`. Both record lists have at most 16 records. Every record has exactly `rule_id`, `severity`, `path`, `line`, `message`, `excerpt`, `material_tag`; text is bounded printable ASCII of at most 180 characters, with nonempty rule/path and line integer 1..1,000,000. `material_tag` is null or `fixture:[A-Za-z0-9.-]{1,32}`. The tag is hashed to a simulated material digest; it is not real matched material. At most eight synthetic error labels and file count 0..16. Policy has exactly `min_severity`, nullable `fail_on`, nullable integer `max_findings` in 0..1,000,000.

Prior capture uses the same minimum-severity threshold as current eligibility. In real operation the file retains whatever earlier write captured; changing options does not regenerate it. The bounded replay only models the explicitly supplied same-threshold scenario. It does not automatically convert legacy baselines, read private quota files or infer historical capture options.

Replay JSON rejects duplicate keys, negative/decimal/exponent numeric spellings, nonfinite numbers, depth above eight and input above 128 KiB. Object APIs require actual integer fields, not floats or booleans. The browser's input-only fixtures contain no precomputed output; every displayed report is recomputed.

## Reproduce and inspect

```sh
python -m unittest discover -s tests -v
python tools/build_quota.py
npm test
bash tools/wheel_smoke.sh
bash tools/quota_wheel_smoke.sh
bash examples/demo.sh
```

100 Python tests retain all 87 earlier tests byte-for-byte. New checks include 4,374 exhaustive independent occurrence-rank controls, 200 seeded complete native/browser report comparisons, parser/schema boundaries, changed severity/path/content/material controls, reordering tradeoffs, real scanner repeated contacts, every report adapter, incomplete refusal and atomic replacement failure. A further 162 browser closed-form duplicate-count controls agree.

Seven Node/actual-Chrome tests retain all three earlier tests. Native and independent browser agree on 24 complete reports, 52 current rows, 32 prior rows, 22 quota entries and 52 legacy-control rows. Chrome checks every displayed row, selected full current record, gate and reported payload, plus all 104 consumption chart marks, stale/invalid state and 320/390/1280 containment. Trusted clicks download input and report, then replay the downloaded input through native CLI. Forty-eight full responsive views are captured when pixel verification is enabled.

An isolated installation outside the checkout reproduces every new report through API, module and console, verifies three installed module origins, and exercises actual scanner repeated-contact quota consumption and severity failure. The original eight-module wheel, original audit and scan/report/baseline/export checks remain. Native scanner patterns, models, legacy baseline, prior audit, report adapters and original tests are byte-exact.

## Credited sources and distinctions

Original implementation and synthetic controls; no external code or data copied. Finite baseline counts and occurrence disambiguation are established approaches, not new methods.

- [alint baseline mode](https://alint.org/docs/concepts/adoption/baseline/): recorded fingerprint counts as budgets, excess occurrences reported; incomplete-write refusal. alint also has accept-new/strict-stale guards that this extension does not implement. Its matching fields/output format differ.
- [Semgrep findings in CI](https://docs.semgrep.dev/semgrep-ci/findings-ci): rule/path/context/index disambiguates repeated identical findings. This extension is a simpler quota, not Semgrep's repository-history/diff-aware analysis.
- [Semgrep duplicate finding identities](https://docs.semgrep.dev/semgrep-code/remove-duplicates): indexed fingerprints and line movement. Their identity details can change; no compatibility is claimed.
- [MongoDB Kingfisher baseline management](https://mongodb.github.io/kingfisher/usage/baseline/): explicit repository scoping, complete-scan updates and atomic replacement. This extension does not have repository identity, history, multi-worker merging or automatic pruning.
- [Yelp detect-secrets](https://github.com/Yelp/detect-secrets): explicit baseline auditing and heuristic detection limitations. This extension adds no detection patterns or secret-handling guarantees.
- [RFC 8259, JSON](https://www.rfc-editor.org/rfc/rfc8259): unique object names support interoperable interpretation; duplicate behavior varies. These new parsers reject duplicates rather than choosing a value.
- [Python hashlib documentation](https://docs.python.org/3/library/hashlib.html): SHA-256 digest API. Hashing does not supply approval provenance, confidentiality or a proof of safety.
