from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from .baseline import BaselineError, apply_baseline, load_baseline, write_baseline
from .quota import load_quota, write_quota, explain_quota
from .models import SEVERITY_ORDER, ScanResult
from .audit import explain_scan, audit_spec, load_spec
from . import __version__
from .report import render_junit, render_markdown, render_report, render_sarif
from .scanner import scan_paths


def cmd_scan(args) -> int:
    if args.max_findings is not None and args.max_findings < 0:
        print("ERROR finding limit must be nonnegative")
        return 2
    quota_mode = args.quota_baseline is not None or args.write_quota_baseline is not None
    if quota_mode and (args.baseline is not None or args.write_baseline is not None):
        print("ERROR legacy and quota baseline modes cannot be combined")
        return 2
    if args.quota_baseline is not None and args.write_quota_baseline is not None:
        print("ERROR reading and writing quota baselines cannot be combined")
        return 2
    quotas = {}
    if args.quota_baseline is not None:
        try:
            quotas = load_quota(args.quota_baseline)
        except ValueError as exc:
            print(f"ERROR {exc}")
            return 2
    complete_result = scan_paths(args.paths, min_severity="info")
    result = ScanResult(complete_result.files_scanned, tuple(f for f in complete_result.findings if SEVERITY_ORDER[f.severity] >= SEVERITY_ORDER[args.min_severity]), complete_result.errors)
    if args.write_baseline and not result.errors:
        written = write_baseline(args.write_baseline, result.findings)
        print(f"wrote baseline {args.write_baseline} with {written} fingerprint(s)")
    if args.write_quota_baseline is not None and not result.errors:
        try:
            identities, occurrences = write_quota(args.write_quota_baseline, result.findings)
        except (ValueError, OSError, UnicodeError) as exc:
            print(f"ERROR {exc}")
            return 2
        print(f"wrote quota baseline {args.write_quota_baseline} with {identities} identities and {occurrences} occurrences")
    suppressed = 0
    known = frozenset()
    if args.baseline:
        try:
            known = load_baseline(args.baseline)
        except BaselineError as exc:
            print(f"ERROR {exc}")
            return 2
        result, suppressed = apply_baseline(result, known)
    witness = explain_scan(complete_result, known, min_severity=args.min_severity, fail_on=args.fail_on, max_findings=args.max_findings)
    if quota_mode:
        witness = explain_quota(complete_result, quotas, min_severity=args.min_severity, fail_on=args.fail_on, max_findings=args.max_findings)
        result = ScanResult(result.files_scanned, tuple(complete_result.findings[i] for i in witness['reported_indices']), result.errors)
        suppressed = witness['counts']['suppressed']
    if args.audit:
        Path(args.audit).write_text(json.dumps(witness, indent=2, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8")
    payload = result.to_dict()
    if args.baseline or args.quota_baseline:
        payload["suppressed_count"] = suppressed
    if args.json:
        Path(args.json).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.html:
        Path(args.html).write_text(render_report(result), encoding="utf-8")
    if args.sarif:
        Path(args.sarif).write_text(render_sarif(result, version=__version__), encoding="utf-8")
    if args.junit:
        Path(args.junit).write_text(render_junit(result), encoding="utf-8")
    if args.markdown:
        Path(args.markdown).write_text(render_markdown(result, suppressed=suppressed), encoding="utf-8", newline="\n")
    print(f"scanned {result.files_scanned} file(s), {len(result.findings)} finding(s), max severity {result.max_severity or 'none'}")
    if args.quota_baseline:
        print(f"{suppressed} finding(s) suppressed by occurrence quota {args.quota_baseline}")
    if args.baseline:
        print(f"{suppressed} finding(s) suppressed by baseline {args.baseline}")
    for finding in result.findings:
        print(f"{finding.severity.upper()} {finding.rule_id} {finding.path}:{finding.line} {finding.message} :: {finding.excerpt}")
    for error in result.errors:
        print(f"WARN {error}")
    if result.errors:
        print("ERROR scan incomplete; refusing a successful gate")
        return 2
    if args.fail_on and result.at_or_above(args.fail_on):
        print(f"FAIL finding at or above {args.fail_on}")
        return 1
    if args.max_findings is not None and len(result.findings) > args.max_findings:
        print(f"FAIL {len(result.findings)} findings (> {args.max_findings})")
        return 1
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="promptguard", description="Lint AI prompts and configs for secrets, PII and prompt-injection risk.")
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="scan prompt/config files or directories")
    scan.add_argument("paths", nargs="+", help="files or directories to scan")
    scan.add_argument("--min-severity", choices=tuple(SEVERITY_ORDER), default="info", help="minimum severity to include")
    scan.add_argument("--fail-on", choices=tuple(SEVERITY_ORDER), help="exit 1 when any finding reaches this severity")
    scan.add_argument("--max-findings", type=int, help="exit 1 above this finding count")
    scan.add_argument("--baseline", help="suppress findings recorded in this baseline file")
    scan.add_argument("--write-baseline", help="record the current findings as a baseline file and continue")
    scan.add_argument("--quota-baseline", help="suppress at most declared occurrence counts with exact path/severity identities")
    scan.add_argument("--write-quota-baseline", help="record eligible occurrence counts without applying suppression; refuses incomplete scans")
    scan.add_argument("--audit", help="write full redacted filtering, baseline and gate witness JSON")
    scan.add_argument("--json", help="write machine-readable JSON report")
    scan.add_argument("--html", help="write standalone escaped HTML report")
    scan.add_argument("--sarif", help="write SARIF 2.1.0 report for code-scanning tools")
    scan.add_argument("--junit", help="write JUnit XML report for CI test viewers")
    scan.add_argument("--markdown", help="write Markdown report for CI job summaries")
    scan.set_defaults(func=cmd_scan)
    audit = sub.add_parser("audit", help="recompute bounded synthetic finding-policy evidence (not a scanner)")
    audit.add_argument("--spec", required=True)
    audit.add_argument("--json", required=True)
    def audit_command(args):
        try:
            report = audit_spec(load_spec(args.spec))
            Path(args.json).write_text(json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n")
        except (ValueError, OSError, UnicodeError, OverflowError) as exc:
            print(f"ERROR {exc}")
            return 2
        return 0
    audit.set_defaults(func=audit_command)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
