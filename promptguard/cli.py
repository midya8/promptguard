from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from .models import SEVERITY_ORDER
from .report import render_report
from .scanner import scan_paths


def cmd_scan(args) -> int:
    result = scan_paths(args.paths, min_severity=args.min_severity)
    payload = result.to_dict()
    if args.json:
        Path(args.json).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.html:
        Path(args.html).write_text(render_report(result), encoding="utf-8")
    print(f"scanned {result.files_scanned} file(s), {len(result.findings)} finding(s), max severity {result.max_severity or 'none'}")
    for finding in result.findings:
        print(f"{finding.severity.upper()} {finding.rule_id} {finding.path}:{finding.line} {finding.message} :: {finding.excerpt}")
    for error in result.errors:
        print(f"WARN {error}")
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
    scan.add_argument("--json", help="write machine-readable JSON report")
    scan.add_argument("--html", help="write standalone escaped HTML report")
    scan.set_defaults(func=cmd_scan)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
