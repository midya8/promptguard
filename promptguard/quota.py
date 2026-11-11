"""Opt-in occurrence quotas. Legacy v1 baseline semantics are untouched."""
from __future__ import annotations
from collections import Counter
import hashlib
import json
import os
import tempfile
from pathlib import Path
import re
from .models import Finding, ScanResult, SEVERITY_ORDER

SCHEMA = 'promptguard-occurrence-quota/v1'
MAX_ENTRIES = 4096
MAX_COUNT = 1_000_000


def quota_identity(finding: Finding) -> str:
    # Exact path, including slash/whitespace spelling. Line deliberately omitted.
    basis = ['material', finding.material_digest] if finding.material_digest else ['content', finding.message, finding.excerpt]
    payload = [SCHEMA, finding.rule_id, finding.path, finding.severity, basis]
    encoded = json.dumps(payload, ensure_ascii=True, separators=(',', ':'), allow_nan=False).encode('ascii')
    return hashlib.sha256(encoded).hexdigest()


def validate_quota(payload):
    if not isinstance(payload, dict) or set(payload) != {'schema', 'entries'} or payload['schema'] != SCHEMA:
        raise ValueError('Exact quota schema and entries fields required')
    entries = payload['entries']
    if not isinstance(entries, list) or len(entries) > MAX_ENTRIES:
        raise ValueError('At most 4096 quota entries')
    quotas = {}
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {'identity', 'count'}:
            raise ValueError('Exact quota entry fields required')
        identity, count = entry['identity'], entry['count']
        if not isinstance(identity, str) or re.fullmatch(r'[0-9a-f]{64}', identity) is None:
            raise ValueError('Invalid quota identity')
        if type(count) is not int or not 1 <= count <= MAX_COUNT:
            raise ValueError('Quota count must be an integer in 1..1000000')
        if identity in quotas:
            raise ValueError('Duplicate quota identity')
        quotas[identity] = count
    return quotas


def quota_payload(findings):
    counts = Counter(quota_identity(f) for f in findings)
    payload = dict(schema=SCHEMA, entries=[dict(identity=k, count=v) for k, v in sorted(counts.items())])
    validate_quota(payload)
    return payload


def load_quota(path):
    path = Path(path)
    try:
        if path.stat().st_size > 1_048_576:
            raise ValueError('Quota file exceeds 1MiB')
        def unique(pairs):
            out = {}
            for key, value in pairs:
                if key in out:
                    raise ValueError('Duplicate JSON key in quota')
                out[key] = value
            return out
        def bad(_):
            raise ValueError('Quota JSON requires integer numeric spelling')
        with path.open('rb') as stream:
            raw = stream.read(1_048_577)
        if len(raw) > 1_048_576:
            raise ValueError('Quota file exceeds 1MiB')
        payload = json.loads(raw.decode('utf-8'), object_pairs_hook=unique, parse_float=bad, parse_constant=bad)
        return validate_quota(payload)
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError(f'Cannot read quota file: {exc}') from exc


def write_quota(path, findings):
    payload = quota_payload(findings)
    path = Path(path)
    # Do not damage a previous quota if serialization/write/replace fails.
    text = json.dumps(payload, indent=2, sort_keys=True) + '\n'
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', newline='\n', dir=path.parent, prefix='.quota-', delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()
    return len(payload['entries']), sum(e['count'] for e in payload['entries'])


def explain_quota(result, quotas, *, min_severity='info', fail_on=None, max_findings=None):
    # Revalidate API dictionaries too; caller-owned state is never decremented.
    payload = dict(schema=SCHEMA, entries=[dict(identity=k, count=v) for k, v in quotas.items()])
    remaining = validate_quota(payload)
    if not isinstance(min_severity,str) or min_severity not in SEVERITY_ORDER or (fail_on is not None and (not isinstance(fail_on,str) or fail_on not in SEVERITY_ORDER)):
        raise ValueError('Unknown severity')
    if max_findings is not None and (type(max_findings) is not int or max_findings < 0):
        raise ValueError('Finding limit must be a nonnegative integer')
    rows = []
    for i, f in enumerate(result.findings):
        identity = quota_identity(f)
        eligible = SEVERITY_ORDER[f.severity] >= SEVERITY_ORDER[min_severity]
        before = remaining.get(identity, 0)
        consumed = eligible and before > 0
        if consumed:
            remaining[identity] -= 1
        rows.append(dict(index=i, finding=f.to_dict(), identity=identity, eligible=eligible,
                         declared_count=quotas.get(identity, 0), remaining_before=before,
                         consumed=consumed, remaining_after=remaining.get(identity, 0),
                         disposition='below_filter' if not eligible else 'suppressed' if consumed else 'reported'))
    reported_indices = [r['index'] for r in rows if r['disposition'] == 'reported']
    filtered = ScanResult(result.files_scanned, tuple(result.findings[i] for i in reported_indices), result.errors)
    severity_indices = [i for i in reported_indices if fail_on is not None and SEVERITY_ORDER[result.findings[i].severity] >= SEVERITY_ORDER[fail_on]]
    exceeded = max_findings is not None and len(reported_indices) > max_findings
    exit_code = 2 if result.errors else 1 if severity_indices or exceeded else 0
    return dict(schema=SCHEMA, policy=dict(min_severity=min_severity, fail_on=fail_on, max_findings=max_findings),
                rows=rows, entries=[dict(identity=k, declared=v, used=v-remaining[k], remaining=remaining[k]) for k, v in sorted(quotas.items())],
                counts={d: sum(r['disposition'] == d for r in rows) for d in ['below_filter','suppressed','reported']},
                reported_indices=reported_indices, reported=filtered.to_dict(),
                gates=dict(severity_indices=severity_indices, count_limit=max_findings, count_observed=len(reported_indices), count_exceeded=exceeded,
                           scan_errors=list(result.errors), complete=not bool(result.errors), exit_code=exit_code,
                           status='incomplete' if exit_code == 2 else 'failed' if exit_code == 1 else 'passed'))
