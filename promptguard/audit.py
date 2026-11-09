"""Full-stage suppression/gate evidence. This does not evaluate scanner detection quality."""
import copy, hashlib, json, re, math
from pathlib import Path
from .baseline import fingerprint
from .models import Finding, ScanResult, SEVERITY_ORDER


def explain_scan(result, known=frozenset(), *, min_severity='info', fail_on=None, max_findings=None):
    if not isinstance(min_severity,str) or min_severity not in SEVERITY_ORDER or (fail_on is not None and (not isinstance(fail_on,str) or fail_on not in SEVERITY_ORDER)):
        raise ValueError('Unknown severity')
    if max_findings is not None and (type(max_findings) is not int or max_findings < 0):
        raise ValueError('Finding limit must be a nonnegative integer')
    rows = []
    for i, f in enumerate(result.findings):
        fp = fingerprint(f)
        eligible = SEVERITY_ORDER[f.severity] >= SEVERITY_ORDER[min_severity]
        matched = fp in known
        disposition = 'below_filter' if not eligible else 'suppressed' if matched else 'reported'
        rows.append(dict(index=i, finding=f.to_dict(), fingerprint=fp, eligible=eligible,
                         baseline_match=matched, disposition=disposition))
    reported_indices = [r['index'] for r in rows if r['disposition'] == 'reported']
    severity_indices = [i for i in reported_indices if fail_on is not None and SEVERITY_ORDER[result.findings[i].severity] >= SEVERITY_ORDER[fail_on]]
    count_exceeded = max_findings is not None and len(reported_indices) > max_findings
    exit_code = 2 if result.errors else 1 if severity_indices or count_exceeded else 0
    filtered = ScanResult(result.files_scanned, tuple(result.findings[i] for i in reported_indices), result.errors)
    used = sorted({r['fingerprint'] for r in rows if r['eligible'] and r['baseline_match']})
    return dict(schema_version=1, policy=dict(min_severity=min_severity, fail_on=fail_on, max_findings=max_findings),
                rows=rows, baseline_fingerprints=sorted(known), used_baseline_fingerprints=used,
                unused_baseline_fingerprints=sorted(set(known)-set(used)),
                counts={k:sum(r['disposition']==k for r in rows) for k in ['below_filter','suppressed','reported']},
                reported_indices=reported_indices, reported=filtered.to_dict(),
                gates=dict(severity_indices=severity_indices, count_limit=max_findings, count_observed=len(reported_indices), count_exceeded=count_exceeded,
                           scan_errors=list(result.errors), complete=not bool(result.errors), exit_code=exit_code,
                           status='incomplete' if exit_code==2 else 'failed' if exit_code==1 else 'passed'))


def _text(v, maximum=180):
    if not isinstance(v,str) or len(v)>maximum or any(ord(c)<32 or ord(c)>126 for c in v):
        raise ValueError('Audit text must be bounded printable ASCII')


def _integer(v, lo, hi):
    return not isinstance(v,bool) and isinstance(v,(int,float)) and lo<=v<=hi and math.isfinite(v) and v==int(v)

def _findings(records):
    if not isinstance(records,list) or len(records)>16:
        raise ValueError('At most sixteen abstract findings per list')
    out=[]
    for r in records:
        if not isinstance(r,dict) or set(r)!={'rule_id','severity','path','line','message','excerpt','material_tag'}:
            raise ValueError('Exact abstract finding fields required')
        for k in ['rule_id','severity','path','message','excerpt']:_text(r[k])
        if not r['rule_id'] or not r['path'] or r['severity'] not in SEVERITY_ORDER:
            raise ValueError('Invalid rule/path/severity')
        if not _integer(r['line'],1,1000000):raise ValueError('Invalid line')
        tag=r['material_tag']
        if tag is not None and (not isinstance(tag,str) or not re.fullmatch(r'fixture:[A-Za-z0-9.-]{1,32}',tag)):
            raise ValueError('Only synthetic fixture tags, never secret material')
        digest=hashlib.sha256(tag.encode()).hexdigest() if tag is not None else None
        out.append(Finding(**{k:(int(v) if k=='line' else v) for k,v in r.items() if k!='material_tag'}, material_digest=digest))
    return tuple(out)


def audit_spec(spec):
    if not isinstance(spec,dict) or set(spec)!={'current','prior','errors','files_scanned','policy'}:raise ValueError('Exact audit root fields required')
    source=copy.deepcopy(spec);current=_findings(source['current']);prior=_findings(source['prior'])
    if not isinstance(source['errors'],list) or len(source['errors'])>8:raise ValueError('At most eight synthetic error labels')
    for e in source['errors']:_text(e)
    if not _integer(source['files_scanned'],0,16):raise ValueError('File count bound')
    policy=source['policy']
    if not isinstance(policy,dict) or set(policy)!={'min_severity','fail_on','max_findings'}:raise ValueError('Exact policy fields required')
    if policy['max_findings'] is not None and not _integer(policy['max_findings'],0,1000000):raise ValueError('Finding cap bound')
    policy=dict(policy,max_findings=int(policy['max_findings']) if policy['max_findings'] is not None else None)
    known=frozenset(fingerprint(f) for f in prior)
    witness=explain_scan(ScanResult(int(source['files_scanned']),current,tuple(source['errors'])),known,**policy)
    return dict(schema_version=1,spec=source,baseline_rows=[dict(index=i,finding=f.to_dict(),fingerprint=fingerprint(f)) for i,f in enumerate(prior)],witness=witness)


def load_spec(path):
    p=Path(path)
    if p.stat().st_size>131072:raise ValueError('Audit file exceeds 128KiB')
    def unique(items):
        out={}
        for k,v in items:
            if k in out:raise ValueError('Duplicate JSON key')
            out[k]=v
        return out
    return json.loads(p.read_text(),object_pairs_hook=unique,parse_constant=lambda _:(_ for _ in ()).throw(ValueError('Nonfinite JSON token')))
