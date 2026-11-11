"""Bounded synthetic quota-policy replay, not a scanner or secret input."""
import copy
import json
from pathlib import Path
from .audit import _findings, _text
from .models import ScanResult, SEVERITY_ORDER
from .quota import SCHEMA, quota_payload, quota_identity, explain_quota
from .baseline import fingerprint


def quota_spec(spec):
    if not isinstance(spec, dict) or set(spec) != {'current','prior','errors','files_scanned','policy'}:
        raise ValueError('Exact quota replay root required')
    source = copy.deepcopy(spec)
    for name in ['current','prior']:
        if not isinstance(source[name], list):
            raise ValueError('Finding lists required')
        for r in source[name]:
            if not isinstance(r, dict) or type(r.get('line')) is not int:
                raise ValueError('Integer finding line required')
    current, prior = _findings(source['current']), _findings(source['prior'])
    if type(source['files_scanned']) is not int or not 0 <= source['files_scanned'] <= 16:
        raise ValueError('File count bound')
    if not isinstance(source['errors'], list) or len(source['errors']) > 8:
        raise ValueError('Error label bound')
    for error in source['errors']:
        _text(error)
    p=source['policy']
    if not isinstance(p,dict) or set(p) != {'min_severity','fail_on','max_findings'}:
        raise ValueError('Exact policy required')
    if not isinstance(p['min_severity'],str) or p['min_severity'] not in SEVERITY_ORDER or (p['fail_on'] is not None and (not isinstance(p['fail_on'],str) or p['fail_on'] not in SEVERITY_ORDER)):
        raise ValueError('Unknown severity')
    if p['max_findings'] is not None and (type(p['max_findings']) is not int or not 0 <= p['max_findings'] <= 1000000):
        raise ValueError('Finding count bound')
    # Prior capture uses the SAME eligibility threshold, like the actual writer.
    eligible_prior=tuple(f for f in prior if SEVERITY_ORDER[f.severity]>=SEVERITY_ORDER[p['min_severity']])
    baseline=quota_payload(eligible_prior)
    quotas={e['identity']:e['count'] for e in baseline['entries']}
    witness=explain_quota(ScanResult(source['files_scanned'],current,tuple(source['errors'])),quotas,**p)
    old_known={fingerprint(f) for f in eligible_prior}
    legacy_rows=[]
    for i,f in enumerate(current):
        eligible=SEVERITY_ORDER[f.severity]>=SEVERITY_ORDER[p['min_severity']]
        matched=fingerprint(f) in old_known
        legacy_rows.append(dict(index=i,fingerprint=fingerprint(f),baseline_match=matched,
                                disposition='below_filter' if not eligible else 'suppressed' if matched else 'reported'))
    return dict(schema=SCHEMA,spec=source,baseline=baseline,
                prior_rows=[dict(index=i,finding=f.to_dict(),identity=quota_identity(f),eligible=SEVERITY_ORDER[f.severity]>=SEVERITY_ORDER[p['min_severity']]) for i,f in enumerate(prior)],
                witness=witness,legacy=dict(rows=legacy_rows,counts={d:sum(r['disposition']==d for r in legacy_rows) for d in ['below_filter','suppressed','reported']}))


def parse_quota_spec(text):
    if not isinstance(text,str) or len(text.encode('utf-8'))>131072:
        raise ValueError('Replay input exceeds128KiB')
    # Bound structural depth before the JSON parser, respecting escaped strings.
    depth=0;string=False;escape=False
    for c in text:
        if string:
            if escape: escape=False
            elif c=='\\': escape=True
            elif c=='"': string=False
        elif c=='"':string=True
        elif c in '[{':
            depth+=1
            if depth>8:raise ValueError('JSON depth exceeds8')
        elif c in ']}':depth-=1
    def unique(pairs):
        out={}
        for k,v in pairs:
            if k in out:raise ValueError('Duplicate JSON key')
            out[k]=v
        return out
    def bad(_):raise ValueError('Integer nonnegative numeric spelling required')
    def integer(s):
        if s.startswith('-'):bad(s)
        return int(s)
    return json.loads(text,object_pairs_hook=unique,parse_float=bad,parse_constant=bad,parse_int=integer)


def main(argv=None):
    import argparse,sys
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input',required=True)
    args=parser.parse_args(argv)
    try:
        if args.input=='-':
            text=sys.stdin.buffer.read(131073).decode('utf-8')
        else:
            with Path(args.input).open('rb') as stream:
                text=stream.read(131073).decode('utf-8')
        report=quota_spec(parse_quota_spec(text))
        print(json.dumps(report,indent=2,sort_keys=True,allow_nan=False))
        return 0
    except (ValueError,OSError,UnicodeError,OverflowError,RecursionError) as exc:
        print(f'quota replay error: {exc}',file=sys.stderr)
        return 2


if __name__=='__main__':
    raise SystemExit(main())
