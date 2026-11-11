"""Generate input-only controls and complete native quota reports."""
import copy,json,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from promptguard.quota_audit import quota_spec
ROOT=Path(__file__).resolve().parents[1]

def record(**kw):
    return dict(dict(rule_id='FIXTURE_RULE',severity='medium',path='fixture/a.txt',line=1,message='abstract finding',excerpt='abstract excerpt',material_tag='fixture:alpha'),**kw)

def spec(current,prior,**p):
    return dict(current=current,prior=prior,errors=[],files_scanned=1,policy=dict(dict(min_severity='info',fail_on='medium',max_findings=None),**p))

def controls():
    a=record();cases=[]
    def add(name,s):cases.append(dict(id=name,spec=s))
    add('one-allowance-three-occurrences',spec([a,record(line=3),record(line=5)],[a]))
    add('exact-allowance',spec([a,a],[a,a]))
    add('empty-prior',spec([a],[]))
    add('empty-current',spec([],[a,a]))
    add('all-empty',spec([],[]))
    add('severity-escalation',spec([record(severity='critical')],[a]))
    add('slash-alias',spec([record(path='fixture\\a.txt')],[a]))
    add('whitespace-alias',spec([record(path='fixture/ a.txt')],[a]))
    add('line-move',spec([record(line=999999)],[a]))
    add('material-rotation',spec([record(material_tag='fixture:beta')],[a]))
    add('same-material-new-excerpt',spec([record(excerpt='different excerpt')],[a]))
    add('same-material-new-message',spec([record(message='different message')],[a]))
    b=record(material_tag=None)
    add('content-unchanged',spec([b],[b]))
    add('content-excerpt-change',spec([dict(b,excerpt='different')],[b]))
    add('content-message-change',spec([dict(b,message='different')],[b]))
    add('rule-change',spec([record(rule_id='OTHER_RULE')],[a]))
    add('below-filter-capture',spec([a,a],[a],min_severity='high'))
    add('count-equality',spec([a,a],[a],fail_on=None,max_findings=1))
    add('count-exceeded',spec([a,a],[a],fail_on=None,max_findings=0))
    s=spec([a,a],[a]);s['errors']=['fixture:unreadable'];add('incomplete-outranks-gate',s)
    add('interleaved-identities',spec([a,record(path='fixture/b.txt'),a,record(path='fixture/b.txt')],[a,record(path='fixture/b.txt')]))
    add('reordered-interchangeable-occurrences',spec([record(line=9),record(line=2)],[a]))
    add('max-sixteen',spec([record(line=i+1) for i in range(16)],[a]*8,max_findings=8,fail_on=None))
    add('five-severities',spec([record(severity=s) for s in ['info','low','medium','high','critical']],[a],min_severity='medium',fail_on='high'))
    return cases

if __name__=='__main__':
    cases=controls();reports=[dict(c,report=quota_spec(c['spec'])) for c in cases]
    def save(path,obj):path.write_text(json.dumps(obj,separators=(',',':'),sort_keys=True)+'\n')
    save(ROOT/'examples/quota.json',cases[0]['spec']);save(ROOT/'examples/quota-reports.json',reports)
    (ROOT/'docs/quota-data.js').write_text('export const quotaCases='+json.dumps(cases,separators=(',',':'),sort_keys=True)+';\n')
    print(json.dumps(dict(cases=len(cases),current=sum(len(r['spec']['current']) for r in reports),prior=sum(len(r['spec']['prior']) for r in reports),entries=sum(len(r['report']['baseline']['entries']) for r in reports))))
