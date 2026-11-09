"""Synthetic finding-policy controls. No scanner effectiveness or secret corpus."""
import copy,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from promptguard.audit import audit_spec

def row(severity='high',tag=None,**kw):
    return dict(rule_id='DEMO_RULE',severity=severity,path='demo/prompt.txt',line=1,message='Synthetic review finding',excerpt='Already redacted fixture context',material_tag=tag,**kw)
def build():
    cases=[]
    def add(name,current=(),prior=(),minimum='info',fail='high',limit=None,errors=()):
        spec=dict(current=list(current),prior=list(prior),errors=list(errors),files_scanned=1,policy=dict(min_severity=minimum,fail_on=fail,max_findings=limit))
        cases.append(dict(name=name,report=audit_spec(spec)))
    a=row();low=row('low');critical=row('critical');tag=row(tag='fixture:A')
    add('No findings, not proof of safety')
    add('High finding reaches severity gate',[a])
    add('Below filter is not a clean detection result',[a],minimum='critical')
    add('Known high finding is suppressed',[a],[a])
    add('Count exactly at cap passes',[low,low],fail=None,limit=2)
    add('Count above cap fails',[low,low],fail=None,limit=1)
    add('Zero cap rejects one finding',[low],fail=None,limit=0)
    add('Duplicate current identities are separate findings',[a,a],[a])
    add('Duplicate prior identities make one baseline entry',[a],[a,a])
    moved=dict(a,line=999);add('Line movement does not change identity',[moved],[a])
    path=dict(a,path='elsewhere/prompt.txt');add('Path change changes identity',[path],[a])
    alias=dict(a,path='demo\\prompt.txt');add('Slash normalization aliases paths',[alias],[a])
    spaces=dict(a,path='demo/a  b.txt');single=dict(a,path='demo/a b.txt');add('Whitespace normalization aliases distinct paths',[spaces],[single])
    add('Severity is not part of baseline identity',[critical],[low])
    changed=dict(a,message='Changed synthetic message');add('Content-mode message change is new',[changed],[a])
    changed=dict(a,excerpt='Changed redacted context');add('Content-mode excerpt change is new',[changed],[a])
    add('Same synthetic material tag stays suppressed',[tag],[tag])
    rotated=dict(tag,material_tag='fixture:B');add('Changed synthetic material tag is new',[rotated],[tag])
    other=dict(tag,message='New message',excerpt='New context',line=44);add('Material mode ignores context and line',[other],[tag])
    rule=dict(tag,rule_id='DEMO_OTHER');add('Material mode binds rule',[rule],[tag])
    add('Unused prior identity stays visible',[low],[dict(a,path='old.txt')],fail=None)
    add('Scan error dominates clean gate',errors=['Synthetic unreadable-file label'])
    add('Scan error dominates finding gate',[critical],limit=0,errors=['Synthetic traversal-error label'])
    add('All five severity levels',[row(s) for s in ['info','low','medium','high','critical']],minimum='medium',fail='critical',limit=2)
    add('Sixteen abstract findings',[dict(row('medium'),line=i+1,path=f'demo/{i}.txt') for i in range(16)],fail=None,limit=16)
    add('Escaped display data',[dict(a,path='demo/<b>.txt',message='<img src=x>',excerpt='<script>data only</script>')])
    add('Every stage stays visible',[dict(row(s),rule_id='DEMO_'+s.upper()) for s in ['info','low','high','critical']],[dict(row('low'),rule_id='DEMO_LOW')],minimum='low',fail='high',limit=1)
    return dict(schema_version=1,cases=cases)
if __name__=='__main__':
    data=build();(ROOT/'docs/audit.json').write_text(json.dumps(data,separators=(',',':'),sort_keys=True,allow_nan=False)+'\n')
    (ROOT/'examples/audit.json').write_text(json.dumps(data['cases'][17]['report']['spec'],indent=2,sort_keys=True)+'\n')
    print('Retained',len(data['cases']),'complete policy reports')
