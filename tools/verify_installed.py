"""Run under installed Python -I, outside the repository."""
import importlib.util,json,sys
from pathlib import Path
root=Path(sys.argv[1]).resolve();origins={}
for name in ['promptguard','promptguard.__main__','promptguard.models','promptguard.scanner','promptguard.baseline','promptguard.audit','promptguard.cli','promptguard.report']:
    path=Path(importlib.util.find_spec(name).origin).resolve()
    assert root not in path.parents, (name,path)
    assert 'site-packages' in str(path),(name,path)
    origins[name]=str(path)
from promptguard.audit import audit_spec
cases=json.loads((root/'docs/audit.json').read_text())['cases']
for case in cases:assert audit_spec(case['report']['spec'])==case['report']
print(json.dumps(dict(module_origins=origins,cases=len(cases)),sort_keys=True))
