import json,pathlib,subprocess,sys
import promptguard.quota,promptguard.quota_audit,promptguard.cli
from promptguard.quota_audit import quota_spec
root=pathlib.Path(sys.argv[1]).resolve()
for module in [promptguard.quota,promptguard.quota_audit,promptguard.cli]:
    assert not pathlib.Path(module.__file__).resolve().is_relative_to(root),module.__file__
cases=json.loads((root/'examples/quota-reports.json').read_text())
for c in cases:
    assert quota_spec(c['spec'])==c['report']
    for command in [[sys.executable,'-I','-m','promptguard.quota_audit'],[str(pathlib.Path(sys.executable).parent/'promptguard-quota-audit')]]:
        p=subprocess.run(command+['--input','-'],input=json.dumps(c['spec']),text=True,capture_output=True)
        assert p.returncode==0,p.stderr
        assert json.loads(p.stdout)==c['report']
source=pathlib.Path('fixture.txt');source.write_text('reviewer@example.invalid\n')
cli=str(pathlib.Path(sys.executable).parent/'promptguard')
p=subprocess.run([cli,'scan',str(source),'--write-quota-baseline','quota.json'],capture_output=True,text=True);assert p.returncode==0,p.stdout
source.write_text('reviewer@example.invalid\nreviewer@example.invalid\n')
p=subprocess.run([cli,'scan',str(source),'--quota-baseline','quota.json','--fail-on','medium','--audit','witness.json','--json','report.json'],capture_output=True,text=True);assert p.returncode==1,p.stdout
w=json.loads(pathlib.Path('witness.json').read_text());assert w['counts']==dict(below_filter=0,suppressed=1,reported=1);assert w['gates']['exit_code']==1
print('Installed quota API/module/console all24reports; actualscanner duplicate allowance gate passes;3module origins outside checkout')
