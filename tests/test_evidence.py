import contextlib,hashlib,io,itertools,json,re,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from promptguard.audit import audit_spec,explain_scan,load_spec
from promptguard.baseline import BaselineError,apply_baseline,fingerprint,load_baseline,write_baseline
from promptguard.cli import main
from promptguard.models import Finding,ScanResult,SEVERITY_ORDER
from promptguard.scanner import scan_text,scan_paths
from promptguard.report import render_report,render_markdown,render_sarif,render_junit
ROOT=Path(__file__).resolve().parents[1]
def f(severity='high',rule='DEMO',**kw):return Finding(rule,severity,'demo.txt',1,'Synthetic review','Redacted context',**kw)
class EvidenceTests(unittest.TestCase):
 def test_original_files_preserved(self):
  for p,h in json.loads((ROOT/'docs/original-sha256.json').read_text()).items():
   file=ROOT/('docs/original-readme.md' if p=='README.md' else p);self.assertEqual(hashlib.sha256(file.read_bytes()).hexdigest(),h,p)
 def test_all_retained_reports(self):
  cases=json.loads((ROOT/'docs/audit.json').read_text())['cases'];self.assertEqual(len(cases),27)
  for c in cases:self.assertEqual(audit_spec(c['report']['spec']),c['report'])
 def test_exhaustive_small_policy_space(self):
  checked=0;levels=list(SEVERITY_ORDER)
  for n in range(3):
   for values in itertools.product(range(5),repeat=n):
    fs=tuple(f(levels[v],str(i)) for i,v in enumerate(values))
    for bits in itertools.product([False,True],repeat=n):
     known=frozenset(fingerprint(fs[i]) for i,b in enumerate(bits) if b)
     for minimum in range(5):
      for fail in [None,*range(5)]:
       for cap in [None,0,1,2]:
        kept=[i for i,v in enumerate(values) if v>=minimum and not bits[i]]
        expected=bool(fail is not None and any(values[i]>=fail for i in kept) or cap is not None and len(kept)>cap)
        r=explain_scan(ScanResult(1,fs),known,min_severity=levels[minimum],fail_on=levels[fail] if fail is not None else None,max_findings=cap)
        self.assertEqual(r['reported_indices'],kept);self.assertEqual(r['gates']['exit_code'],int(expected));checked+=1
  self.assertEqual(checked,13320)
 def test_all_sensitive_occurrences_same_line(self):
  fs=[x for x in scan_text(Path('x.txt'),'first@example.invalid second@example.invalid') if x.rule_id=='PII_EMAIL'];self.assertEqual(len(fs),2);self.assertNotEqual(fingerprint(fs[0]),fingerprint(fs[1]))
  kept,count=apply_baseline(ScanResult(1,tuple(fs)),frozenset([fingerprint(fs[0])]))
  self.assertEqual(count,1);self.assertEqual(kept.findings,(fs[1],))
 def test_generic_token_rule_all_occurrences_safe_pattern(self):
  with patch('promptguard.scanner.TOKEN_RULES',(('DEMO_TOKEN',re.compile(r'DEMO-[AB]'),'high','Synthetic match'),)):
   fs=[x for x in scan_text(Path('x.txt'),'DEMO-A DEMO-B') if x.rule_id=='DEMO_TOKEN'];self.assertEqual(len(fs),2)
 def test_redact_before_truncate(self):
  text='x'*165+' first@example.invalid';fs=scan_text(Path('x.txt'),text)
  self.assertTrue(fs);self.assertNotIn('first@',fs[0].excerpt);self.assertIn('<email>',fs[0].excerpt)
 def test_metadata_excerpt_is_redacted_and_rotation_bound(self):
  one=scan_text(Path('x.md'),'first@example.invalid');two=scan_text(Path('x.md'),'second@example.invalid')
  self.assertNotIn('first@',str([x.to_dict() for x in one]));a=next(x for x in one if x.rule_id=='STRUCTURE_FRONTMATTER');b=next(x for x in two if x.rule_id=='STRUCTURE_FRONTMATTER');self.assertNotEqual(fingerprint(a),fingerprint(b))
 def test_no_raw_contact_in_any_report(self):
  result=ScanResult(1,scan_text(Path('x.md'),'first@example.invalid second@example.invalid'))
  for s in [json.dumps(result.to_dict()),render_report(result),render_markdown(result),render_sarif(result,version='0.2.0'),render_junit(result),json.dumps(explain_scan(result))]:
   self.assertNotIn('first@',s);self.assertNotIn('second@',s);self.assertNotIn('material_digest',s)
 def test_files_scanned_counts_successful_reads(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'bad.txt';p.write_bytes(b'\0data');r=scan_paths([str(p)]);self.assertEqual(r.files_scanned,0);self.assertEqual(len(r.errors),1)
 def test_scan_error_exits_two_and_keeps_reports(self):
  with tempfile.TemporaryDirectory() as d,contextlib.redirect_stdout(io.StringIO()):
   p=Path(d);rc=main(['scan',str(p/'missing.txt'),'--json',str(p/'out.json'),'--audit',str(p/'audit.json')]);self.assertEqual(rc,2);self.assertTrue(json.loads((p/'out.json').read_text())['errors']);self.assertEqual(json.loads((p/'audit.json').read_text())['gates']['status'],'incomplete')
 def test_incomplete_scan_does_not_write_baseline(self):
  with tempfile.TemporaryDirectory() as d,contextlib.redirect_stdout(io.StringIO()):
   p=Path(d);b=p/'baseline.json';self.assertEqual(main(['scan',str(p/'missing.txt'),'--write-baseline',str(b)]),2);self.assertFalse(b.exists())
 def test_errors_dominate_findings(self):self.assertEqual(explain_scan(ScanResult(1,(f(),),('Synthetic error',)),fail_on='high')['gates']['exit_code'],2)
 def test_negative_limit_rejected(self):
  with self.assertRaises(ValueError):explain_scan(ScanResult(0,()),max_findings=-1)
  with contextlib.redirect_stdout(io.StringIO()):self.assertEqual(main(['scan','examples/prompts/safe.md','--max-findings','-1']),2)
 def test_baseline_strict_and_unicode(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'x'
   for raw in [b'\xff',b'{"schema_version":true,"fingerprints":[]}',b'{"schema_version":1,"fingerprints":["bad"]}',b'{"schema_version":1,"schema_version":1,"fingerprints":[]}']:
    p.write_bytes(raw)
    with self.assertRaises(BaselineError):load_baseline(p)
 def test_identity_does_not_bind_severity_or_line(self):self.assertEqual(fingerprint(f('low')),fingerprint(Finding('DEMO','critical','demo.txt',99,'Synthetic review','Redacted context')))
 def test_path_whitespace_alias_is_exposed_not_repaired(self):self.assertEqual(fingerprint(Finding('D','low','a  b',1,'m','e')),fingerprint(Finding('D','low','a b',1,'m','e')))
 def test_audit_cli_and_native_scan_witness(self):
  with tempfile.TemporaryDirectory() as d,contextlib.redirect_stdout(io.StringIO()):
   p=Path(d)/'r.json';self.assertEqual(main(['audit','--spec',str(ROOT/'examples/audit.json'),'--json',str(p)]),0);self.assertEqual(json.loads(p.read_text()),audit_spec(load_spec(ROOT/'examples/audit.json')))
   self.assertEqual(main(['scan',str(ROOT/'examples/prompts/safe.md'),'--audit',str(p)]),0);self.assertEqual(json.loads(p.read_text())['gates']['exit_code'],0)
 def test_invalid_spec_rejected(self):
  spec=json.loads((ROOT/'examples/audit.json').read_text())
  for key,value in [('current',[{}]),('files_scanned',True),('errors',[3]),('policy',{'min_severity':[], 'fail_on':None,'max_findings':None})]:
   v=dict(spec);v[key]=value
   with self.assertRaises(ValueError):audit_spec(v)
 def test_loader_duplicate_nonfinite(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'x'
   for raw in ['{"x":1,"x":2}','{"x":NaN}']:
    p.write_text(raw)
    with self.assertRaises(ValueError):load_spec(p)
