import contextlib
import io
import itertools
import json
from pathlib import Path
import random
import tempfile
import unittest
from unittest.mock import patch
from dataclasses import replace
from promptguard.models import Finding, ScanResult, SEVERITY_ORDER
from promptguard.quota import (SCHEMA, quota_identity, quota_payload, validate_quota,
                               load_quota, write_quota, explain_quota)
from promptguard.baseline import fingerprint
from promptguard.cli import main
from promptguard.scanner import scan_text


class QuotaTests(unittest.TestCase):
    def finding(self, **kwargs):
        return replace(Finding('FIXTURE_RULE', 'medium', 'fixture/a.txt', 1,
                               'abstract finding', 'abstract excerpt'), **kwargs)

    def test_exact_identity_boundaries_and_legacy_unchanged(self):
        f = self.finding()
        self.assertEqual(quota_identity(f), quota_identity(replace(f, line=99)))
        for field, value in [('rule_id','OTHER'), ('severity','high'),
                             ('path','fixture\\a.txt'), ('path','fixture/ a.txt'),
                             ('message','different'), ('excerpt','different')]:
            self.assertNotEqual(quota_identity(f), quota_identity(replace(f, **{field:value})))
        self.assertEqual(fingerprint(f), fingerprint(replace(f, severity='critical', line=2, path='fixture\\a.txt')))
        sensitive = replace(f, material_digest='a'*64)
        self.assertEqual(quota_identity(sensitive), quota_identity(replace(sensitive, message='different', excerpt='different')))
        self.assertNotEqual(quota_identity(sensitive), quota_identity(replace(sensitive, material_digest='b'*64)))
        self.assertNotEqual(quota_identity(f), quota_identity(sensitive))
        # JSON array framing has no newline-delimiter ambiguity.
        self.assertNotEqual(quota_identity(replace(f, rule_id='x\ny',path='z')), quota_identity(replace(f,rule_id='x',path='y\nz')))

    def test_finite_consumption_no_mutation(self):
        f = self.finding(); identity = quota_identity(f); q = {identity:1}
        r = explain_quota(ScanResult(1,(f,replace(f,line=5),f)),q,fail_on='medium')
        self.assertEqual([x['disposition'] for x in r['rows']],['suppressed','reported','reported'])
        self.assertEqual([x['remaining_before'] for x in r['rows']],[1,0,0])
        self.assertEqual(r['gates']['exit_code'],1)
        self.assertEqual(q,{identity:1})
        self.assertEqual(explain_quota(ScanResult(1,()),q)['entries'][0]['remaining'],1)
        self.assertEqual(explain_quota(ScanResult(1,(f,),('fixture unreadable',)),q)['gates']['exit_code'],2)

    def test_filter_does_not_consume_and_strict_count_boundary(self):
        f=self.finding();q={quota_identity(f):2}
        r=explain_quota(ScanResult(1,(f,f)),q,min_severity='high')
        self.assertEqual(r['counts'],dict(below_filter=2,suppressed=0,reported=0))
        self.assertEqual(r['entries'][0]['remaining'],2)
        for limit,code in [(0,1),(1,0),(2,0)]:
            self.assertEqual(explain_quota(ScanResult(1,(f,f,f)),q,max_findings=limit)['gates']['exit_code'],code)

    def test_exhaustive_independent_occurrence_ranks(self):
        choices=[self.finding(),self.finding(severity='high'),self.finding(path='fixture/b.txt')]
        checks=0
        for indices in itertools.product(range(3), repeat=4):
            rows=tuple(choices[i] for i in indices)
            for counts in itertools.product(range(3), repeat=3):
                quotas={quota_identity(f):n for f,n in zip(choices,counts) if n}
                for threshold in ['info','high']:
                    expected=[]
                    for i,f in enumerate(rows):
                        eligible=SEVERITY_ORDER[f.severity]>=SEVERITY_ORDER[threshold]
                        rank=sum(quota_identity(g)==quota_identity(f) and SEVERITY_ORDER[g.severity]>=SEVERITY_ORDER[threshold] for g in rows[:i+1])
                        expected.append('below_filter' if not eligible else 'suppressed' if rank<=quotas.get(quota_identity(f),0) else 'reported')
                    r=explain_quota(ScanResult(1,rows),quotas,min_severity=threshold)
                    self.assertEqual([x['disposition'] for x in r['rows']],expected)
                    for entry in r['entries']:
                        self.assertEqual(entry['used']+entry['remaining'],entry['declared'])
                    checks+=1
        self.assertEqual(checks,4374)

    def test_payload_strict_file_and_roundtrip(self):
        f=self.finding();payload=quota_payload((f,f));self.assertEqual(payload['entries'][0]['count'],2)
        for bad in [None,{},dict(payload,extra=1),dict(schema=SCHEMA,entries=[payload['entries'][0]]*2),
                    dict(schema=SCHEMA,entries=[dict(identity='not-a-digest',count=1)]),
                    *[dict(schema=SCHEMA,entries=[dict(identity=quota_identity(f),count=n)]) for n in [True,0,-1,1.0,1000001]],
                    dict(schema=SCHEMA,entries=[dict(payload['entries'][0],extra=1)])]:
            with self.assertRaises(ValueError):validate_quota(bad)
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'quota.json';self.assertEqual(write_quota(p,(f,f)),(1,2));self.assertEqual(load_quota(p),{quota_identity(f):2})
            for text in ['{"schema":"x","schema":"y","entries":[]}',json.dumps(payload).replace('"count": 2','"count": 2.0'),json.dumps(payload).replace('"count": 2','"count": 2e0'),'[]','{"schema":NaN}', '['*1200]:
                p.write_text(text)
                with self.assertRaises(ValueError):load_quota(p)
            p.write_bytes(b'\xff')
            with self.assertRaises(ValueError):load_quota(p)
            p.write_bytes(b' '*1048577)
            with self.assertRaises(ValueError):load_quota(p)
            with self.assertRaises(ValueError):load_quota(Path(d)/'missing.json')

    def test_real_scanner_contact_duplication_and_exports(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);source=root/'fixture.txt';quota=root/'quota.json';output=root/'report.json';audit=root/'audit.json'
            source.write_text('reviewer@example.invalid\n')
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(['scan',str(source),'--write-quota-baseline',str(quota)]),0)
                source.write_text('reviewer@example.invalid\nreviewer@example.invalid\n')
                self.assertEqual(main(['scan',str(source),'--quota-baseline',str(quota),'--fail-on','medium','--json',str(output),'--audit',str(audit),
                                       '--html',str(root/'report.html'),'--junit',str(root/'report.xml'),'--sarif',str(root/'report.sarif'),'--markdown',str(root/'report.md')]),1)
            report=json.loads(output.read_text());w=json.loads(audit.read_text())
            self.assertEqual(report['finding_count'],1);self.assertEqual(report['suppressed_count'],1)
            self.assertEqual(report['findings'][0]['line'],2);self.assertEqual(w['gates']['exit_code'],1)
            self.assertEqual(w['counts'],dict(below_filter=0,suppressed=1,reported=1))
            for file in root.glob('report.*'):
                self.assertNotIn('reviewer@example.invalid',file.read_text())
            self.assertNotIn('reviewer@example.invalid',quota.read_text())
            self.assertNotIn('material_digest',audit.read_text())

    def test_incomplete_no_write_and_modes_fail_before_outputs(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);q=root/'quota.json';out=root/'report.json'
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(['scan',str(root/'missing'),'--write-quota-baseline',str(q)]),2)
                self.assertFalse(q.exists())
                for flags in [['--quota-baseline',str(q)],['--quota-baseline',str(q),'--baseline',str(q)],['--write-quota-baseline',str(q),'--write-baseline',str(q)],['--quota-baseline',str(q),'--write-quota-baseline',str(q)]]:
                    self.assertEqual(main(['scan',str(root/'missing'),'--json',str(out),*flags]),2)
                    self.assertFalse(out.exists())

    def test_real_scanner_same_line_multiple_contacts(self):
        a=scan_text(Path('fixture.txt'),'a@example.invalid a@example.invalid')
        self.assertEqual(len(a),2);self.assertEqual(quota_identity(a[0]),quota_identity(a[1]))
        r=explain_quota(ScanResult(1,a),{quota_identity(a[0]):1})
        self.assertEqual(r['counts']['reported'],1)

    def test_atomic_replace_failure_preserves_prior_quota(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'quota.json';p.write_text('previous bytes')
            with patch('promptguard.quota.os.replace',side_effect=OSError('fixture replace failure')):
                with self.assertRaises(OSError):write_quota(p,(self.finding(),))
            self.assertEqual(p.read_text(),'previous bytes')
            self.assertEqual(sorted(x.name for x in Path(d).iterdir()),['quota.json'])

    def test_all_complete_replays_and_cli(self):
        from promptguard.quota_audit import quota_spec,parse_quota_spec
        import subprocess,sys
        root=Path(__file__).resolve().parents[1]
        cases=json.loads((root/'examples/quota-reports.json').read_text())
        for c in cases:
            self.assertEqual(quota_spec(parse_quota_spec(json.dumps(c['spec']))),c['report'])
        p=subprocess.run([sys.executable,'-m','promptguard.quota_audit','--input','-'],input=json.dumps(cases[0]['spec']),text=True,capture_output=True)
        self.assertEqual(p.returncode,0,p.stderr);self.assertEqual(json.loads(p.stdout),cases[0]['report'])
        p=subprocess.run([sys.executable,'-m','promptguard.quota_audit','--input','-'],input='{}',text=True,capture_output=True)
        self.assertEqual(p.returncode,2);self.assertEqual(p.stdout,'')

    def test_strict_replay_boundary_and_integer_objects(self):
        from promptguard.quota_audit import quota_spec,parse_quota_spec
        for text in ['{"x":1,"x":2}','{"x":1.0}','{"x":1e0}','{"x":-0}','{"x":NaN}','['*9+']'*9,' '*131073,'[01]','{"x":1,}']:
            with self.assertRaises(ValueError):parse_quota_spec(text)
        root=Path(__file__).resolve().parents[1]
        c=json.loads((root/'examples/quota.json').read_text())
        for value in [True,1.0]:
            c['current'][0]['line']=value
            with self.assertRaises(ValueError):quota_spec(c)

    def test_actual_identity_escalation_and_order_tradeoff(self):
        a=self.finding();b=replace(a,line=9)
        q={quota_identity(a):1}
        x=explain_quota(ScanResult(1,(a,b)),q)
        y=explain_quota(ScanResult(1,(b,a)),q)
        self.assertEqual(x['counts'],y['counts'])
        self.assertEqual(x['reported']['findings'][0]['line'],9)
        self.assertEqual(y['reported']['findings'][0]['line'],1)
        for f in [replace(a,severity='high'),replace(a,path='fixture\\a.txt'),replace(a,path='fixture/ a.txt')]:
            self.assertEqual(explain_quota(ScanResult(1,(f,)),q)['counts']['reported'],1)
        for threshold in [[],{},True]:
            with self.assertRaises(ValueError):explain_quota(ScanResult(1,(a,)),q,min_severity=threshold)

    def test_seeded_full_browser_differential(self):
        from promptguard.quota_audit import quota_spec
        import subprocess
        rng=random.Random(7047);root=Path(__file__).resolve().parents[1];cases=[]
        for i in range(200):
            pool=[dict(rule_id='FIXTURE_RULE_'+str(j%2),severity=rng.choice(list(SEVERITY_ORDER)),path=rng.choice(['fixture/a.txt','fixture\\a.txt','fixture/ a.txt','fixture/b.txt']),line=j+1,message='abstract '+str(j%3),excerpt='abstract '+str(j%2),material_tag=rng.choice([None,'fixture:alpha','fixture:beta'])) for j in range(5)]
            prior=[dict(rng.choice(pool)) for _ in range(rng.randrange(17))];current=[dict(rng.choice(pool),line=rng.randrange(1,100)) for _ in range(rng.randrange(17))]
            spec=dict(current=current,prior=prior,errors=['fixture:read'] if i%13==0 else [],files_scanned=1,policy=dict(min_severity=rng.choice(list(SEVERITY_ORDER)),fail_on=rng.choice([None,*SEVERITY_ORDER]),max_findings=rng.choice([None,0,1,3,16])))
            cases.append(dict(spec=spec,report=quota_spec(spec)))
        script="import {quotaSpec} from './docs/quota-engine.js';import assert from 'node:assert/strict';let s='';for await(const c of process.stdin)s+=c;for(const r of JSON.parse(s))assert.deepEqual(await quotaSpec(r.spec),r.report);console.log('200 seeded fullreports exact')"
        p=subprocess.run(['node','--input-type=module','-e',script],input=json.dumps(cases),text=True,capture_output=True,cwd=root)
        self.assertEqual(p.returncode,0,p.stderr)
