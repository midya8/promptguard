import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {webcrypto} from 'node:crypto';
import {quotaSpec,parseQuotaSpec} from '../docs/quota-engine.js';
if(!globalThis.crypto)Object.defineProperty(globalThis,"crypto",{value:webcrypto});
const reports=JSON.parse(fs.readFileSync(new URL('../examples/quota-reports.json',import.meta.url),'utf8'));
test('all complete independent quota reports including identities legacy and gates',async()=>{
 for(const c of reports)assert.deepEqual(await quotaSpec(parseQuotaSpec(JSON.stringify(c.spec))),c.report,c.id);
});
test('strict replay JSON and schema boundaries',async()=>{
 for(const s of ['{"x":1,"x":2}','{"x":1.0}','{"x":1e0}','{"x":-0}','{"x":NaN}','['.repeat(9)+']'.repeat(9),' '.repeat(131073),'[01]','{"x":1,}','\u00a0{}'])assert.throws(()=>parseQuotaSpec(s),s.slice(0,50));
 for(const change of [x=>x.current[0].line=true,x=>x.current[0].material_tag='not a fixture',x=>x.policy.max_findings=1.5,x=>x.policy.fail_on={},x=>x.extra=1]){const s=structuredClone(reports[0].spec);change(s);await assert.rejects(quotaSpec(s))}
});
test('independent occurrence ranks agree with closed form over duplicate patterns',async()=>{
 const a=reports[0].spec.current[0];let cases=0;
 for(let n=0;n<=8;n++)for(let prior=0;prior<=8;prior++)for(const min of ['info','high']){
  const s={current:Array.from({length:n},(_,i)=>({...a,line:i+1})),prior:Array.from({length:prior},()=>({...a})),errors:[],files_scanned:1,policy:{min_severity:min,fail_on:'medium',max_findings:null}},r=await quotaSpec(s),eligible=min==='info';
  assert.equal(r.witness.counts.suppressed,eligible?Math.min(n,prior):0);assert.equal(r.witness.counts.reported,eligible?Math.max(0,n-prior):0);assert.equal(r.witness.counts.below_filter,eligible?0:n);cases++;
 }assert.equal(cases,162);
});
