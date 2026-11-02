import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { isDemoOverview } from '../app/demo-overview.ts';

const valid = () => ({mode:'synthetic-demo',notice:'synthetic fixture',records:[{id:'x',title:'t',category:'c',severity:'High',source:'s',observed_at:'2026-10-31T08:00:00Z',confidence:50,description:'d',synthetic:true}],sources:[{name:'fixture',status:'not configured'}]});
test('accept only bounded, explicitly synthetic demo contract',()=>{
  assert.equal(isDemoOverview(valid()),true);
  for (const change of [
    (v:ReturnType<typeof valid>)=>{v.mode='production'},
    (v:ReturnType<typeof valid>)=>{v.records[0].synthetic=false},
    (v:ReturnType<typeof valid>)=>{v.sources[0].status='online'},
    (v:ReturnType<typeof valid>)=>{v.records[0].observed_at='invalid'},
    (v:ReturnType<typeof valid>)=>{v.records[0].confidence=101},
    (v:ReturnType<typeof valid>)=>{v.records[0].title='x'.repeat(501)},
    (v:ReturnType<typeof valid>)=>{v.records.push({...v.records[0]})},
    (v:ReturnType<typeof valid>)=>{v.records=Array(101).fill(v.records[0])},
  ]) {const v=valid();change(v);assert.equal(isDemoOverview(v),false)}
  assert.equal(isDemoOverview({...valid(), secret:'not for demo'}),false);
  assert.equal(isDemoOverview({...valid(),records:[{...valid().records[0],secret:'not for demo'}]}),false);
  for (const value of [null,[],{},'text']) assert.equal(isDemoOverview(value),false);
});
