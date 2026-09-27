import assert from 'node:assert/strict';
import test from 'node:test';
import { createHandoffLink, encodeHandoff, parseHandoff, parseRecoveryKit, type HandoffInput } from '../frontend/identity/handoff.js';

const origin='https://workspace.example.test';
const workspaceId='11111111-1111-4111-8111-111111111111';
const accountId='22222222-2222-4222-8222-222222222222';
const operationId='33333333-3333-4333-8333-333333333333';
const genesisFingerprint='a'.repeat(64);
const join:HandoffInput={kind:'join',workspaceId,code:'JOIN-ABCD-EFGH-JKLM',genesisFingerprint};
const raw=(value:unknown)=>JSON.stringify(value);
const encoded=(value:string)=>Buffer.from(value,'utf8').toString('base64url');

test('frontend handoffs round-trip every supported journey without a query credential',()=>{
  const values:HandoffInput[]=[
    {kind:'signin',workspaceId,accountId},join,
    {kind:'reset',workspaceId,code:'RESET-ABCD-EFGH-JKLM'},
    ...(['join','reset','pair'] as const).map(ceremony=>({kind:'approve' as const,workspaceId,operationId,ceremony})),
    {kind:'promote',workspaceId,operationId},
  ];
  for(const input of values){
    const link=createHandoffLink(input,origin),url=new URL(link),expected={...input,version:1,origin};
    assert.equal(url.origin,origin);assert.equal(url.pathname,'/');assert.equal(url.search,'');
    assert.match(url.hash,/^#access=[A-Za-z0-9_-]+$/);
    assert.deepEqual({...parseHandoff(link,origin)},expected);
    assert.deepEqual({...parseHandoff(url.hash,origin)},expected);
    assert.deepEqual({...parseHandoff(encodeHandoff(input,origin),origin)},expected);
    assert.deepEqual({...parseHandoff(raw(expected),origin)},expected);
    if('code'in input){assert.ok(!url.pathname.includes(input.code));assert.ok(!url.search.includes(input.code));}
  }
});

test('frontend handoffs reject credentials in any query and ambiguous fragment parameters',()=>{
  const link=createHandoffLink(join,origin),fragment=new URL(link).hash;
  for(const query of ['?code=JOIN-ABCD-EFGH-JKLM','?password=secret','?resumeToken=secret','?access='+encodeHandoff(join,origin),'?tracking=1']){
    assert.throws(()=>parseHandoff(origin+'/'+query+fragment,origin));
  }
  for(const tail of ['&password=secret','&access=second','&code=JOIN-ABCD-EFGH-JKLM']){
    assert.throws(()=>parseHandoff(link+tail,origin));
  }
  assert.throws(()=>parseHandoff(origin+'/?code=JOIN-ABCD-EFGH-JKLM',origin));
});

test('frontend handoffs accept only the exact secure application origin',()=>{
  const valid=createHandoffLink(join,origin),fragment=new URL(valid).hash;
  for(const bad of [
    'https://other.example.test/'+fragment,
    'http://workspace.example.test/'+fragment,
    'https://workspace.example.test:444/'+fragment,
    'https://someone:password@workspace.example.test/'+fragment,
    origin+'/another-page'+fragment,
    'javascript:alert(1)','data:text/plain,anything','file:///tmp/link.json',
  ])assert.throws(()=>parseHandoff(bad,origin));
  assert.throws(()=>parseHandoff(raw({...join,version:1,origin:'https://other.example.test'}),origin));
  assert.throws(()=>createHandoffLink(join,'http://public.example.test'));
  assert.throws(()=>createHandoffLink(join,'https://workspace.example.test/path'));
  for(const local of ['http://localhost:3555','http://127.0.0.1:3555','http://[::1]:3555']){
    assert.equal(parseHandoff(createHandoffLink(join,local),local).origin,local);
  }
});

test('frontend handoffs reject secret fields, changed schemas and invalid public references',()=>{
  const base={...join,version:1,origin};
  for(const field of ['password','phrase','resumeToken','csrfToken','privateKey','displayName','redirect','url']){
    const source=raw({...base,[field]:'never-echo-this-secret'});
    assert.throws(()=>parseHandoff(source,origin),error=>error instanceof Error&&!error.message.includes('never-echo-this-secret'));
    assert.throws(()=>createHandoffLink({...join,[field]:'private'} as HandoffInput,origin));
  }
  for(const invalid of [
    {...base,version:2},{...base,workspaceId:'../../private'},
    {...base,genesisFingerprint:'a'.repeat(63)},{...base,genesisFingerprint:'z'.repeat(64)},
    {...base,code:'JOIN-ABCD-EFGH-0000'},{...base,code:'RESET-ABCD-EFGH-JKLM'},
    {...base,kind:'owner'},{...base,code:null},
    {version:1,origin,kind:'signin',workspaceId,accountId:'name'},
    {version:1,origin,kind:'approve',workspaceId,operationId,ceremony:'delete'},
    {version:1,origin,kind:'promote',workspaceId,operationId:'not-an-id'},
  ])assert.throws(()=>parseHandoff(raw(invalid),origin));
});

test('frontend handoffs fail closed on duplicate JSON fields, malformed and oversized files',()=>{
  const valid=raw({...join,version:1,origin});
  const duplicate=valid.slice(0,-1)+',"workspaceId":"'+workspaceId+'"}';
  const poisoned=valid.slice(0,-1)+',"__proto__":{"kind":"signin"}}';
  for(const source of [duplicate,poisoned]){
    assert.throws(()=>parseHandoff(source,origin));
    assert.throws(()=>parseHandoff(encoded(source),origin));
  }
  for(const source of ['', ' ', 'not a link', '{}', '[]', 'null', '{broken', '%GG', 'x'.repeat(12001)])assert.throws(()=>parseHandoff(source,origin));
  const fieldMissing={...join,version:1,origin} as Record<string,unknown>;delete fieldMissing.genesisFingerprint;
  assert.throws(()=>parseHandoff(raw(fieldMissing),origin));
});

test('recovery kit files keep account identity bound to the exact origin and reject extra secrets or duplicate fields',()=>{
  // Deliberately public fixture words; mnemonic proof remains the recovery Worker's responsibility.
  const kit={version:1,language:'english',application:origin,workspaceId,accountId,genesisFingerprint,phrase:Array(24).fill('abandon').join(' ')};
  assert.deepEqual({...parseRecoveryKit(raw(kit),origin)},kit);
  for(const bad of [
    {...kit,application:'https://other.example.test'},{...kit,workspaceId:'wrong'},
    {...kit,accountId:'wrong'},{...kit,genesisFingerprint:'b'.repeat(63)},
    {...kit,phrase:'only two'},{...kit,language:'other'},{...kit,version:2},
    {...kit,password:'never-echo-this-secret'},{...kit,resumeToken:'never-echo-this-secret'},
  ])assert.throws(()=>parseRecoveryKit(raw(bad),origin));
  const valid=raw(kit);assert.throws(()=>parseRecoveryKit(valid.slice(0,-1)+',"application":"'+origin+'"}',origin));
  assert.throws(()=>parseRecoveryKit('x'.repeat(12001),origin));
  assert.throws(()=>parseRecoveryKit('null',origin));
});
