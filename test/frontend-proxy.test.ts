import test from 'node:test';
import assert from 'node:assert/strict';
import { POST, GET } from '../web/app/v1/[...path]/route.js';

test('frontend proxy preserves authenticated same-origin transport and separate cookies', async t => {
  t.mock.method(globalThis, 'fetch', async (url: URL, init: RequestInit) => {
    assert.equal(url.pathname, '/v1/auth/session');
    const headers = new Headers(init.headers);
    assert.equal(headers.get('origin'), 'https://workspace.example');
    assert.equal(headers.get('cookie'), '__Host-session=example');
    assert.equal(headers.get('x-csrf-token'), 'test-token');
    assert.equal(headers.get('authorization'), 'Setup example-setup-token');
    assert.equal(headers.has('x-forwarded-for'), false);
    assert.equal(init.redirect, 'manual');
    assert.equal(init.cache, 'no-store');
    assert.equal(new TextDecoder().decode(init.body as Uint8Array), '{}');
    const response = new Response('{"ok":true}', { headers: { 'content-type':'application/json', 'cache-control':'no-store' } });
    response.headers.append('set-cookie','__Host-session=updated; Secure; HttpOnly; Path=/');
    response.headers.append('set-cookie','__Host-other=updated; Secure; HttpOnly; Path=/');
    return response;
  });
  const result = await POST(new Request('https://workspace.example/v1/auth/session', {method:'POST',body:'{}',headers:{
    origin:'https://workspace.example',cookie:'__Host-session=example','x-csrf-token':'test-token',authorization:'Setup example-setup-token','x-forwarded-for':'untrusted',
  }}));
  assert.equal(result.status,200);
  assert.equal(result.headers.getSetCookie().length,2);
  assert.equal(result.headers.get('cache-control'),'no-store');
  assert.deepEqual(await result.json(),{ok:true});
});

test('frontend proxy carries allowed larger planning/update requests and bounds unknown-size bodies', async t => {
  let calls=0;
  t.mock.method(globalThis,'fetch',async (_url: URL, init: RequestInit)=>{
    calls++; assert.equal((init.body as Uint8Array).byteLength,2*1024*1024);
    return new Response('{}',{headers:{'content-type':'application/json'}});
  });
  for(const path of ['/v1/work/planning/save','/v1/upgrades/batch','/v1/restoration/verify','/v1/reporting/save']){
    const result=await POST(new Request('https://workspace.example'+path,{method:'POST',body:new Uint8Array(2*1024*1024)}));
    assert.equal(result.status,200,path);
  }
  // Request has no Content-Length: enforce the byte limit while reading too.
  const tooLarge=await POST(new Request('https://workspace.example/v1/auth/session',{method:'POST',body:new Uint8Array(1024*1024+1)}));
  assert.equal(tooLarge.status,413);
  const declared=await POST(new Request('https://workspace.example/v1/upgrades/batch',{method:'POST',body:'{}',headers:{'content-length':String(24*1024*1024+1)}}));
  assert.equal(declared.status,413);
  assert.equal(calls,4);
});

test('frontend proxy preserves cancellation and gives a bounded non-sensitive upstream failure', async t => {
  const controller=new AbortController();
  const request=new Request('https://workspace.example/v1/application',{signal:controller.signal});
  t.mock.method(globalThis,'fetch',async (_url: URL, init: RequestInit)=>{
    assert.equal(init.signal,request.signal);
    throw new Error('private upstream details');
  });
  const result=await GET(request);
  assert.equal(result.status,503);
  assert.equal(result.headers.get('cache-control'),'no-store');
  assert.equal((await result.text()).includes('private upstream'),false);
});
