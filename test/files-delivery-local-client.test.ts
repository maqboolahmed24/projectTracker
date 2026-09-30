import assert from 'node:assert/strict';
import test from 'node:test';
import {z} from 'zod';
import {DeliveryController,LocalDeliveryError} from '../src/client/files-delivery-controller.js';
import {FileClientError} from '../src/client/files-crypto.js';

// Exercise the actual bounded local HTTP protocol without cloud credentials or a real shared drive.
function local(fetcher:typeof fetch){
 const object=Object.create(DeliveryController.prototype) as {options:{localFetcher:typeof fetch};local:<T>(address:string,path:string,body:unknown,schema:z.ZodType<T>,signal:AbortSignal,token?:string)=>Promise<T>};
 object.options={localFetcher:fetcher};return object.local.bind(object);
}
test('Local delivery transport preserves actionable disk errors, rejects unexpected responses and never sends cookies',async()=>{
 const call=local(async(_url,options)=>{assert.equal(options?.credentials,'omit');assert.equal(options?.redirect,'error');assert.equal((options?.headers as Record<string,string>).authorization,'Bearer local-token');
  return Response.json({code:'DISK_FULL'},{status:400});});
 await assert.rejects(call('https://localhost:3411','/apply',{},z.strictObject({}),new AbortController().signal,'local-token'),e=>e instanceof LocalDeliveryError&&e.code==='DISK_FULL');
 const oversized=local(async()=>new Response(new Uint8Array(512*1024+1)));await assert.rejects(oversized('https://localhost:3411','/status',{},z.strictObject({}),new AbortController().signal),e=>e instanceof FileClientError&&e.code==='TOO_LARGE');
 const malformed=local(async()=>new Response('{"ready":true,"ready":false}'));await assert.rejects(malformed('https://localhost:3411','/status',{},z.strictObject({ready:z.boolean()}),new AbortController().signal),e=>e instanceof FileClientError&&e.code==='INVALID_FILE');
});
test('Local delivery requests have finite status/operation deadlines and user cancellation remains distinct',async t=>{
 const deadlines:number[]=[];t.mock.method(AbortSignal,'timeout',(ms:number)=>{deadlines.push(ms);return AbortSignal.abort(new DOMException('Timeout','TimeoutError'));});
 const call=local(async(_url,options)=>{assert.ok(options?.signal?.aborted);throw options.signal.reason;});
 for(const path of ['/status','/apply'])await assert.rejects(call('https://localhost:3411',path,{},z.strictObject({}),new AbortController().signal),e=>e instanceof LocalDeliveryError&&e.code==='LOCAL_TIMEOUT');
 assert.deepEqual(deadlines,[10000,120000]);
 const cancelled=new AbortController();cancelled.abort();await assert.rejects(call('https://localhost:3411','/apply',{},z.strictObject({}),cancelled.signal),e=>e instanceof FileClientError&&e.code==='CANCELLED');
});
