import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import test from 'node:test';
import Fastify from 'fastify';
import { AppError } from '../src/errors.js';
import { registerCollaborationRoutes } from '../src/modules/collaboration/routes.js';
import { registerWorkReadRoutes } from '../src/modules/work/routes.js';
import { readSessionCookie, SESSION_COOKIE_NAME } from '../src/modules/identity/sessions.js';
import { digestObject } from '../src/shared/crypto.js';
import { collaborationFixture } from './collaboration-fixture.js';
import { origin } from './password-change-fixture.js';

test('CP09 HTTP: strict encrypted commands require origin, CSRF and live session; receipts replay and hidden entries never consume ordinary page slots',async(t)=>{
  const f=await collaborationFixture(t),taskId=await f.createTask(),app=Fastify({logger:false}),budgets:unknown[]=[];
  app.setErrorHandler((error,_request,reply)=>reply.code(error instanceof AppError?error.statusCode:503).send({error:{code:error instanceof AppError?error.code:'UNAVAILABLE'}}));
  registerCollaborationRoutes(app,{origin,collaboration:f.collaboration,budgets:{async take(entries){budgets.push(entries);}}});
  registerWorkReadRoutes(app,f.databases,async(request)=>{const cookie=readSessionCookie(request.headers.cookie);if(!cookie)throw new AppError('AUTH_REQUIRED','Authentication required',401);return f.sessions.authenticate(cookie,{approved:true});});
  t.after(()=>app.close());
  const auth=f.auth(),headers={origin,cookie:`${SESSION_COOKIE_NAME}=${auth.cookieValue}`,'x-csrf-token':auth.csrfToken};
  const post=(path:string,payload:object,custom=headers)=>app.inject({method:'POST',url:`/v1/collaboration/${path}`,headers:custom,payload});
  const ref=f.ref('comment');
  assert.equal((await post('context',ref,{...headers,origin:'https://foreign.example'})).statusCode,403);assert.equal(budgets.length,0);
  assert.equal((await post('context',ref,{...headers,'x-csrf-token':''})).statusCode,403);
  assert.equal((await post('context',ref,{...headers,cookie:''})).statusCode,401);
  assert.equal((await post('context',{...ref,text:'Never accept plaintext here'})).statusCode,400);
  assert.equal((await post('context?plaintext=forbidden',ref)).statusCode,400);
  const initial=await post('context',ref);assert.equal(initial.statusCode,200);assert.equal(initial.headers['cache-control'],'no-store');assert.equal(initial.json().entry,null);
  const ids=[randomUUID(),randomUUID()].sort();let first;
  for(const entryId of ids){const payload=await f.prepareCollaboration({action:'post_comment',entryId,taskId},{text:'Private HTTP comment'});const saved=await post('save',payload);
    assert.equal(saved.statusCode,200);assert.equal(saved.json().state,'completed');assert.deepEqual((await post('save',payload)).json(),saved.json());
    const b=payload.mutation.body.binding;assert.deepEqual((await post('status',{workspaceId:b.workspaceId,projectId:b.projectId,operationId:b.operationId,dataGeneration:b.dataGeneration,requestHash:await digestObject(payload)})).json(),saved.json());
    if(entryId===ids[0])first=payload;
  }
  const row=(await f.readCollaboration('comment')).records.find((entry)=>entry.entryId===ids[0])!;
  const moderation=await f.prepareCollaboration({action:'hide_comment',entryId:ids[0]!,expectedRevision:'1',previousHead:row.head,originalDigest:row.originalDigest},{reason:'Private HTTP moderation reason'});
  assert.equal((await post('save',moderation)).statusCode,200);
  const list=await post('list',{workspaceId:f.workspaceId,projectId:f.projectId,kind:'comment',taskId,limit:1});assert.equal(list.statusCode,200);assert.equal(list.json().entries.length,1);assert.equal(list.json().complete,true);
  const retained=await post('list',{workspaceId:f.workspaceId,projectId:f.projectId,kind:'comment',taskId,includeHidden:true,limit:1});
  assert.equal(retained.statusCode,200);assert.equal(retained.json().entries.length,1);assert.ok(retained.json().entries[0].moderation);
  assert.notEqual(retained.json().anchor,list.json().anchor);assert.equal(retained.json().complete,false);
  assert.equal(retained.body.includes('Private HTTP moderation reason'),false);
  const retainedNext=await post('list',{workspaceId:f.workspaceId,projectId:f.projectId,kind:'comment',taskId,includeHidden:true,limit:1,
    after:retained.json().nextCursor,anchor:retained.json().anchor});
  assert.equal(retainedNext.statusCode,200);assert.equal(retainedNext.json().complete,true);
  assert.equal((await post('list',{workspaceId:f.workspaceId,projectId:f.projectId,kind:'comment',taskId,limit:1,
    after:retained.json().nextCursor,anchor:retained.json().anchor})).statusCode,409);
  assert.equal((await post('list',{workspaceId:f.workspaceId,projectId:f.projectId,kind:'comment',includeHidden:'true'})).statusCode,400);
  assert.equal((await post('list',{workspaceId:f.workspaceId,projectId:f.projectId,kind:'comment',includeHidden:true},{...headers,cookie:''})).statusCode,401);
  const ordinary=await app.inject({method:'GET',url:`/v1/workspaces/${f.workspaceId}/projects/${f.projectId}/records/comments?limit=1`,headers});
  assert.equal(ordinary.statusCode,200);assert.equal(ordinary.json().records[0].id,ids[1]);assert.equal(ordinary.json().nextCursor,null);
  const history=await post('history',f.ref('comment',ids[0]!));assert.equal(history.statusCode,200);assert.deepEqual(history.json().entry.origin.payload,first);assert.ok(history.json().entry.moderation);
  const source=await post('list',{workspaceId:f.workspaceId,projectId:f.projectId,kind:'comment',taskId,limit:1,after:ids[1]});assert.equal(source.statusCode,400);
  const foreign=await post('context',{...ref,projectId:randomUUID()});assert.equal(foreign.statusCode,403);
});
