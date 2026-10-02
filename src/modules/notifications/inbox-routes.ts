import type { FastifyInstance,FastifyRequest } from 'fastify';
import { z } from 'zod';
import { AppError } from '../../errors.js';
import { parseInput } from '../../http.js';
import { binary,identifier } from '../../shared/contracts.js';
import { inboxReference,inboxListRequest,inboxMutation } from '../../shared/inbox.js';
import { readSessionCookie } from '../identity/sessions.js';
import type { RequestBudgets } from '../identity/budgets.js';
import type { InboxService } from './inbox.js';
export function registerInboxRoutes(app:FastifyInstance,input:{origin:string;inbox:InboxService;budgets:Pick<RequestBudgets,'take'>}){
  const auth=(request:FastifyRequest)=>{const cookie=readSessionCookie(request.headers.cookie),csrf=request.headers['x-csrf-token'];
    if(!cookie)throw new AppError('AUTH_REQUIRED','Authentication required',401);
    if(typeof csrf!=='string'||!binary(32).safeParse(csrf).success)throw new AppError('CSRF_REJECTED','Request verification failed',403);return{cookie,csrf};};
  function route<T>(name:string,schema:z.ZodType<T>,handler:(body:T,a:{cookie:string;csrf:string})=>Promise<unknown>){
    app.post('/v1/inbox/'+name,{bodyLimit:128*1024,preHandler:async (request,reply)=>{
      reply.header('cache-control','no-store');
      if(request.headers.origin!==input.origin||request.headers['sec-fetch-site']==='cross-site')throw new AppError('ORIGIN_REJECTED','Request origin is not allowed',403);
      if(Object.keys(request.query as object).length)throw new AppError('INVALID_REQUEST','Invalid request',400);
      await input.budgets.take([{purpose:'inbox-source',key:request.ip,limit:1200,windowMs:600000}]);
    }},async request=>{const body=parseInput(schema,request.body),credentials=auth(request);
      try{return await handler(body,credentials);}catch(error){if(error instanceof AppError)throw error;throw new AppError('INBOX_UNAVAILABLE','Inbox is temporarily unavailable',503);}
    });
  }
  route('context',inboxReference,(b,a)=>input.inbox.context(a.cookie,a.csrf,b));
  route('save',inboxMutation,(b,a)=>input.inbox.save(a.cookie,a.csrf,b));
  route('status',inboxReference,(b,a)=>input.inbox.status(a.cookie,a.csrf,b));
  route('list',inboxListRequest,(b,a)=>input.inbox.list(a.cookie,a.csrf,b));
  route('resolve',z.strictObject({workspaceId:identifier,notificationId:identifier}),(b,a)=>input.inbox.resolve(a.cookie,a.csrf,b));
  route('preference',z.strictObject({workspaceId:identifier,projectId:identifier}),(b,a)=>input.inbox.preference(a.cookie,a.csrf,b));
}
