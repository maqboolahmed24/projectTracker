import type { FastifyInstance,FastifyRequest } from 'fastify';
import { z } from 'zod';
import { AppError } from '../../errors.js';
import { parseInput } from '../../http.js';
import { binary,identifier } from '../../shared/contracts.js';
import { lifecycleContextRequest,lifecycleMutation,lifecycleStatusRequest } from '../../shared/lifecycle.js';
import type { RequestBudgets } from '../identity/budgets.js';
import { readSessionCookie } from '../identity/sessions.js';
import type { LifecycleAuth,LifecycleService } from './service.js';
export function registerLifecycleRoutes(app:FastifyInstance,options:{origin:string;lifecycle:LifecycleService;budgets:Pick<RequestBudgets,'take'>}){
 function auth(request:FastifyRequest):LifecycleAuth{
  const cookieValue=readSessionCookie(request.headers.cookie),csrfToken=request.headers['x-csrf-token'];
  if(!cookieValue)throw new AppError('AUTH_REQUIRED','Authentication required',401);
  if(typeof csrfToken!=='string'||!binary(32).safeParse(csrfToken).success)throw new AppError('CSRF_REJECTED','Request verification failed',403);
  return {cookieValue,csrfToken};
 }
 function route<T>(path:string,schema:z.ZodType<T>,action:(a:LifecycleAuth,b:T)=>Promise<unknown>){
  app.post(`/v1/lifecycle/${path}`,{bodyLimit:256*1024,preHandler:async(request,reply)=>{
   reply.header('cache-control','no-store');
   if(request.headers.origin!==options.origin||request.headers['sec-fetch-site']==='cross-site')throw new AppError('ORIGIN_REJECTED','Request origin is not allowed',403);
   if(Object.keys(request.query as object).length)throw new AppError('INVALID_REQUEST','Invalid lifecycle request',400);
   await options.budgets.take([{purpose:'lifecycle-source',key:request.ip,limit:120,windowMs:600000}]);
  }},async request=>action(auth(request),parseInput(schema,request.body)));
 }
 route('context',lifecycleContextRequest,(a,b)=>options.lifecycle.context(a,b));
 route('save',lifecycleMutation,(a,b)=>options.lifecycle.save(a,b));
 route('status',lifecycleStatusRequest,(a,b)=>options.lifecycle.status(a,b));
 route('erasures',z.strictObject({workspaceId:identifier}),(a,b)=>options.lifecycle.erasures(a,b.workspaceId));
}
