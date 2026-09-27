import type { FastifyInstance,FastifyRequest } from 'fastify';
import { z } from 'zod';
import { AppError } from '../../errors.js';
import { parseInput } from '../../http.js';
import { binary } from '../../shared/contracts.js';
import { restoreContextRequest,restoreStatusRequest,restoreVerification,RESTORE_MAX_BYTES } from '../../shared/restoration.js';
import { readSessionCookie } from '../identity/sessions.js';
import type { RequestBudgets } from '../identity/budgets.js';
import type { RestorationService,RestoreAuth } from './service.js';
export function registerRestorationRoutes(app:FastifyInstance,options:{origin:string;restoration:RestorationService;budgets:Pick<RequestBudgets,'take'>}){
  function auth(request:FastifyRequest):RestoreAuth{const csrfToken=request.headers['x-csrf-token'],cookieValue=readSessionCookie(request.headers.cookie);
    if(typeof csrfToken!=='string'||!binary(32).safeParse(csrfToken).success)throw new AppError('CSRF_REJECTED','Request verification failed',403);
    if(!cookieValue)throw new AppError('AUTH_REQUIRED','Authentication required',401);return {cookieValue,csrfToken};}
  function route<T>(path:string,schema:z.ZodType<T>,action:(a:RestoreAuth,b:T)=>Promise<unknown>){app.post(`/v1/restoration/${path}`,{bodyLimit:RESTORE_MAX_BYTES,
    preHandler:async(request,reply)=>{reply.header('cache-control','no-store');if(request.headers.origin!==options.origin||request.headers['sec-fetch-site']==='cross-site')throw new AppError('ORIGIN_REJECTED','Request origin is not allowed',403);
      if(Object.keys(request.query as object).length)throw new AppError('INVALID_REQUEST','Invalid restoration request',400);
      await options.budgets.take([{purpose:'restoration-source',key:request.ip,limit:120,windowMs:600000}]);}},async request=>{
      try{return await action(auth(request),parseInput(schema,request.body));}catch(error){if(error instanceof AppError)throw error;throw new AppError('RESTORE_UNAVAILABLE','Restoration verification is unavailable; workspace remains quarantined',503);}});}
  route('context',restoreContextRequest,(a,b)=>options.restoration.context(a,b));route('verify',restoreVerification,(a,b)=>options.restoration.verify(a,b));route('status',restoreStatusRequest,(a,b)=>options.restoration.status(a,b));
}
