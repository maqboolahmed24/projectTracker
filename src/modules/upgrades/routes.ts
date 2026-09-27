import type { FastifyInstance, FastifyRequest } from 'fastify';
import { z } from 'zod';
import { AppError } from '../../errors.js';
import { parseInput } from '../../http.js';
import { binary } from '../../shared/contracts.js';
import { upgradeBatch,upgradeContextRequest,upgradeFinish,upgradeStart,upgradeStatusRequest,UPGRADE_MAX_CONTEXT_BYTES } from '../../shared/upgrade-api.js';
import type { RequestBudgets } from '../identity/budgets.js';
import { readSessionCookie } from '../identity/sessions.js';
import type { UpgradeAuth,UpgradeService } from './service.js';

export function registerUpgradeRoutes(app:FastifyInstance,options:{origin:string;upgrades:UpgradeService;budgets:Pick<RequestBudgets,'take'>}){
  function auth(request:FastifyRequest):UpgradeAuth{
    const csrfToken=request.headers['x-csrf-token'],cookieValue=readSessionCookie(request.headers.cookie);
    if(typeof csrfToken!=='string'||!binary(32).safeParse(csrfToken).success)throw new AppError('CSRF_REJECTED','Request verification failed',403);
    if(!cookieValue)throw new AppError('AUTH_REQUIRED','Authentication required',401);
    return {cookieValue,csrfToken};
  }
  function route<T>(path:string,schema:z.ZodType<T>,action:(auth:UpgradeAuth,body:T)=>Promise<unknown>){
    app.post(`/v1/upgrades/${path}`,{bodyLimit:UPGRADE_MAX_CONTEXT_BYTES,preHandler:async(request,reply)=>{
      reply.header('cache-control','no-store');
      if(request.headers.origin!==options.origin||request.headers['sec-fetch-site']==='cross-site')throw new AppError('ORIGIN_REJECTED','Request origin is not allowed',403);
      if(Object.keys(request.query as object).length)throw new AppError('INVALID_REQUEST','Invalid encrypted upgrade request',400);
      await options.budgets.take([{purpose:'upgrades-source',key:request.ip,limit:600,windowMs:600000}]);
    }},async request=>{
      const body=parseInput(schema,request.body),credentials=auth(request);
      try{return await action(credentials,body);}catch(error){
        if(error instanceof AppError)throw error;
        throw new AppError('UPGRADE_UNAVAILABLE','Encrypted upgrade is temporarily unavailable; retain the signed request',503);
      }
    });
  }
  route('context',upgradeContextRequest,(a,b)=>options.upgrades.context(a,b));
  route('start',upgradeStart,(a,b)=>options.upgrades.start(a,b));
  route('batch',upgradeBatch,(a,b)=>options.upgrades.batch(a,b));
  route('finish',upgradeFinish,(a,b)=>options.upgrades.finish(a,b));
  route('status',upgradeStatusRequest,(a,b)=>options.upgrades.status(a,b));
}
