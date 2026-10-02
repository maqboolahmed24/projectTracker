import type { FastifyInstance, FastifyRequest } from 'fastify';
import { z } from 'zod';
import { AppError } from '../../errors.js';
import { parseInput } from '../../http.js';
import { binary } from '../../shared/contracts.js';
import { exportStartRequest, exportPageRequest, exportFinalize } from '../../shared/export.js';
import { readSessionCookie } from '../identity/sessions.js';
import type { RequestBudgets } from '../identity/budgets.js';
import type { ExportAuth, ExportService } from './service.js';
export function registerExportRoutes(app:FastifyInstance,options:{origin:string;exports:ExportService;budgets:Pick<RequestBudgets,'take'>}) {
  function auth(request:FastifyRequest):ExportAuth {const cookieValue=readSessionCookie(request.headers.cookie),csrfToken=request.headers['x-csrf-token'];
    if(typeof csrfToken!=='string'||!binary(32).safeParse(csrfToken).success)throw new AppError('CSRF_REJECTED','Request verification failed',403);
    if(!cookieValue)throw new AppError('AUTH_REQUIRED','Authentication required',401);return {cookieValue,csrfToken};}
  function route<T>(path:string,schema:z.ZodType<T>,action:(auth:ExportAuth,body:T)=>Promise<unknown>) {
    app.post(`/v1/export/${path}`,{bodyLimit:32*1024,preHandler:async(request,reply)=>{
      reply.header('cache-control','no-store');if(request.headers.origin!==options.origin||request.headers['sec-fetch-site']==='cross-site')throw new AppError('ORIGIN_REJECTED','Request origin is not allowed',403);
      if(Object.keys(request.query as object).length)throw new AppError('EXPORT_INVALID','Invalid export request',400);
      await options.budgets.take([{purpose:'export-source',key:request.ip,limit:1200,windowMs:600000}]);
    }},async request=>{const body=parseInput(schema,request.body);return action(auth(request),body);});
  }
  route('start',exportStartRequest,(a,b)=>options.exports.start(a,b));
  route('page',exportPageRequest,(a,b)=>options.exports.page(a,b));
  route('finalize',exportFinalize,(a,b)=>options.exports.finalize(a,b));
}
