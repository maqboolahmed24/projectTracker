import type { FastifyInstance, FastifyRequest } from 'fastify';
import { z } from 'zod';
import { AppError } from '../../errors.js';
import { parseInput } from '../../http.js';
import { binary, identifier } from '../../shared/contracts.js';
import { reportingReference, reportingContextRequest, reportingSettingsPayload, reportingStatusRequest, reportingSummaryPayload } from '../../shared/reporting.js';
import type { RequestBudgets } from '../identity/budgets.js';
import { readSessionCookie } from '../identity/sessions.js';
import type { ReportingAuth, ReportingService } from './reporting.js';
export function registerReportingRoutes(app:FastifyInstance,options:{origin:string;reporting:ReportingService;budgets:Pick<RequestBudgets,'take'>}){
  function auth(request:FastifyRequest):ReportingAuth{const csrfToken=request.headers['x-csrf-token'],cookieValue=readSessionCookie(request.headers.cookie);
    if(typeof csrfToken!=='string'||!binary(32).safeParse(csrfToken).success)throw new AppError('CSRF_REJECTED','Request verification failed',403);
    if(!cookieValue)throw new AppError('AUTH_REQUIRED','Authentication required',401);return {cookieValue,csrfToken};}
  function route<T>(path:string,schema:z.ZodType<T>,action:(a:ReportingAuth,body:T)=>Promise<unknown>){
    app.post(`/v1/reporting/${path}`,{bodyLimit:2*1024*1024,preHandler:async(request,reply)=>{
      reply.header('cache-control','no-store');if(request.headers.origin!==options.origin||request.headers['sec-fetch-site']==='cross-site')throw new AppError('ORIGIN_REJECTED','Request origin is not allowed',403);
      if(Object.keys(request.query as object).length)throw new AppError('INVALID_REQUEST','Invalid reporting request',400);
      await options.budgets.take([{purpose:'reporting-source',key:request.ip,limit:600,windowMs:600000}]);
    }},async(request)=>{const body=parseInput(schema,request.body),credentials=auth(request);
      try{return await action(credentials,body);}catch(error){if(error instanceof AppError)throw error;throw new AppError('REPORTING_UNAVAILABLE','Reporting is temporarily unavailable; retain the signed request',503);}});
  }
  route('settings',z.strictObject({workspaceId:identifier}),(a,b)=>options.reporting.settings(a,b));
  route('settings/context',reportingReference,(a,b)=>options.reporting.settingsContext(a,b));
  route('settings/save',reportingSettingsPayload,(a,b)=>options.reporting.saveSettings(a,b));
  route('settings/status',reportingStatusRequest.refine(b=>b.kind==='settings'),(a,b)=>options.reporting.status(a,b));
  route('context',reportingContextRequest,(a,b)=>options.reporting.context(a,b));
  route('publish',reportingSummaryPayload,(a,b)=>options.reporting.publish(a,b));
  route('status',reportingStatusRequest.refine(b=>b.kind==='summary'),(a,b)=>options.reporting.status(a,b));
  route('read',reportingContextRequest,(a,b)=>options.reporting.read(a,b));
}
