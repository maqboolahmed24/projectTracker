import type { FastifyInstance,FastifyRequest } from 'fastify';
import type { z } from 'zod';
import { AppError } from '../../errors.js';
import { parseInput } from '../../http.js';
import { binary } from '../../shared/contracts.js';
import { FILE_MAX_REQUEST_BYTES } from '../../shared/files.js';
import { evidenceContextRequest,evidenceSubmitRequest,evidenceReviewRequest,evidenceSharedRequest,evidenceRevokeRequest,evidenceStatusRequest } from '../../shared/file-evidence.js';
import type { RequestBudgets } from '../identity/budgets.js';
import { readSessionCookie } from '../identity/sessions.js';
import type { FileEvidenceService } from './evidence-service.js';
export function registerFileEvidenceRoutes(app:FastifyInstance,input:{origin:string;evidence:FileEvidenceService;budgets:Pick<RequestBudgets,'take'>}) {
 function auth(request:FastifyRequest){const csrf=request.headers['x-csrf-token'],cookie=readSessionCookie(request.headers.cookie);
  if(typeof csrf!=='string'||!binary(32).safeParse(csrf).success)throw new AppError('CSRF_REJECTED','Request verification failed',403);
  if(!cookie)throw new AppError('AUTH_REQUIRED','Authentication required',401);return {cookie,csrf};}
 function route<T>(path:string,schema:z.ZodType<T>,action:(body:T,a:{cookie:string;csrf:string})=>Promise<unknown>){
  app.post(`/v1/files/evidence/${path}`,{bodyLimit:FILE_MAX_REQUEST_BYTES,preHandler:async(request,reply)=>{
   reply.header('cache-control','no-store');if(request.headers.origin!==input.origin||request.headers['sec-fetch-site']==='cross-site')throw new AppError('ORIGIN_REJECTED','Request origin is not allowed',403);
   if(Object.keys(request.query as object).length)throw new AppError('INVALID_REQUEST','Invalid request',400);
   await input.budgets.take([{purpose:'file-evidence-source',key:request.ip,limit:12000,windowMs:600000}]);
  }},async request=>{const body=parseInput(schema,request.body),credentials=auth(request);return action(body,credentials);});
 }
 route('context',evidenceContextRequest,(b,a)=>input.evidence.context(a.cookie,a.csrf,b));
 route('submit',evidenceSubmitRequest,(b,a)=>input.evidence.submit(a.cookie,a.csrf,b));
 route('review',evidenceReviewRequest,(b,a)=>input.evidence.review(a.cookie,a.csrf,b));
 route('approve-shared',evidenceSharedRequest,(b,a)=>input.evidence.approveShared(a.cookie,a.csrf,b));
 route('revoke',evidenceRevokeRequest,(b,a)=>input.evidence.revoke(a.cookie,a.csrf,b));
 route('status',evidenceStatusRequest,(b,a)=>input.evidence.status(a.cookie,a.csrf,b));
}
