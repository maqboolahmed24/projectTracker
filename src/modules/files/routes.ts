import type { FastifyInstance, FastifyRequest } from 'fastify';
import { z } from 'zod';
import { AppError } from '../../errors.js';
import { parseInput } from '../../http.js';
import { binary } from '../../shared/contracts.js';
import { fileBeginRequest,fileCancelRequest,fileChunkRequest,fileLinkRequest,fileListRequest,fileReadChunkRequest,fileReference,
 fileStatusRequest,fileVersionRequest,fileVersionsRequest,fileEditorPermitRequest,FILE_MAX_REQUEST_BYTES } from '../../shared/files.js';
import type { RequestBudgets } from '../identity/budgets.js';
import { readSessionCookie } from '../identity/sessions.js';
import type { FilesService } from './service.js';
export function filesAccountBudget(budgets:Pick<RequestBudgets,'take'>) {
 return ({workspaceId,accountId}:{workspaceId:string;accountId:string})=>budgets.take([{purpose:'files-account',key:`${workspaceId}:${accountId}`,limit:24000,windowMs:600000}]);
}
export function registerFilesRoutes(app:FastifyInstance,input:{origin:string;files:FilesService;budgets:Pick<RequestBudgets,'take'>}) {
 function auth(request:FastifyRequest) {const csrf=request.headers['x-csrf-token'];
  if(typeof csrf!=='string'||!binary(32).safeParse(csrf).success)throw new AppError('CSRF_REJECTED','Request verification failed',403);
  const cookie=readSessionCookie(request.headers.cookie);if(!cookie)throw new AppError('AUTH_REQUIRED','Authentication required',401);return {cookie,csrf};}
 function route<T>(path:string,schema:z.ZodType<T>,action:(body:T,a:{cookie:string;csrf:string})=>Promise<unknown>) {
  app.post(`/v1/files/${path}`,{bodyLimit:FILE_MAX_REQUEST_BYTES,preHandler:async(request,reply)=>{
   reply.header('cache-control','no-store');
   if(request.headers.origin!==input.origin||request.headers['sec-fetch-site']==='cross-site')throw new AppError('ORIGIN_REJECTED','Request origin is not allowed',403);
   if(Object.keys(request.query as object).length)throw new AppError('INVALID_REQUEST','Invalid request',400);
   await input.budgets.take([{purpose:'files-source',key:request.ip,limit:30000,windowMs:600000}]);
  }},async request=>{
   const body=parseInput(schema,request.body),credentials=auth(request);
   const fields=body as {workspaceId?:string;manifest?:{body:{binding:{workspaceId:string}}};mutation?:{body:{binding:{workspaceId:string}}}},workspaceId=fields.workspaceId??fields.manifest?.body.binding.workspaceId??fields.mutation?.body.binding.workspaceId;
   if(workspaceId)await input.budgets.take([{purpose:'files-workspace',key:workspaceId,limit:60000,windowMs:600000}]);
   try{return await action(body,credentials);}catch(error){if(error instanceof AppError)throw error;throw new AppError('FILES_UNAVAILABLE','Files are temporarily unavailable; retain your upload',503);}
  });
 }
 route('context',fileReference,(b,a)=>input.files.context(a.cookie,a.csrf,b));
 route('begin',fileBeginRequest,(b,a)=>input.files.begin(a.cookie,a.csrf,b));
 route('chunk',fileChunkRequest,(b,a)=>input.files.chunk(a.cookie,a.csrf,b));
 route('complete',fileVersionRequest,(b,a)=>input.files.complete(a.cookie,a.csrf,b));
 route('cancel',fileCancelRequest,(b,a)=>input.files.cancel(a.cookie,a.csrf,b));
 route('link',fileLinkRequest,(b,a)=>input.files.link(a.cookie,a.csrf,b));
 route('list',fileListRequest,(b,a)=>input.files.list(a.cookie,a.csrf,b));
 route('versions',fileVersionsRequest,(b,a)=>input.files.versions(a.cookie,a.csrf,b));
 route('version',fileVersionRequest,(b,a)=>input.files.version(a.cookie,a.csrf,b));
 route('read-chunk',fileReadChunkRequest,(b,a)=>input.files.readChunk(a.cookie,a.csrf,b));
 route('status',fileStatusRequest,(b,a)=>input.files.status(a.cookie,a.csrf,b));
 route('editor-services',fileReference,(b,a)=>input.files.editorServices(a.cookie,a.csrf,b));
 route('editor-permit',fileEditorPermitRequest,(b,a)=>input.files.editorPermit(a.cookie,a.csrf,b));
}
