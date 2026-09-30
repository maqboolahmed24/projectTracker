import { createServer as httpServer,Agent as HttpAgent,type IncomingMessage,type ServerResponse } from 'node:http';
import { createServer as httpsServer } from 'node:https';
import { createProxyMiddleware } from 'http-proxy-middleware';
import { z } from 'zod';
import { Socket } from 'node:net';
import { LocalFileError,LocalFilesService } from './service.js';
import { LocalOffice } from './office.js';
import { editorLeaseReference } from '../shared/file-editor.js';
import { localBatchRequest } from '../shared/local-files.js';

export interface LocalHttpOptions {service:LocalFilesService;origin:string;publicOrigin:string;office?:LocalOffice;documentServer?:string;
 tls?:{key:Buffer;cert:Buffer};host?:string;port?:number;internalPort?:number}
const json=(res:ServerResponse,status:number,value:unknown)=>{res.writeHead(status,{'content-type':'application/json','cache-control':'no-store','x-content-type-options':'nosniff'});res.end(JSON.stringify(value));};
const escape=(value:string)=>value.replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]!));
async function body(req:IncomingMessage,limit=36*1024*1024):Promise<unknown>{const parts:Buffer[]=[];let size=0;for await(const chunk of req){const b=Buffer.from(chunk);size+=b.length;if(size>limit)throw new LocalFileError('INVALID');parts.push(b);}return JSON.parse(Buffer.concat(parts).toString('utf8'));}
const bearer=(req:IncomingMessage)=>req.headers.authorization?.startsWith('Bearer ')?req.headers.authorization.slice(7):'';
function fail(res:ServerResponse,error:unknown){if(res.headersSent){res.destroy();return;}const code=error instanceof LocalFileError?error.code:(error as NodeJS.ErrnoException).code==='ENOSPC'?'DISK_FULL':(error as NodeJS.ErrnoException).code==='EEXIST'?'CONFLICT':'INVALID';json(res,code==='FORBIDDEN'?403:code==='CONFLICT'?409:400,{code});}

export async function startLocalHttp(options:LocalHttpOptions){
 const publicUrl=new URL(options.publicOrigin),origin=new URL(options.origin).origin,port=options.port??Number(publicUrl.port||443),host=options.host??'127.0.0.1';
 if(origin!==options.origin||publicUrl.origin!==options.publicOrigin||!['localhost','127.0.0.1'].includes(publicUrl.hostname)||!['127.0.0.1','::1'].includes(host)||
   (publicUrl.protocol==='https:')!==Boolean(options.tls))throw new Error('Invalid local listener');
 const sockets=new Set<Socket>(),proxyAgent=new HttpAgent({keepAlive:false});const track=(socket:Socket)=>{sockets.add(socket);socket.on('close',()=>sockets.delete(socket));};
 const proxy=options.documentServer?createProxyMiddleware({target:options.documentServer,changeOrigin:true,ws:true,agent:proxyAgent,pathRewrite:{'^/office':''},
  on:{proxyReq:(request)=>{if(request.socket)track(request.socket);request.on('socket',track);request.setHeader('X-Forwarded-Host',publicUrl.host+'/office');request.setHeader('X-Forwarded-Proto',publicUrl.protocol.slice(0,-1));},
   proxyReqWs:(request)=>{if(request.socket)track(request.socket);request.on('socket',track);request.setHeader('X-Forwarded-Host',publicUrl.host+'/office');request.setHeader('X-Forwarded-Proto',publicUrl.protocol.slice(0,-1));},
   error:(_error,_request,response)=>{if('writeHead' in response){response.writeHead(502);response.end();}}}}):undefined;
 const allowedProxy=(path:string)=>/^\/office\/(?:[a-zA-Z0-9_.-]+\/)?(?:(?:web-apps|sdkjs|fonts|cache|doc|spellchecker|coauthoring)\/|themes\.json$)/.test(path);
 let count=0,window=Date.now();
 const handle=async(req:IncomingMessage,res:ServerResponse)=>{try{
  if(Date.now()-window>60000){count=0;window=Date.now();}if(++count>1200){json(res,429,{code:'BUSY'});return;}
  if(req.headers.host!==publicUrl.host)throw new LocalFileError('FORBIDDEN');
  const url=new URL(req.url??'/',options.publicOrigin),requestOrigin=req.headers.origin;
  if(url.pathname.startsWith('/office/')&&proxy){
   const referer=req.headers.referer?new URL(req.headers.referer).origin:undefined;
   if(!allowedProxy(url.pathname)||requestOrigin&&![origin,publicUrl.origin].includes(requestOrigin)||referer&&![origin,publicUrl.origin].includes(referer))throw new LocalFileError('FORBIDDEN');
   proxy(req,res);return;
  }
  if(req.method==='GET'&&url.pathname==='/'&&!url.search){
   if(requestOrigin&&requestOrigin!==publicUrl.origin)throw new LocalFileError('FORBIDDEN');
   res.writeHead(200,{'content-type':'text/html; charset=utf-8','cache-control':'no-store','content-security-policy':"default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",'x-content-type-options':'nosniff','referrer-policy':'no-referrer'});
   res.end(`<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Maqbool shared folder</title><style>body{font:17px system-ui;background:#101113;color:#f1f3f2;margin:0;display:grid;place-items:center;min-height:100vh}main{max-width:520px;padding:40px}h1{font-size:30px}p{line-height:1.6;color:#a9b1ad}code{display:block;padding:20px;background:#202326;border-radius:12px;overflow-wrap:anywhere;color:#eef6f2}small{color:#a9b1ad}</style><main><h1>Your shared folder is ready</h1><p>In Maqbool, choose Connect shared folder and enter this code.</p><code>${escape(options.service.setupCode())}</code><p>Folder: <strong>${escape(options.service.rootLabel)}</strong></p><small>This code changes after a successful connection. Keep this helper open while you publish or edit.</small></main></html>`);return;
  }
  if(requestOrigin!==origin)throw new LocalFileError('FORBIDDEN');
  res.setHeader('Access-Control-Allow-Origin',origin);res.setHeader('Vary','Origin');res.setHeader('Access-Control-Allow-Private-Network','true');
  if(req.method==='OPTIONS'){res.setHeader('Access-Control-Allow-Methods','POST');res.setHeader('Access-Control-Allow-Headers','content-type,authorization');res.setHeader('Access-Control-Max-Age','300');res.writeHead(204);res.end();return;}
  if(req.method!=='POST'||url.search||req.headers['content-type']?.split(';')[0]!=='application/json')throw new LocalFileError('INVALID');
  const input=await body(req),token=bearer(req);let result:unknown;
  switch(url.pathname){
   case '/status':z.strictObject({}).parse(input);result=options.service.status(await options.office?.available());break;
   case '/pair':result=await options.service.pair(input);break;
   case '/apply':result=await options.service.apply(token,input);break;
   case '/progress':result=await options.service.progress(token,localBatchRequest.parse(input).batchId);break;
   case '/finish':{const v=localBatchRequest.extend({itemCount:z.number().int().min(1).max(64)}).parse(input);result=await options.service.finish(token,v.batchId,v.itemCount);break;}
   case '/editor/open':if(!options.office)throw new LocalFileError('INTERRUPTED');result=await options.office.start(input);break;
   case '/editor/save':if(!options.office)throw new LocalFileError('INTERRUPTED');result=await options.office.forceSave(editorLeaseReference.parse(input).leaseId,token);break;
   case '/editor/snapshot':if(!options.office)throw new LocalFileError('INTERRUPTED');result=options.office.snapshot(editorLeaseReference.parse(input).leaseId,token);break;
   case '/editor/close':if(!options.office)throw new LocalFileError('INTERRUPTED');result=options.office.close(editorLeaseReference.parse(input).leaseId,token);break;
   default:throw new LocalFileError('INVALID');
  }json(res,200,result);
 }catch(error){fail(res,error);}};
 const server=options.tls?httpsServer(options.tls,(req,res)=>void handle(req,res)):httpServer((req,res)=>void handle(req,res));
 server.on('connection',track);
 server.requestTimeout=45000;server.headersTimeout=15000;server.on('upgrade',(req,socket,head)=>{if(!(socket instanceof Socket)||!proxy||req.headers.host!==publicUrl.host||req.headers.origin!==publicUrl.origin||!allowedProxy(new URL(req.url??'/',publicUrl).pathname)){socket.destroy();return;}proxy.upgrade!(req,socket,head);});
 await new Promise<void>((resolve,reject)=>{server.once('error',reject);server.listen(port,host,()=>resolve());});
 const internal=options.office?httpServer((req,res)=>void (async()=>{try{
  const match=/^\/document\/([a-f0-9-]{36})\/([A-Za-z0-9_-]{43})\/(source|callback)$/.exec(req.url??'');
  if(!match)throw new LocalFileError('FORBIDDEN');
  if(req.method==='GET'&&match[3]==='source'){const file=options.office!.source(match[1]!,match[2]!);res.writeHead(200,{'content-type':'application/octet-stream','content-length':file.bytes.length,'cache-control':'no-store'});res.end(file.bytes);return;}
  if(req.method==='POST'&&match[3]==='callback'){json(res,200,await options.office!.callback(match[1]!,match[2]!,await body(req,128*1024),req.headers.authorization));return;}
  throw new LocalFileError('INVALID');
 }catch(error){fail(res,error);}})()):undefined;
 if(internal)await new Promise<void>((resolve,reject)=>{internal.once('error',reject);internal.listen(options.internalPort??3412,'127.0.0.1',()=>resolve());});
 const sweep=setInterval(()=>options.office?.sweep(),60000);sweep.unref();
 return {server,internal,async close(){clearInterval(sweep);options.office?.clear();proxyAgent.destroy();for(const socket of sockets)socket.destroy();server.closeAllConnections();internal?.closeAllConnections();await Promise.all([new Promise<void>(r=>server.close(()=>r())),internal?new Promise<void>(r=>internal.close(()=>r())):Promise.resolve()]);}};
}
