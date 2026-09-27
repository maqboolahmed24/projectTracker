/** Same-origin streaming transport only. Private content is never decrypted here. */
import { PLANNING_MAX_BYTES } from '../../../../src/shared/planning-api.js';
import { UPGRADE_MAX_CONTEXT_BYTES } from '../../../../src/shared/upgrade-api.js';
import { RESTORE_MAX_BYTES } from '../../../../src/shared/restoration.js';
export const runtime='nodejs';
export const dynamic='force-dynamic';
// Preserve the backend's larger signed planning/update payloads. The API still
// enforces its own per-route limits and strict request schemas.
function bodyLimit(path:string){
  if(path.startsWith('/v1/upgrades/'))return UPGRADE_MAX_CONTEXT_BYTES;
  if(path.startsWith('/v1/work/planning/'))return PLANNING_MAX_BYTES;
  if(path.startsWith('/v1/restoration/'))return RESTORE_MAX_BYTES;
  if(path.startsWith('/v1/reporting/'))return 2*1024*1024;
  return 1024*1024;
}
async function proxy(request:Request){
  const url=new URL(request.url),origin=process.env.UKDA_API_ORIGIN??'http://127.0.0.1:3400';
  const maxBody=bodyLimit(url.pathname);
  const headers=new Headers();
  for(const name of ['accept','content-type','authorization','cookie','origin','x-csrf-token','sec-fetch-site','last-event-id','if-none-match']){const value=request.headers.get(name);if(value)headers.set(name,value);}
  let body:Uint8Array|undefined;
  if(!['GET','HEAD'].includes(request.method)){
    if(Number(request.headers.get('content-length')??0)>maxBody)return new Response(null,{status:413});
    const reader=request.body?.getReader();if(reader){const chunks:Uint8Array[]=[];let size=0;for(;;){const part=await reader.read();if(part.done)break;size+=part.value.length;if(size>maxBody){await reader.cancel();return new Response(null,{status:413});}chunks.push(part.value);}body=new Uint8Array(size);let at=0;for(const chunk of chunks){body.set(chunk,at);at+=chunk.length;}}
  }
  try{
    const response=await fetch(new URL(url.pathname+url.search,origin),{method:request.method,headers,...(body?{body:body as BodyInit}:{}),cache:'no-store',redirect:'manual',signal:request.signal});
    const outgoing=new Headers();for(const name of ['content-type','cache-control','etag','x-request-id','retry-after']){const value=response.headers.get(name);if(value)outgoing.set(name,value);}
    for(const cookie of response.headers.getSetCookie())outgoing.append('set-cookie',cookie);
    outgoing.set('X-Content-Type-Options','nosniff');outgoing.set('Referrer-Policy','no-referrer');
    return new Response(response.body,{status:response.status,headers:outgoing});
  }catch{return Response.json({error:{code:'SERVICE_UNAVAILABLE',message:'Please try again shortly.'}},{status:503,headers:{'Cache-Control':'no-store'}});}
}
export const GET=proxy,POST=proxy,PUT=proxy,PATCH=proxy,DELETE=proxy,HEAD=proxy;
