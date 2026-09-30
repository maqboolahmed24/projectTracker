import { createHash,createHmac,randomBytes,randomUUID,timingSafeEqual } from 'node:crypto';
import { z } from 'zod';
import { unzipSync } from 'fflate';
import { DOMParser } from 'linkedom';
import { editorStart,editorSnapshot,type EditorOpened } from '../shared/file-editor.js';
import { FILE_MAX_PLAIN_BYTES,type FileEditorPermit } from '../shared/files.js';
import { base64urlDecode,base64urlEncode,canonicalJson,digestObject } from '../shared/crypto.js';
import { validateFileBytes } from '../client/file-formats.js';
import { LocalFileError } from './service.js';

const TTL=30*60*1000;
/** Do not let a local editor resolve automatic remote content from a private document. */
function assertLocalOfficeDocument(bytes:Uint8Array,filename:string){
 const ext=validateFileBytes(bytes,filename);if(!['docx','xlsx','pptx'].includes(ext))throw new LocalFileError('INVALID');
 const entries=unzipSync(bytes);try{for(const [path,value] of Object.entries(entries)){
  if(/(?:^|\/)(?:externalLinks|queryTables)\/|^xl\/connections\.xml$/i.test(path))throw new LocalFileError('INVALID');
  if(!path.endsWith('.rels'))continue;const xml=new TextDecoder().decode(value);
  if(/<!DOCTYPE|<!ENTITY/i.test(xml))throw new LocalFileError('INVALID');
  const document=new DOMParser().parseFromString(xml,'text/xml');
  for(const node of Array.from<{localName:string;getAttribute(name:string):string|null}>(document.querySelectorAll('*'))){if(node.localName.split(':').at(-1)!=='Relationship')continue;
   const mode=node.getAttribute('TargetMode'),type=node.getAttribute('Type')??'';
   if(mode?.toLowerCase()==='external'&&!type.endsWith('/hyperlink'))throw new LocalFileError('INVALID');
  }
 }}finally{for(const value of Object.values(entries))value.fill(0);}return ext;
}

type Lease={id:string;token:string;capability:string;key:string;filename:string;ext:string;input:Uint8Array;output:Uint8Array|null;
 expires:number;revision:number;saveId:string|null;state:'waiting'|'ready'|'unchanged'|'error';permit:FileEditorPermit};
export interface OfficeOptions {documentServer:string;callbackOrigin:string;publicOrigin:string;jwtSecret:string;
 verifyPermit:(permit:FileEditorPermit)=>Promise<void>;fetcher?:typeof fetch;now?:()=>number}
/** Temporary editing runs on the organisation's helper, never on the cloud API. */
export class LocalOffice {
 private starting=0;private readonly leases=new Map<string,Lease>();private readonly used=new Map<string,number>();private readonly fetcher:typeof fetch;
 private readonly now:()=>number;
 constructor(private readonly options:OfficeOptions){
  const url=new URL(options.documentServer),callback=new URL(options.callbackOrigin),publicUrl=new URL(options.publicOrigin);
  if(!['http:','https:'].includes(url.protocol)||url.origin!==options.documentServer||!['localhost','127.0.0.1'].includes(url.hostname)||
    !['localhost','127.0.0.1','host.docker.internal'].includes(callback.hostname)||callback.origin!==options.callbackOrigin||publicUrl.origin!==options.publicOrigin||options.jwtSecret.length<32)throw new Error('Invalid local editor configuration');
  this.fetcher=options.fetcher??fetch;this.now=options.now??Date.now;
 }
 private jwt(value:unknown){const header=Buffer.from('{"alg":"HS256","typ":"JWT"}').toString('base64url'),body=Buffer.from(JSON.stringify(value)).toString('base64url'),input=header+'.'+body;
  return input+'.'+createHmac('sha256',this.options.jwtSecret).update(input).digest('base64url');}
 private jwtPayload(token:string):Record<string,unknown>{
  try{if(token.length>65536)throw new Error();const [h,b,s,...rest]=token.split('.');if(!h||!b||!s||rest.length)throw new Error();
   const header=JSON.parse(Buffer.from(h,'base64url').toString());if(header.alg!=='HS256')throw new Error();
   const expected=createHmac('sha256',this.options.jwtSecret).update(h+'.'+b).digest(),actual=Buffer.from(s,'base64url');
   if(actual.length!==expected.length||!timingSafeEqual(actual,expected))throw new Error();
   const payload=z.record(z.string(),z.unknown()).parse(JSON.parse(Buffer.from(b,'base64url').toString()));
   if(typeof payload.exp==='number'&&payload.exp*1000<this.now()||typeof payload.nbf==='number'&&payload.nbf*1000>this.now()+30000)throw new Error();return payload;
  }catch{throw new LocalFileError('FORBIDDEN');}
 }
 sweep(){for(const [id,lease] of this.leases)if(lease.expires<=this.now()){lease.input.fill(0);lease.output?.fill(0);this.leases.delete(id);}for(const [id,expiry] of this.used)if(expiry<=this.now())this.used.delete(id);}
 async available(){try{const r=await this.fetcher(this.options.documentServer+'/healthcheck',{signal:AbortSignal.timeout(3000),redirect:'error'});return r.ok&&(await r.text()).trim()==='true';}catch{return false;}}
 async start(value:unknown):Promise<EditorOpened>{this.sweep();const input=editorStart.parse(value);await this.options.verifyPermit(input.permit);
  if(this.leases.size+this.starting>=2||this.used.has(input.permit.body.permitId)||this.used.size>=1024)throw new LocalFileError('CONFLICT');
  if(input.manifest.body.storage!=='managed'||input.permit.body.manifestDigest!==await digestObject(input.manifest)||input.permit.body.versionId!==input.manifest.body.versionId||
   input.permit.body.workspaceId!==input.manifest.body.binding.workspaceId||input.permit.body.projectId!==input.manifest.body.binding.projectId)throw new LocalFileError('FORBIDDEN');
  if(this.leases.size+this.starting>=2||this.used.has(input.permit.body.permitId)||this.used.size>=1024)throw new LocalFileError('CONFLICT');
  const bytes=base64urlDecode(input.bytes);let retained=false;this.starting++;this.used.set(input.permit.body.permitId,Date.parse(input.permit.body.expiresAt));
  try{const ext=assertLocalOfficeDocument(bytes,input.filename);
  if(!['docx','xlsx','pptx'].includes(ext)||bytes.length!==input.manifest.body.plainBytes||hash(bytes)!==input.sha256){bytes.fill(0);throw new LocalFileError('INVALID');}
  if(!await this.available()){bytes.fill(0);throw new LocalFileError('INTERRUPTED');}
  const lease:Lease={id:randomUUID(),token:randomBytes(32).toString('base64url'),capability:randomBytes(32).toString('base64url'),key:randomUUID(),filename:input.filename,ext,
   input:bytes,output:null,expires:this.now()+TTL,revision:0,saveId:null,state:'unchanged',permit:input.permit};
  this.leases.set(lease.id,lease);retained=true;
  const base=this.options.callbackOrigin+'/document/'+lease.id+'/'+lease.capability;
  const config={documentType:ext==='docx'?'word':ext==='xlsx'?'cell':'slide',type:'desktop',height:'100%',width:'100%',title:input.filename,
   document:{fileType:ext,key:lease.key,title:input.filename,url:base+'/source',permissions:{edit:true,download:false,print:false,comment:false,review:false,fillForms:false,copy:true}},
   editorConfig:{mode:'edit',lang:'en',callbackUrl:base+'/callback',user:{id:input.permit.body.accountId,name:'Maqbool member'},coEditing:{mode:'fast',change:false},
    customization:{autosave:true,forcesave:false,compactHeader:true,compactToolbar:true,hideRightMenu:true,hideRulers:true,chat:false,comments:false,help:false,feedback:false,plugins:false,macros:false,macrosMode:'Disable',uiTheme:input.theme==='dark'?'theme-dark':'theme-light'},plugins:{autostart:[],pluginsData:[]}}};
  return {leaseId:lease.id,token:lease.token,config:{...config,token:this.jwt(config)},expiresAt:new Date(lease.expires).toISOString()};
  }finally{this.starting--;if(!retained)bytes.fill(0);}
 }
 private current(id:string,token:string){this.sweep();const l=this.leases.get(id);if(!l||l.token!==token)throw new LocalFileError('FORBIDDEN');return l;}
 private document(id:string,capability:string){this.sweep();const l=this.leases.get(id);if(!l||l.capability!==capability)throw new LocalFileError('FORBIDDEN');return l;}
 source(id:string,capability:string){const l=this.document(id,capability);return {bytes:l.input,filename:l.filename};}
 async callback(id:string,capability:string,value:unknown,authorization?:string){const l=this.document(id,capability),body=z.record(z.string(),z.unknown()).parse(value),token=typeof body.token==='string'?body.token:authorization?.replace(/^Bearer /,'');
  if(!token)throw new LocalFileError('FORBIDDEN');const decoded=this.jwtPayload(token),payload=z.record(z.string(),z.unknown()).parse(decoded.payload??decoded);
  for(const key of ['key','status','url','userdata'])if(canonicalJson(payload[key]??null)!==canonicalJson(body[key]??null))throw new LocalFileError('FORBIDDEN');
  if(body.key!==l.key||!Number.isInteger(body.status))throw new LocalFileError('INVALID');
  if(body.status===3||body.status===7){l.state='error';return {error:0};}
  if(body.status!==2&&body.status!==6)return {error:0};
  if(typeof body.url!=='string'||body.filetype!==undefined&&body.filetype!==l.ext)throw new LocalFileError('INVALID');
  // Save replies may arrive out of order; only the currently requested snapshot
  // can fulfil the explicit Save action. Toolbar saves are held as recovery data.
  const url=new URL(body.url),doc=new URL(this.options.documentServer),pub=new URL(this.options.publicOrigin);
  if(url.username||url.password||url.hash||!((url.origin===doc.origin&&url.pathname.startsWith('/cache/'))||(url.origin===pub.origin&&url.pathname.startsWith('/office/cache/'))))throw new LocalFileError('FORBIDDEN');
  const path=url.origin===pub.origin?url.pathname.slice('/office'.length):url.pathname;
  const response=await this.fetcher(doc.origin+path+url.search,{signal:AbortSignal.timeout(30000),redirect:'error'});
  if(!response.ok||!response.body||Number(response.headers.get('content-length')??0)>FILE_MAX_PLAIN_BYTES)throw new LocalFileError('INVALID');
  const chunks:Uint8Array[]=[];let size=0;const reader=response.body.getReader();try{while(true){const r=await reader.read();if(r.done)break;size+=r.value.length;if(size>FILE_MAX_PLAIN_BYTES)throw new LocalFileError('INVALID');chunks.push(r.value);}}finally{await reader.cancel().catch(()=>{});}
  const bytes=new Uint8Array(size);let at=0;for(const c of chunks){bytes.set(c,at);at+=c.length;c.fill(0);}try{assertLocalOfficeDocument(bytes,l.filename);this.document(id,capability);}catch(error){bytes.fill(0);throw error;}
  l.output?.fill(0);l.output=bytes;l.revision++;if(body.userdata===l.saveId||body.status===2)l.state='ready';return {error:0};
 }
 async forceSave(id:string,token:string){const l=this.current(id,token);l.saveId=randomUUID();l.state='waiting';
  const command={c:'forcesave',key:l.key,userdata:l.saveId},response=await this.fetcher(this.options.documentServer+'/command',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({token:this.jwt(command)}),signal:AbortSignal.timeout(15000),redirect:'error'});
  const result=z.object({error:z.number()}).parse(await response.json());if(!response.ok||![0,4].includes(result.error)){l.state='error';throw new LocalFileError('INTERRUPTED');}
  if(result.error===4)l.state=l.output?'ready':'unchanged';return this.snapshot(id,token);
 }
 snapshot(id:string,token:string){const l=this.current(id,token),bytes=l.state==='ready'?l.output:null;
  return editorSnapshot.parse({leaseId:id,state:l.state,revision:l.revision,filename:l.filename,sha256:bytes?hash(bytes):null,bytes:bytes?base64urlEncode(bytes):null});}
 close(id:string,token:string){const l=this.current(id,token);l.input.fill(0);l.output?.fill(0);this.leases.delete(id);return {closed:true as const};}
 clear(){for(const l of this.leases.values()){l.input.fill(0);l.output?.fill(0);}this.leases.clear();}
}
const hash=(bytes:Uint8Array)=>createHash('sha256').update(bytes).digest('hex');
