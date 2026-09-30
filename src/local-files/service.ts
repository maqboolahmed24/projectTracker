import { createHash,generateKeyPairSync,randomBytes,randomUUID,sign as nodeSign } from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import { chmod,lstat,mkdir,open,readFile,realpath,rename,statfs } from 'node:fs/promises';
import { basename,dirname,isAbsolute,relative,resolve,sep } from 'node:path';
import sodium from 'libsodium-wrappers';
import { z } from 'zod';
import { base64urlDecode,base64urlEncode,canonicalJson,digestObject,verifyObject } from '../shared/crypto.js';
import { deliveryMetadataContext,publicationReceipt,type DeliveryPermit,type PublicationReceipt } from '../shared/file-delivery.js';
import { localRelativePath,deliveryDetails,localApplyRequest,localPairRequest,localOperationResult,localProgress,type DeliveryDetails } from '../shared/local-files.js';
import { RootIO } from './root-io.js';
import { fileEditorPermit,type FileEditorPermit } from '../shared/files.js';
import { parseJsonStrict } from '../shared/json.js';

const utf8=new TextEncoder();
export class LocalFileError extends Error {constructor(readonly code:'INVALID'|'FORBIDDEN'|'CONFLICT'|'EXPIRED'|'DISK_FULL'|'INTERRUPTED'){super(code);}}
function failure(code:LocalFileError['code']):never {throw new LocalFileError(code);}
interface Options {root:string;stateDirectory:string;origin:string;trustedServiceKeys:Record<string,string>;
  now?:()=>Date;hook?:(stage:string,index:number)=>Promise<void>}
type Result=z.infer<typeof localOperationResult>;
type JournalEntry={index:number;stage:'prepared'|'backed_up'|'installed'|'verified';permitId:string;destination:string;fromPath:string|null;
  operation:'add'|'replace'|'move'|'rename'|'remove';expectedOldSha256:string|null;sha256:string;backup:string;temporary:string;completedAt:string|null};
type Journal={version:1;batchId:string;frozenDigest:string;workspaceId:string;projectId:string;itemCount:number;startedAt:string;
  entries:JournalEntry[];receipt:PublicationReceipt|null};
const journalSchema=z.strictObject({version:z.literal(1),batchId:z.string().uuid(),frozenDigest:z.string().regex(/^[0-9a-f]{64}$/),workspaceId:z.string().uuid(),projectId:z.string().uuid(),itemCount:z.number().int().min(1).max(64),startedAt:z.iso.datetime(),receipt:publicationReceipt.nullable(),entries:z.array(z.strictObject({index:z.number().int().min(0).max(63),stage:z.enum(['prepared','backed_up','installed','verified']),permitId:z.string().uuid(),destination:localRelativePath,fromPath:localRelativePath.nullable(),operation:z.enum(['add','replace','move','rename','remove']),expectedOldSha256:z.string().regex(/^[0-9a-f]{64}$/).nullable(),sha256:z.string().regex(/^[0-9a-f]{64}$/),backup:z.string(),temporary:z.string(),completedAt:z.iso.datetime().nullable()})).max(64).refine(v=>new Set(v.map(e=>e.index)).size===v.length)});
const keyRecord=z.strictObject({serviceId:z.string().uuid(),publicKey:z.string(),privateKey:z.string(),root:z.string()});
const grants=z.record(z.string(),z.strictObject({workspaceId:z.string().uuid(),projectId:z.string().uuid(),token:z.string(),ownerPublicKey:z.string()}));
/** Organisation-owned helper. It never receives a workspace/project content key. */
export class LocalFilesService {
  readonly serviceId:string;readonly publicKey:string;readonly root:string;readonly rootLabel:string;
  private readonly privateKey:string;private readonly journalRoot:string;private readonly locks=new Set<string>();
  private pairCode=base64urlEncode(randomBytes(18));private readonly connected:Record<string,z.infer<typeof grants>[string]>;
  private readonly now:()=>Date;
  private constructor(private readonly options:Options,root:string,key:z.infer<typeof keyRecord>,connections:z.infer<typeof grants>,private readonly io:RootIO){
    this.root=root;this.rootLabel=basename(root);this.journalRoot=resolve(root,'.maqbool-delivery');this.serviceId=key.serviceId;this.publicKey=key.publicKey;
    this.privateKey=key.privateKey;this.connected=connections;this.now=options.now??(()=>new Date());
  }
  static async open(options:Options):Promise<LocalFilesService>{
    const root=await realpath(options.root),info=await lstat(options.root);if(!info.isDirectory()||info.isSymbolicLink()||root===sep||dirname(root)===sep)failure('INVALID');
    const origin=new URL(options.origin);if(origin.origin!==options.origin||origin.username||origin.password||
      (origin.protocol!=='https:'&&!(origin.protocol==='http:'&&['localhost','127.0.0.1'].includes(origin.hostname))))failure('INVALID');
    if(Object.keys(options.trustedServiceKeys).length<1)failure('INVALID');
    await mkdir(options.stateDirectory,{recursive:true,mode:0o700});await chmod(options.stateDirectory,0o700);
    const state=await realpath(options.stateDirectory);if((await lstat(options.stateDirectory)).isSymbolicLink())failure('INVALID');
    let key:z.infer<typeof keyRecord>;
    try{key=keyRecord.parse(parseJsonStrict(await readFile(resolve(state,'identity.json'),'utf8')));if(key.root!==root)failure('CONFLICT');}
    catch(error){if((error as NodeJS.ErrnoException).code!=='ENOENT')throw error;const keys=generateKeyPairSync('ed25519');
      key={serviceId:randomUUID(),publicKey:keys.publicKey.export({type:'spki',format:'der'}).subarray(-32).toString('base64url'),
        privateKey:keys.privateKey.export({type:'pkcs8',format:'pem'}).toString(),root};await durableJson(resolve(state,'identity.json'),key);}
    let connections:z.infer<typeof grants>={};try{connections=grants.parse(parseJsonStrict(await readFile(resolve(state,'connections.json'),'utf8')));}catch(error){if((error as NodeJS.ErrnoException).code!=='ENOENT')throw error;}
    const io=await RootIO.open(root);await io.mkdir(resolve(root,'.maqbool-delivery'));
    return new LocalFilesService({...options,stateDirectory:state},root,key,connections,io);
  }
  status(officeAvailable=false){return {version:1 as const,serviceId:this.serviceId,publicKey:this.publicKey,rootLabel:this.rootLabel,officeAvailable};}
  /** Only the local setup page displays this one-time code. Never put it in logs/URLs. */
  setupCode(){return this.pairCode;}
  private signature<T extends {purpose:string}>(body:T){return {body:structuredClone(body),signature:nodeSign(null,Buffer.from(canonicalJson(body)),this.privateKey).toString('base64url')};}
  async pair(value:unknown){const input=localPairRequest.parse(value),b=input.approval.body.binding;
    if(input.code!==this.pairCode||input.approval.body.serviceId!==this.serviceId||input.approval.body.publicKey!==this.publicKey||b.origin!==this.options.origin||
      Date.parse(b.expiresAt)<=this.now().getTime()||!await verifyObject(input.approval,base64urlDecode(b.signingPublicKey,32),'ukda.file-service-pair.v1'))failure('FORBIDDEN');
    const token=base64urlEncode(randomBytes(32)),key=`${b.workspaceId}:${b.projectId}`;
    this.connected[key]={workspaceId:b.workspaceId,projectId:b.projectId,token,ownerPublicKey:b.signingPublicKey};
    await durableJson(resolve(this.options.stateDirectory,'connections.json'),this.connected);this.pairCode=base64urlEncode(randomBytes(18));
    return {serviceId:this.serviceId,token,proof:this.signature(input.approval.body).signature};
  }
  authorise(token:string,workspaceId?:string,projectId?:string){const match=Object.values(this.connected).find(g=>g.token===token);
    if(!match||(workspaceId&&match.workspaceId!==workspaceId)||(projectId&&match.projectId!==projectId))failure('FORBIDDEN');return match;}
  async verifyEditorPermit(value:FileEditorPermit){const permit=fileEditorPermit.parse(value),b=permit.body,key=this.options.trustedServiceKeys[b.keyId],now=this.now().getTime();
    if(b.serviceId!==this.serviceId||b.origin!==this.options.origin||!this.connected[`${b.workspaceId}:${b.projectId}`]||!key||!await verifyObject(permit,base64urlDecode(key,32),'ukda.file-edit-permit.v1'))failure('FORBIDDEN');
    if(Date.parse(b.issuedAt)>now+30000||Date.parse(b.expiresAt)<=now||Date.parse(b.expiresAt)-Date.parse(b.issuedAt)>30000)failure('EXPIRED');
  }
  private async permit(permit:DeliveryPermit,live=true){const b=permit.body,key=this.options.trustedServiceKeys[b.keyId],now=this.now().getTime();
    if(b.serviceId!==this.serviceId||b.origin!==this.options.origin||!key||!await verifyObject(permit,base64urlDecode(key,32),'ukda.file-delivery-permit.v1'))failure('FORBIDDEN');
    if(live&&(Date.parse(b.issuedAt)>now+30000||Date.parse(b.expiresAt)<=now||Date.parse(b.expiresAt)-Date.parse(b.issuedAt)>30000))failure('EXPIRED');
  }
  private async path(name:string):Promise<string>{
    const accepted=(await import('../shared/local-files.js')).localRelativePath.parse(name),path=resolve(this.root,accepted),parts=accepted.split('/');
    let current=this.root;for(const part of parts.slice(0,-1)){current=resolve(current,part);let info;try{info=await lstat(current);}catch(error){if((error as NodeJS.ErrnoException).code==='ENOENT')failure('INVALID');throw error;}
      if(!info.isDirectory()||info.isSymbolicLink()||await realpath(current)!==current)failure('FORBIDDEN');}
    try{if((await lstat(path)).isSymbolicLink())failure('FORBIDDEN');}catch(error){if((error as NodeJS.ErrnoException).code!=='ENOENT')throw error;}return path;
  }
  private async externalPath(name:string){const rel=isAbsolute(name)?relative(this.root,resolve(name)):name;return this.path(rel);}
  private async journal(id:string):Promise<Journal|undefined>{if(!z.string().uuid().safeParse(id).success)failure('INVALID');
    try{const journal=journalSchema.parse(parseJsonStrict(await this.io.read(resolve(this.journalRoot,id,'journal.json'))));if(journal.batchId!==id)failure('CONFLICT');for(const e of journal.entries){if(e.backup!==resolve(this.journalRoot,id,`${e.index}.old`)||e.temporary!==resolve(this.journalRoot,id,`${e.index}.new`))failure('CONFLICT');}return journal;}catch(error){if((error as NodeJS.ErrnoException).code==='ENOENT')return;throw error;}}
  private async save(journal:Journal){await this.io.json(resolve(this.journalRoot,journal.batchId,'journal.json'),canonicalJson(journal));}
  async progress(token:string,batchId:string){const journal=await this.journal(batchId);if(!journal)failure('INVALID');this.authorise(token,journal.workspaceId,journal.projectId);
    const results=journal.entries.filter(e=>e.stage==='verified').map(e=>({index:e.index,state:'verified' as const,permitId:e.permitId,sha256:e.operation==='remove'?null:e.sha256,completedAt:e.completedAt!}));
    return localProgress.parse({batchId,frozenDigest:journal.frozenDigest,complete:journal.receipt!==null,results,receipt:journal.receipt});}
  async apply(token:string,value:unknown):Promise<Result>{const request=localApplyRequest.parse(value),body=request.batch.body,permit=request.permit;
    this.authorise(token,body.binding.workspaceId,body.binding.projectId);await this.permit(permit);
    const frozenDigest=await digestObject(request.batch),item=body.items[permit.body.index];
    if(!item||permit.body.batchId!==body.batchId||permit.body.workspaceId!==body.binding.workspaceId||permit.body.projectId!==body.binding.projectId||
      permit.body.dataGeneration!==body.binding.dataGeneration||permit.body.frozenDigest!==frozenDigest||permit.body.itemDigest!==await digestObject(item))failure('FORBIDDEN');
    const key=base64urlDecode(request.detailsKey,32);await sodium.ready;let details:DeliveryDetails;
    try{const raw=sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null,base64urlDecode(body.details.ciphertext),canonicalJson(deliveryMetadataContext(body,'details')),base64urlDecode(body.details.nonce,24),key);
      try{details=deliveryDetails.parse(parseJsonStrict(new TextDecoder('utf8',{fatal:true}).decode(raw)));}finally{raw.fill(0);}}
    catch{failure('INVALID');}finally{key.fill(0);}
    if(details.items.length!==body.items.length||details.rootLabel!==this.rootLabel)failure('CONFLICT');
    const spec=details.items[permit.body.index]!;if(new Set(details.items.map(d=>d.destination.normalize('NFD').toLowerCase())).size!==details.items.length)failure('INVALID');
    if(this.locks.size||this.locks.has(body.batchId))failure('CONFLICT');this.locks.add(body.batchId);
    try{return await this.applyLocked(request,spec,frozenDigest);}finally{this.locks.delete(body.batchId);}
  }
  private async applyLocked(request:z.infer<typeof localApplyRequest>,spec:DeliveryDetails['items'][number],frozenDigest:string):Promise<Result>{
    const b=request.batch.body,index=request.permit.body.index,item=b.items[index]!,directory=resolve(this.journalRoot,b.batchId);
    let journal=await this.journal(b.batchId);if(journal&&journal.frozenDigest!==frozenDigest)failure('CONFLICT');
    await this.io.mkdir(directory);
    journal??={version:1,batchId:b.batchId,frozenDigest,workspaceId:b.binding.workspaceId,projectId:b.binding.projectId,itemCount:b.items.length,startedAt:this.now().toISOString(),entries:[],receipt:null};
    const prior=journal.entries.find(e=>e.index===index),destination=await this.path(spec.destination),fromPath=spec.fromPath?await this.path(spec.fromPath):null;
    if(prior?.stage==='verified'){
      const actual=item.operation==='remove'?await this.io.hash(destination):await this.io.hash(destination);
      if(actual!==(item.operation==='remove'?null:spec.sha256)||fromPath&&['move','rename'].includes(item.operation)&&await this.io.hash(fromPath)!==null)failure('CONFLICT');
      return {index,state:'verified',permitId:prior.permitId,sha256:prior.operation==='remove'?null:prior.sha256,completedAt:prior.completedAt!};
    }
    const temporary=resolve(directory,`${index}.new`),backup=resolve(directory,`${index}.old`);
    let entry=prior;if(!entry){
      if(['move','rename'].includes(item.operation)&&(!fromPath||!spec.expectedOldSha256||fromPath===destination))failure('INVALID');
      if(['move','rename','remove'].includes(item.operation)&&spec.expectedOldSha256!==spec.sha256)failure('INVALID');
      if(item.operation==='add'&&spec.expectedOldSha256!==null||['replace','remove'].includes(item.operation)&&!spec.expectedOldSha256)failure('INVALID');
      const existing=await this.io.hash(['move','rename'].includes(item.operation)?fromPath!:destination);
      if(existing!==spec.expectedOldSha256)failure('CONFLICT');
      if(['move','rename'].includes(item.operation)&&await this.io.hash(destination)!==null)failure('CONFLICT');
      const disk=await statfs(this.root);if(Number(disk.bavail)*Number(disk.bsize)<spec.plainBytes*2+64*1024*1024)failure('DISK_FULL');
      if(['add','replace'].includes(item.operation)){
        const preparedHash=await this.io.hash(temporary);
        if(preparedHash!==null&&preparedHash!==spec.sha256)await this.io.capture(temporary,temporary+'.interrupted-'+randomUUID());
        if(preparedHash===spec.sha256){/* A fully written file survived before its journal entry. */}
        else if(request.bytes){const bytes=base64urlDecode(request.bytes);try{if(bytes.length!==spec.plainBytes||sha(bytes)!==spec.sha256)failure('CONFLICT');
          await this.io.write(temporary,request.bytes);}
          finally{bytes.fill(0);}}
        else {if(!spec.externalPath)failure('INVALID');const source=await this.externalPath(spec.externalPath);if(await this.io.hash(source)!==spec.sha256)failure('CONFLICT');
          await this.io.copy(source,temporary);if(await this.io.hash(temporary)!==spec.sha256)failure('CONFLICT');}
      }
      entry={index,stage:'prepared',permitId:request.permit.body.permitId,destination:spec.destination,fromPath:spec.fromPath??null,
        operation:item.operation,expectedOldSha256:spec.expectedOldSha256,sha256:spec.sha256,backup,temporary,completedAt:null};journal.entries.push(entry);await this.save(journal);await this.options.hook?.('prepared',index);
    }else if(entry.operation!==item.operation||entry.fromPath!==(spec.fromPath??null)||entry.destination!==spec.destination||entry.sha256!==spec.sha256||entry.expectedOldSha256!==spec.expectedOldSha256)failure('CONFLICT');
    await this.permit(request.permit);entry.permitId=request.permit.body.permitId;
    const oldPath=['move','rename'].includes(item.operation)?fromPath!:destination;
    // If a crash happened after moving the old file but before journalling it,
    // adopt that captured precondition only when both paths still agree.
    if(entry.stage==='prepared'&&await this.io.hash(backup)!==null){if(await this.io.hash(backup)!==spec.expectedOldSha256||await this.io.hash(oldPath)!==null)failure('CONFLICT');entry.stage='backed_up';await this.save(journal);}
    if(entry.stage==='prepared'&&item.operation!=='add'){
      if(await this.io.hash(oldPath)!==spec.expectedOldSha256)failure('CONFLICT');await this.path(['move','rename'].includes(item.operation)?spec.fromPath!:spec.destination);
      await this.io.capture(oldPath,backup);
      if(await this.io.hash(backup)!==spec.expectedOldSha256){if(await this.io.hash(oldPath)===null){await this.io.link(backup,oldPath);}failure('CONFLICT');}
      entry.stage='backed_up';await this.save(journal);await this.options.hook?.('backed_up',index);
    }
    if(entry.stage==='prepared'||entry.stage==='backed_up'){
      await this.permit(request.permit);await this.path(spec.destination);
      if(item.operation==='remove'){if(await this.io.hash(destination)!==null)failure('CONFLICT');}
      else{
        const source=['move','rename'].includes(item.operation)?backup:temporary,actual=await this.io.hash(destination);
        if(actual!==null&&actual!==spec.sha256)failure('CONFLICT');
        if(actual===null)try{await this.io.link(source,destination);}catch(error){if((error as NodeJS.ErrnoException).code==='EEXIST')failure('CONFLICT');throw error;}

      }
      entry.stage='installed';await this.save(journal);await this.options.hook?.('installed',index);
    }
    if((item.operation==='remove'?await this.io.hash(destination):await this.io.hash(destination))!==(item.operation==='remove'?null:spec.sha256))failure('CONFLICT');
    entry.stage='verified';entry.completedAt=this.now().toISOString();await this.save(journal);await this.options.hook?.('verified',index);
    return {index,state:'verified',permitId:entry.permitId,sha256:entry.operation==='remove'?null:entry.sha256,completedAt:entry.completedAt};
  }
  async finish(token:string,batchId:string,itemCount:number):Promise<PublicationReceipt>{const journal=await this.journal(batchId);if(!journal)failure('INVALID');
    this.authorise(token,journal.workspaceId,journal.projectId);if(journal.receipt)return publicationReceipt.parse(journal.receipt);
    if(itemCount!==journal.itemCount||itemCount<1||itemCount>64||journal.entries.length!==itemCount||journal.entries.some(e=>e.stage!=='verified')||new Set(journal.entries.map(e=>e.index)).size!==itemCount)failure('INTERRUPTED');
    for(const e of journal.entries){const path=await this.path(e.destination),actual=await this.io.hash(path);if(actual!==(e.operation==='remove'?null:e.sha256)||e.fromPath&&['move','rename'].includes(e.operation)&&await this.io.hash(await this.path(e.fromPath))!==null)failure('CONFLICT');}
    journal.receipt=this.signature({purpose:'ukda.local-file-publication.v1',serviceId:this.serviceId,workspaceId:journal.workspaceId,projectId:journal.projectId,
      batchId:journal.batchId,frozenDigest:journal.frozenDigest,permitIds:journal.entries.sort((a,b)=>a.index-b.index).map(e=>e.permitId),
      resultDigest:await digestObject(journal.entries.map(({index,destination,sha256,completedAt})=>({index,destination,sha256,completedAt}))),startedAt:journal.startedAt,completedAt:this.now().toISOString()});
    await this.save(journal);return publicationReceipt.parse(journal.receipt);
  }
}
async function durableJson(path:string,value:unknown){const temporary=path+'.'+randomUUID()+'.tmp',file=await open(temporary,fsConstants.O_WRONLY|fsConstants.O_CREAT|fsConstants.O_EXCL|fsConstants.O_NOFOLLOW,0o600);
  try{await file.writeFile(canonicalJson(value));await file.sync();}finally{await file.close();}await rename(temporary,path);await syncDirectory(dirname(path));}
async function syncDirectory(path:string){const file=await open(path,'r');try{await file.sync();}finally{await file.close();}}
const sha=(bytes:Uint8Array)=>createHash('sha256').update(bytes).digest('hex');
