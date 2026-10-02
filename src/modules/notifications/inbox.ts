import { randomUUID } from 'node:crypto';
import type pg from 'pg';
import { transaction,type Databases } from '../../db.js';
import { dataTransaction } from '../../persistence.js';
import { AppError } from '../../errors.js';
import { base64urlEncode,canonicalJson,digestObject } from '../../shared/crypto.js';
import { inboxBinding,inboxListRequest,inboxMutation,inboxReceipt,validateInboxMutation,type InboxBinding,type InboxReceipt } from '../../shared/inbox.js';
import { SessionService,type SessionPrincipal } from '../identity/sessions.js';
import { readCurrentDeviceProjectScopes } from '../work/planning.js';

const changed=()=>new AppError('INBOX_CHANGED','Inbox state changed; refresh before applying this change',409);
const missing=()=>new AppError('NOT_FOUND','Inbox item not available',404);
interface Options{databases:Databases;sessions:SessionService;origin:string;now?:()=>Date}
export class InboxService{
  constructor(private readonly options:Options){}
  private async withCurrent<T>(cookie:string,csrf:string,workspaceId:string,work:(app:pg.PoolClient,control:pg.PoolClient,p:SessionPrincipal,now:Date)=>Promise<T>):Promise<T>{
    const initial=await this.options.sessions.authenticate(cookie,{csrfToken:csrf,approved:true});
    if(initial.workspaceId!==workspaceId)throw missing();
    return dataTransaction(this.options.databases,initial,async app=>{
      await app.query("SELECT pg_advisory_xact_lock(hashtextextended('ukda.inbox:'||$1||':'||$2,0))",[workspaceId,initial.accountId]);
      return transaction(this.options.databases.control,async control=>{
        const now=this.options.now?.()??new Date(),p=await this.options.sessions.resolveCurrent(control,cookie,{csrfToken:csrf,approved:true},now);
        if(p.workspaceId!==workspaceId||p.accountId!==initial.accountId||p.deviceId!==initial.deviceId||p.securityHead!==initial.securityHead||p.dataGeneration!==initial.dataGeneration)throw changed();
        return work(app,control,p,now);
      });
    });
  }
  private async binding(control:pg.PoolClient,p:SessionPrincipal,operationId:string,issued:Date):Promise<InboxBinding>{
    const device=(await control.query("SELECT key_generation,signing_public_key FROM security.devices WHERE workspace_id=$1 AND device_id=$2 AND state='active'",[p.workspaceId,p.deviceId])).rows[0];
    if(!device)throw missing();
    return inboxBinding.parse({version:1,workspaceId:p.workspaceId,operationId,origin:this.options.origin,accountId:p.accountId,deviceId:p.deviceId,
      signingPublicKey:base64urlEncode(device.signing_public_key),keyGeneration:device.key_generation,credentialGeneration:p.credentialGeneration,
      sessionGeneration:p.sessionGeneration,dataGeneration:p.dataGeneration,securityHead:p.securityHead,securityVersion:p.securityVersion,
      issuedAt:issued.toISOString(),expiresAt:new Date(issued.getTime()+600000).toISOString()});
  }
  context(cookie:string,csrf:string,input:{workspaceId:string;operationId:string}){
    return this.withCurrent(cookie,csrf,input.workspaceId,async(_app,control,p,now)=>({binding:await this.binding(control,p,input.operationId,now)}));
  }
  private async projects(control:pg.PoolClient,p:SessionPrincipal,now:Date){return(await readCurrentDeviceProjectScopes(control,p,now)).filter(s=>s.scope==='project').map(s=>s.scopeId);}
  private publicNotice(row:Record<string,any>,projects:string[]){
    const available=!!row.event_type&&(!row.project_id||projects.includes(row.project_id));
    return{id:row.id,revision:row.revision,readAt:row.read_at?.toISOString()??null,createdAt:row.created_at.toISOString(),
      eventType:available?row.event_type:'content.unavailable',projectId:available?row.project_id:null,recordId:available?row.record_id:null,unavailable:!available};
  }
  list(cookie:string,csrf:string,input:unknown){
    const query=inboxListRequest.parse(input);
    return this.withCurrent(cookie,csrf,query.workspaceId,async(app,control,p,now)=>{
      const projects=await this.projects(control,p,now);
      const cursor=query.after?(await app.query('SELECT created_at,id FROM app.notification_receipts WHERE workspace_id=$1 AND id=$2',[query.workspaceId,query.after])).rows[0]:undefined;
      if(query.after&&!cursor)throw missing();
      const rows=(await app.query(`SELECT r.*,n.event_type,n.project_id,n.record_id FROM app.notification_receipts r
        LEFT JOIN app.notifications n ON n.workspace_id=r.workspace_id AND n.id=r.id
        WHERE r.workspace_id=$1 AND ($2::timestamptz IS NULL OR (r.created_at,r.id)<($2,$3::uuid))
        AND (NOT $4::boolean OR r.read_at IS NULL) ORDER BY r.created_at DESC,r.id DESC LIMIT $5`,
      [query.workspaceId,cursor?.created_at??null,cursor?.id??null,query.unreadOnly,query.limit+1])).rows;
      const page=rows.slice(0,query.limit);
      return{records:page.map(row=>this.publicNotice(row,projects)),nextCursor:rows.length>query.limit?page.at(-1)!.id:null,
        dataGeneration:p.dataGeneration,securityHead:p.securityHead,securityVersion:p.securityVersion};
    });
  }
  resolve(cookie:string,csrf:string,input:{workspaceId:string;notificationId:string}){
    return this.withCurrent(cookie,csrf,input.workspaceId,async(app,control,p,now)=>{
      const row=(await app.query(`SELECT r.*,n.event_type,n.project_id,n.record_id FROM app.notification_receipts r LEFT JOIN app.notifications n
        ON n.workspace_id=r.workspace_id AND n.id=r.id WHERE r.workspace_id=$1 AND r.id=$2`,[input.workspaceId,input.notificationId])).rows[0];
      if(!row)throw missing();return this.publicNotice(row,await this.projects(control,p,now));
    });
  }
  preference(cookie:string,csrf:string,input:{workspaceId:string;projectId:string}){
    return this.withCurrent(cookie,csrf,input.workspaceId,async(app,control,p,now)=>{
      if(!(await this.projects(control,p,now)).includes(input.projectId))throw missing();
      const row=(await app.query('SELECT muted,revision FROM app.notification_preferences WHERE workspace_id=$1 AND profile_id=$2 AND project_id=$3',[input.workspaceId,p.accountId,input.projectId])).rows[0];
      return{projectId:input.projectId,muted:row?.muted??false,revision:row?.revision??'0'};
    });
  }
  status(cookie:string,csrf:string,input:{workspaceId:string;operationId:string}){
    return this.withCurrent(cookie,csrf,input.workspaceId,async(app,control,p,now)=>{
      const row=(await app.query('SELECT receipt,data_generation,signed_change FROM app.inbox_operations WHERE workspace_id=$1 AND operation_id=$2',[input.workspaceId,input.operationId])).rows[0];
      if(row&&row.data_generation!==p.dataGeneration)throw changed();
      if(row){const command=inboxMutation.parse(row.signed_change).body.command;
        if(command.action==='set_project_muted'&&!(await this.projects(control,p,now)).includes(command.projectId))throw missing();}
      return{receipt:row?inboxReceipt.parse(row.receipt):null};
    });
  }
  save(cookie:string,csrf:string,input:unknown){
    const payload=inboxMutation.parse(input),b=payload.body.binding;
    return this.withCurrent(cookie,csrf,b.workspaceId,async(app,control,p,now):Promise<InboxReceipt>=>{
      if(payload.body.command.action==='set_project_muted'&&!(await this.projects(control,p,now)).includes(payload.body.command.projectId))throw missing();
      const hash=await digestObject(payload),prior=(await app.query('SELECT request_digest,receipt,data_generation FROM app.inbox_operations WHERE workspace_id=$1 AND operation_id=$2',[b.workspaceId,b.operationId])).rows[0];
      if(prior){if(prior.request_digest!==hash||prior.data_generation!==p.dataGeneration)throw changed();return inboxReceipt.parse(prior.receipt);}
      if(Date.parse(b.expiresAt)<=now.getTime()||Date.parse(b.issuedAt)>now.getTime()+30000||
        canonicalJson(b)!==canonicalJson(await this.binding(control,p,b.operationId,new Date(b.issuedAt))))throw changed();
      try{await validateInboxMutation(payload);}catch{throw new AppError('INBOX_INVALID','Invalid signed Inbox change',400);}
      const command=payload.body.command,revisions:InboxReceipt['revisions']=[],before:unknown[]=[];
      if(command.action==='set_read'){
        for(const ref of [...command.records].sort((a,b)=>a.id.localeCompare(b.id))){
          const row=(await app.query('SELECT id,revision,read_at FROM app.notification_receipts WHERE workspace_id=$1 AND id=$2 FOR UPDATE',[b.workspaceId,ref.id])).rows[0];
          if(!row)throw missing();if(row.revision!==ref.expectedRevision)throw changed();before.push(row);
          const readAt=command.read?now:null,revision=String(BigInt(row.revision)+1n);
          await app.query('UPDATE app.notification_receipts SET read_at=$3,revision=$4 WHERE workspace_id=$1 AND id=$2',[b.workspaceId,ref.id,readAt,revision]);
          await app.query('UPDATE app.notifications SET read_at=$3,revision=$4,updated_at=$5 WHERE workspace_id=$1 AND id=$2',[b.workspaceId,ref.id,readAt,revision,now]);
          revisions.push({id:ref.id,revision});
        }
      }else{
        if(!(await this.projects(control,p,now)).includes(command.projectId))throw missing();
        const row=(await app.query('SELECT id,revision,muted FROM app.notification_preferences WHERE workspace_id=$1 AND profile_id=$2 AND project_id=$3 FOR UPDATE',[b.workspaceId,p.accountId,command.projectId])).rows[0];
        if((row?.revision??'0')!==command.expectedRevision)throw changed();before.push(row??null);
        const id=row?.id??randomUUID(),revision=String(BigInt(command.expectedRevision)+1n);
        await app.query(`INSERT INTO app.notification_preferences(workspace_id,id,profile_id,project_id,muted,revision,updated_at)
          VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(workspace_id,profile_id,project_id) DO UPDATE SET muted=EXCLUDED.muted,revision=EXCLUDED.revision,updated_at=EXCLUDED.updated_at`,
        [b.workspaceId,id,p.accountId,command.projectId,command.muted,revision,now]);revisions.push({id:command.projectId,revision});
      }
      const receipt=inboxReceipt.parse({workspaceId:b.workspaceId,operationId:b.operationId,actorId:p.accountId,dataGeneration:p.dataGeneration,requestHash:hash,committedAt:now.toISOString(),revisions});
      await app.query(`INSERT INTO app.inbox_operations(workspace_id,operation_id,actor_profile_id,data_generation,request_digest,signed_change,before_state,receipt,created_at)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`,[b.workspaceId,b.operationId,p.accountId,p.dataGeneration,hash,payload,JSON.stringify(before),receipt,now]);
      return receipt;
    });
  }
}
