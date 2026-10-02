import { randomUUID } from 'node:crypto';
import sodium from 'libsodium-wrappers';
import type { Databases } from '../../db.js';
import { tenantTransaction } from '../../persistence.js';
import { base64urlEncode, digestObject, signObject } from '../../shared/crypto.js';
import { DELETION_DELAY_MS,deletionFinalization, lifecycleMutation } from '../../shared/lifecycle.js';
import { ServiceSecrets } from '../identity/secrets.js';
import { projectAuthoritativeWorkspace, withSecurityFence } from '../identity/projection.js';

export function deletionElapsed(state: {lifecycle:string;delete_after?:Date|string|null}, now=new Date()): boolean {
  return state.lifecycle==='deleted'||state.lifecycle==='pending_deletion'&&state.delete_after!=null&&new Date(state.delete_after).getTime()<=now.getTime();
}
/** Run before acquiring any control transaction/lock. In-transaction callers use
 * deletionElapsed instead: no protected endpoint waits for the scheduler. */
export async function finalizeDeletionIfDue(input:{databases:Databases;secrets:ServiceSecrets;workspaceId:string;now?:Date}) {
  const {databases,secrets,workspaceId}=input, now=input.now??new Date();
  const snapshot=await tenantTransaction(databases.control,workspaceId,undefined,async c=>(await c.query(
    'SELECT lifecycle,delete_after FROM security.workspaces WHERE workspace_id=$1',[workspaceId])).rows[0]);
  if(!snapshot||!deletionElapsed(snapshot,now))return {deleted:false};
  if(snapshot.lifecycle==='deleted')return {deleted:true};
  return withSecurityFence(databases,workspaceId,async app=>{
    const result=await tenantTransaction(databases.control,workspaceId,undefined,async c=>{
      await c.query("SET LOCAL synchronous_commit='on'");
      const w=(await c.query('SELECT * FROM security.workspaces WHERE workspace_id=$1 FOR UPDATE',[workspaceId])).rows[0];
      if(!w||w.lifecycle==='deleted')return {deleted:true};
      if(!deletionElapsed(w,now))return {deleted:false};
      const row=(await c.query('SELECT signed_transition,head FROM security.security_transitions WHERE workspace_id=$1 AND operation_id=$2',[workspaceId,w.active_deletion_operation_id])).rows[0];
      if(!row)throw new Error('Deletion request proof missing');
      const request=lifecycleMutation.parse(row.signed_transition),b=request.body.binding;
      if(b.action!=='request_deletion'||b.workspaceId!==workspaceId||b.operationId!==w.active_deletion_operation_id||
        b.issuedAt!==new Date(w.deletion_requested_at).toISOString()||new Date(w.delete_after).getTime()!==Date.parse(b.issuedAt)+DELETION_DELAY_MS||
        await digestObject(request)!==row.head)throw new Error('Deletion request proof changed');
      await sodium.ready;
      const seed=secrets.digest('entitlement-signing-key',secrets.keyId),pair=sodium.crypto_sign_seed_keypair(seed);
      const operationId=randomUUID(),version=String(BigInt(w.security_version)+1n),generation=String(BigInt(w.data_generation)+1n);
      let transition;
      try{transition=deletionFinalization.parse(await signObject({purpose:'ukda.workspace-deleted.v1' as const,workspaceId,operationId,
        previousHead:w.security_head,securityVersion:version,dataGeneration:w.data_generation,nextDataGeneration:generation,
        deletion:{requestId:b.operationId,requestedAt:b.issuedAt,deleteAfter:new Date(w.delete_after).toISOString()},requestDigest:row.head,
        finalizedAt:now.toISOString(),serviceKeyId:secrets.keyId,servicePublicKey:base64urlEncode(pair.publicKey)},pair.privateKey));
      }finally{seed.fill(0);pair.privateKey.fill(0);}
      const head=await digestObject(transition);
      await c.query(`INSERT INTO security.security_transitions(workspace_id,sequence,operation_id,previous_head,head,action,actor_kind,signed_transition,created_at)
        VALUES($1,$2,$3,$4,$5,'workspace.deleted','service',$6,$7)`,[workspaceId,version,operationId,w.security_head,head,transition,now]);
      await c.query(`INSERT INTO security.deletion_tombstones(workspace_id,entity_kind,entity_id,deleted_at,security_version)
        VALUES($1,'workspace',$1,$2,$3) ON CONFLICT DO NOTHING`,[workspaceId,w.delete_after,version]);
      await c.query(`UPDATE security.workspaces SET lifecycle='deleted',deleted_at=delete_after,security_head=$2,security_version=$3,data_generation=$4,updated_at=$5 WHERE workspace_id=$1`,
        [workspaceId,head,version,generation,now]);
      await c.query(`UPDATE security.profiles SET state='removed',removed_at=coalesce(removed_at,$2),is_owner=false,owner_ready_at=NULL,
        credential_generation=credential_generation+1,session_generation=session_generation+1,invitation_generation=invitation_generation+1,
        reset_generation=reset_generation+1,recovery_generation=recovery_generation+1,opaque_registration_record=NULL,opaque_setup_id=NULL,
        opaque_config_id=NULL,opaque_identifiers=NULL,updated_at=$2 WHERE workspace_id=$1`,[workspaceId,w.delete_after]);
      await c.query("UPDATE security.devices SET state='revoked',revoked_at=coalesce(revoked_at,$2) WHERE workspace_id=$1",[workspaceId,w.delete_after]);
      await c.query("UPDATE security.grants SET state='revoked',revoked_at=coalesce(revoked_at,$2) WHERE workspace_id=$1",[workspaceId,w.delete_after]);
      await c.query("UPDATE security.recovery_authorities SET state='revoked',revoked_at=coalesce(revoked_at,$2) WHERE workspace_id=$1",[workspaceId,w.delete_after]);
      await c.query('UPDATE security.sessions SET revoked_at=coalesce(revoked_at,$2) WHERE workspace_id=$1',[workspaceId,w.delete_after]);
      await c.query("UPDATE security.ceremonies SET state='cancelled',verification_digest=NULL,verification_key_id=NULL,public_state='{}',staged_registration_record=NULL,server_state_ciphertext=NULL,server_state_key_id=NULL WHERE workspace_id=$1 AND state IN('issued','waiting_approval')",[workspaceId]);
      await c.query('DELETE FROM security.auth_attempts WHERE workspace_id=$1',[workspaceId]);
      await c.query("UPDATE security.restorations SET state='aborted' WHERE workspace_id=$1 AND state='quarantined'",[workspaceId]);
      await c.query(`INSERT INTO security.workspace_purges(workspace_id,deletion_deadline,final_head,final_security_version)
        VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING`,[workspaceId,w.delete_after,head,version]);
      return {deleted:true};
    });
    await projectAuthoritativeWorkspace(databases,workspaceId,app);
    return result;
  },{enqueueActivationProjection:true});
}
