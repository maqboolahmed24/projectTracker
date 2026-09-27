import { randomUUID } from 'node:crypto';
import type { TestContext } from 'node:test';
import { transaction } from '../src/db.js';
import { RestorationService,type RestoreAuth } from '../src/modules/restoration/service.js';
import { RESTORE_TABLES } from '../src/modules/restoration/manifest.js';
import { base64urlDecode,signObject } from '../src/shared/crypto.js';
import { startLogin,finishLogin,startRegistration,finishRegistration } from '../src/client/opaque.js';
import { prepareRestorationVerification } from '../src/client/restoration-crypto.js';
import { unwrapDeviceBundle,type DeviceBundle } from '../src/client/device-store.js';
import { RecoveryService } from '../src/modules/identity/recovery.js';
import { prepareRecoveryDraft,confirmRecoveryRecipient,preparePhraseRecoveryApproval,prepareOwnerRecoveryApproval,proveOwnerPhrase } from '../src/client/recovery-controller.js';
import { newOwnerPhrase } from '../src/client/recovery.js';
import { digestObject } from '../src/shared/crypto.js';
import type { RestoreCheckpointManifest } from '../src/shared/restoration.js';
import { encryptedUpgradesFixture } from './encrypted-upgrades-fixture.js';
import { oldPassword,origin } from './password-change-fixture.js';
export async function restorationFixture(t:TestContext){
  let f:Awaited<ReturnType<typeof encryptedUpgradesFixture>>;
  t.after(async()=>{if(f){await transaction(f.admin.application,async c=>{await c.query("SET LOCAL session_replication_role='replica'");for(const table of ['restorations','unrecovered_projects','reporting_summaries','reporting_preparations','reporting_operations','reporting_settings'])await c.query(`DELETE FROM app.${table} WHERE workspace_id=$1`,[f.workspaceId]);});
    await transaction(f.admin.control,async c=>{await c.query("SET LOCAL session_replication_role='replica'");for(const table of ['restorations','content_checkpoints'])await c.query(`DELETE FROM security.${table} WHERE workspace_id=$1`,[f.workspaceId]);});}});
  f=await encryptedUpgradesFixture(t);let hooks:NonNullable<ConstructorParameters<typeof RestorationService>[0]['hooks']>={},snapshot=new Map<string,unknown[]>();
  const make=()=>new RestorationService({...f,origin,hooks}),operator={operatorId:randomUUID()};let service=make();
  async function checkpoint(){hooks={...hooks,checkpointCaptured:async()=>{snapshot=new Map();for(const table of RESTORE_TABLES)snapshot.set(table,(await f.admin.application.query(`SELECT to_jsonb(t) AS row FROM app.${table} t WHERE workspace_id=$1`,[f.workspaceId])).rows.map(r=>r.row));}};service=make();
    const result=await service.captureCheckpoint({workspaceId:f.workspaceId,checkpointId:randomUUID()},operator);hooks={};service=make();return result;}
  /** Focused protocol fixture only. The separate root drill uses actual base
   * backup + WAL recovery; this helper installs the captured selected rows. */
  async function install(){await transaction(f.admin.application,async c=>{await c.query("SET LOCAL session_replication_role='replica'");
    for(const table of ['notifications','notification_receipts','notification_preferences','inbox_operations','operation_receipts','outbox','summaries','reporting_preparations','reporting_summaries',...RESTORE_TABLES.filter(t=>t!=='workspaces')])await c.query(`DELETE FROM app.${table} WHERE workspace_id=$1`,[f.workspaceId]);
    for(const table of RESTORE_TABLES)for(const row of snapshot.get(table)??[]){if(table==='workspaces'){const w=row as {encrypted_envelope:unknown;revision:string};await c.query('UPDATE app.workspaces SET encrypted_envelope=$2,revision=$3,fence_closed=true,restore_quarantine=true WHERE workspace_id=$1',[f.workspaceId,w.encrypted_envelope,w.revision]);}
      else await c.query(`INSERT INTO app.${table} SELECT * FROM jsonb_populate_record(NULL::app.${table},$1::jsonb)`,[JSON.stringify(row)]);}
  });}
  async function begin(manifest:RestoreCheckpointManifest){const restoreId=randomUUID();await service.begin({workspaceId:f.workspaceId,restoreId,manifest},operator);return restoreId;}
  async function login(accountId=f.accountId,deviceId=f.deviceId,bundle:DeviceBundle=f.originalBundle,password=oldPassword):Promise<RestoreAuth>{
    const started=await startLogin(password),response=await f.authentication.startLogin({workspaceId:f.workspaceId,accountId,startLoginRequest:started.startLoginRequest}),finished=await finishLogin({password,clientLoginState:started.clientLoginState,loginResponse:response.loginResponse,configuration:response.configuration}),
      session=await f.authentication.finishLogin({loginId:response.loginId,finishLoginRequest:finished.finishLoginRequest}),challenge=await f.sessions.beginDeviceChallenge(session.cookieValue,session.csrfToken,deviceId),
      approved=await f.sessions.completeDeviceChallenge(session.cookieValue,session.csrfToken,await signObject(challenge,base64urlDecode(bundle.signingPrivateKey)));
    return {cookieValue:approved.cookieValue,csrfToken:approved.csrfToken};
  }
  async function proof(restoreId:string,auth:RestoreAuth,bundle=f.originalBundle){const context=await service.context(auth,{workspaceId:f.workspaceId,restoreId,operationId:randomUUID()}),history=await f.history();
    return prepareRestorationVerification({context,history,accountId:context.binding.accountId,deviceId:context.binding.deviceId},bundle);}
  async function recover(options:{accountId:string;phrase?:string;password:string;auth?:RestoreAuth;bundle?:DeviceBundle}){
    const recovery=new RecoveryService({...f,origin}),ref={workspaceId:f.workspaceId,operationId:randomUUID(),resumeToken:f.secrets.token()},
      kit={workspaceId:f.workspaceId,accountId:options.accountId,origin,genesisFingerprint:await digestObject(f.prepared.payload.genesis)};
    let binding;
    if(options.phrase){const challenge=await recovery.beginPhrase({...ref,accountId:options.accountId});binding=(await recovery.provePhrase({...ref,proof:await proveOwnerPhrase({challenge,kit,phrase:options.phrase})})).binding!;}
    else {const auth=options.auth??f.auth(),issued=await recovery.issueReset(auth.cookieValue,auth.csrfToken,{workspaceId:f.workspaceId,accountId:options.accountId,resetId:ref.operationId});
      await recovery.beginReset({workspaceId:f.workspaceId,code:issued.code,resumeToken:ref.resumeToken});binding=(await recovery.claim({workspaceId:f.workspaceId,operationId:ref.operationId},auth)).binding!;}
    const registration=await startRegistration(options.password),response=await recovery.registration({...ref,registrationRequest:registration.registrationRequest}),registered=await finishRegistration({password:options.password,clientRegistrationState:registration.clientRegistrationState,registrationResponse:response.registrationResponse,configuration:response.configuration});
    const phrase=binding.isOwner?await newOwnerPhrase():undefined,positions=[2,11,20],prepared=await prepareRecoveryDraft({binding,configuration:response.configuration,registrationRecord:registered.registrationRecord,exportKey:registered.exportKey,
      ...(phrase?{newOwnerKit:{phrase,positions,answers:positions.map(position=>phrase.split(' ')[position]!)}}:{})});
    const pendingLogin=await startLogin(options.password),proof=await recovery.startProof({...ref,draft:prepared.draft,startLoginRequest:pendingLogin.startLoginRequest}),finished=await finishLogin({password:options.password,clientLoginState:pendingLogin.clientLoginState,loginResponse:proof.loginResponse,configuration:proof.configuration});
    await recovery.finishProof({...ref,proofId:proof.proofId,finishLoginRequest:finished.finishLoginRequest});
    const history=await f.history(),fingerprint=await digestObject(prepared.draft.transcript),recipient=await confirmRecoveryRecipient({...prepared,exportKey:registered.exportKey,fingerprint,history});prepared.draft.recipientConfirmation=recipient;await recovery.confirm(ref,recipient);
    const auth=options.auth??f.auth(),reference=options.phrase?ref:{workspaceId:f.workspaceId,operationId:ref.operationId},materials=await recovery.materials(reference,options.phrase?undefined:auth);
    const approval=options.phrase?await preparePhraseRecoveryApproval({...prepared,exportKey:registered.exportKey,phrase:options.phrase,kit,history,fingerprint,materials}):
      await prepareOwnerRecoveryApproval({draft:{transcript:prepared.draft.transcript,recipientConfirmation:prepared.draft.recipientConfirmation,
        newRecoveryConfirmation:prepared.draft.newRecoveryConfirmation},history,fingerprint,materials},options.bundle??f.originalBundle);
    await recovery.confirm(reference,approval.transition.body.authorizerConfirmation,options.phrase?undefined:auth);
    const staged=await recovery.stage(reference,approval,options.phrase?undefined:auth);await recovery.finalize({...reference,requestHash:staged.requestHash!},options.phrase?undefined:auth);
    const deviceId=prepared.draft.transcript.device.id,bundle=await unwrapDeviceBundle({workspaceId:f.workspaceId,accountId:options.accountId,deviceId,credentialGeneration:binding.nextCredentialGeneration},prepared.wrapper,registered.exportKey);
    return {deviceId,bundle,phrase,auth:await login(options.accountId,deviceId,bundle,options.password),recovery};
  }
  // Keep the upgrade getter live: spreading f captures its current service,
  // while setUpgradeHooks replaces that service inside the nested fixture.
  return {...f,checkpoint,install,begin,recover,restoreLogin:login,restoreProof:proof,operator,get upgrades(){return f.upgrades;},get restoration(){return service;},setRestoreHooks(value:typeof hooks={}){hooks=value;service=make();}};
}
