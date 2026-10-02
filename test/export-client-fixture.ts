import { randomUUID } from 'node:crypto';
import { digestObject } from '../src/shared/crypto.js';
import { exportBinding, exportSourceManifest, exportSources, exportManifestKey, sortedExportManifest, type ExportSource, type ExportPage } from '../src/shared/export.js';
import { prepareCollaboration } from '../src/client/collaboration-crypto.js';
import { collaborationClientFixture } from './collaboration-client-fixture.js';

export async function exportClientFixture() {
  const collab=await collaborationClientFixture(),f=collab.planning.f,owner=collab.owner,entryId=randomUUID();
  await collab.apply(await prepareCollaboration({...await collab.input(entryId,'comment'),command:{action:'post_comment',entryId,taskId:collab.taskId},text:'Private original discussion'},owner.bundle));
  const prior=(await collab.context(entryId,'comment')).entry!;
  const {verifyCollaborationEntry}=await import('../src/shared/collaboration.js'),{planningSecurityResolver}=await import('../src/client/planning-crypto.js');
  const verified=await verifyCollaborationEntry(prior,await collab.planning.context(),planningSecurityResolver(f.history,f.state));
  await collab.apply(await prepareCollaboration({...await collab.input(entryId,'comment'),command:{action:'hide_comment',entryId,expectedRevision:'1',previousHead:verified.head,originalDigest:verified.originalDigest},reason:'Private moderation reason'},owner.bundle));
  async function input() {
    const settings={workspaceId:f.workspaceId,initial:f.initialWorkspace,revision:'0',head:await digestObject(f.initialWorkspace),timezone:null,history:[],
      securityHead:f.state.securityHead,securityVersion:f.state.securityVersion,dataGeneration:f.state.dataGeneration};
    const sources:ExportSource[]=[{kind:'workspace',workspace:f.initialWorkspace,profiles:[{id:owner.accountId,revision:'1',state:'active',envelope:f.initialProfile}],settings},
      {kind:'project',context:await collab.planning.context()},
      {kind:'entry',history:{planning:await collab.planning.context(),entry:(await collab.entry(entryId))!}}];
    const manifest=sortedExportManifest((await Promise.all(sources.map(exportSourceManifest))).flat()),refs=exportSources(manifest),now=Date.now(),
      profile=f.state.profiles[owner.accountId]!,device=f.state.devices[owner.deviceId]!,binding=exportBinding.parse({version:1,workspaceId:f.workspaceId,exportId:randomUUID(),origin:f.history.origin,
        accountId:owner.accountId,deviceId:owner.deviceId,credentialGeneration:profile.credentialGeneration,sessionGeneration:profile.sessionGeneration,keyGeneration:device.keyGeneration,
        signingPublicKey:device.signingPublicKey,securityHead:f.state.securityHead,securityVersion:f.state.securityVersion,dataGeneration:f.state.dataGeneration,
        manifestDigest:await digestObject(manifest),sourceCount:refs.length,issuedAt:new Date(now).toISOString(),expiresAt:new Date(now+600000).toISOString(),acknowledgePlaintext:true});
    const pages:ExportPage[]=refs.map((source,index)=>({binding,source,data:source.kind==='workspace'?sources[0]!:source.kind==='project'?sources[1]!:sources[2]!,nextCursor:index+1<refs.length?exportManifestKey(source):null}));
    return {start:{binding,manifest,sources:refs},pages,history:f.history,materials:f.materials,accountId:owner.accountId,deviceId:owner.deviceId,acknowledgePlaintext:true as const};
  }
  return {f,owner,collab,input};
}
