import { randomUUID } from 'node:crypto';
import { digestObject } from '../src/shared/crypto.js';
import { reportingBinding,reportingContext,reportingLocalDate,reportingManifest,type ReportingSettings,type ReportingSettingsPayload,type ReportingScope } from '../src/shared/reporting.js';
import { preparePlanning,type PlanningIntent,type PlanningPrivateContent } from '../src/client/planning-crypto.js';
import { planningClientFixture } from './planning-client-fixture.js';

export async function reportingClientFixture(){
  const planning=await planningClientFixture({version:2,secondOwner:true}),f=planning.f,owner=f.owner,initial=f.initialWorkspace;
  let changes:ReportingSettingsPayload[]=[];
  const settings=async():Promise<ReportingSettings>=>({workspaceId:f.workspaceId,initial,revision:String(changes.length),head:await digestObject(changes.at(-1)?.mutation??initial),
    timezone:changes.at(-1)?.mutation.body.timezone??null,history:[...changes],securityHead:f.state.securityHead,securityVersion:f.state.securityVersion,dataGeneration:f.state.dataGeneration});
  const keys=()=>({history:f.history,materials:f.materials,accountId:owner.accountId,deviceId:owner.deviceId});
  const context=async(scope:ReportingScope={kind:'project',projectId:planning.projectId},operationId:string=randomUUID())=>{
    const project=await planning.context(operationId),pb=project.binding,config=await settings(),issuedAt=new Date().toISOString(),timezone=config.timezone??'Europe/London',
      visibleScopes=f.state.profiles[owner.accountId]!.scopes.filter(s=>s.scope==='project').map(s=>({projectId:s.scopeId,keyEpoch:s.keyEpoch,permissions:[...s.permissions].sort()})).sort((a,b)=>a.projectId.localeCompare(b.projectId));
    const binding=reportingBinding.parse({version:1,origin:pb.origin,workspaceId:f.workspaceId,operationId,accountId:owner.accountId,deviceId:owner.deviceId,
      credentialGeneration:pb.credentialGeneration,sessionGeneration:pb.sessionGeneration,keyGeneration:pb.keyGeneration,signingPublicKey:pb.signingPublicKey,
      securityHead:pb.securityHead,securityVersion:pb.securityVersion,dataGeneration:pb.dataGeneration,isOwner:true,issuedAt,expiresAt:new Date(Date.parse(issuedAt)+600000).toISOString(),
      scope,scopeHash:await digestObject(scope),authorizationFingerprint:await digestObject({securityHead:pb.securityHead,securityVersion:pb.securityVersion,dataGeneration:pb.dataGeneration,visibleScopes}),
      visibleScopes,sources:[await reportingManifest(project)],settingsRevision:config.revision,settingsHead:config.head,initialDigest:await digestObject(initial),timezone,
      asOfUtc:issuedAt,localDate:reportingLocalDate(issuedAt,timezone),complete:true,calculationVersion:'progress-health-v1'});
    return reportingContext.parse({binding,settings:config,projects:[project]});
  };
  const command=async(command:PlanningIntent,content?:PlanningPrivateContent,outcome?:string)=>{const payload=await preparePlanning({...await planning.input(),command,
    ...(content?{content}:{}),...(outcome?{outcome}:{})},owner.bundle);await planning.apply(payload);return payload;};
  const settingsContext=async()=>{const b=(await context()).binding,s=await settings();return {settings:s,binding:{version:b.version,origin:b.origin,workspaceId:b.workspaceId,operationId:randomUUID(),accountId:b.accountId,deviceId:b.deviceId,
    credentialGeneration:b.credentialGeneration,sessionGeneration:b.sessionGeneration,keyGeneration:b.keyGeneration,signingPublicKey:b.signingPublicKey,securityVersion:b.securityVersion,securityHead:b.securityHead,
    dataGeneration:b.dataGeneration,isOwner:b.isOwner,issuedAt:b.issuedAt,expiresAt:b.expiresAt,expectedRevision:s.revision,previousHead:s.head,previousTimezone:s.timezone,initialDigest:await digestObject(initial)}};};
  return {planning,f,owner,keys,settings,context,settingsContext,command,applySettings:(payload:ReportingSettingsPayload)=>{changes=[...changes,payload];},
    input:async(scope?:ReportingScope)=>({...keys(),context:await context(scope)})};
}
