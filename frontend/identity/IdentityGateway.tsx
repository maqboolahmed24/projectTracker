import { useEffect, useRef, useState } from 'react';
import { ArrowRight, Check, Download, FileKey, KeyRound, LockKeyhole, Plus, ShieldCheck, UserRound, X } from 'lucide-react';
import type { ClientRuntime } from '../../src/client/runtime.js';
import type { RememberedProfile } from '../../src/client/remembered-profiles.js';
import type { AvatarSelection } from '../../src/shared/avatar.js';
import type { ActivationResult } from '../../src/client/activation-controller.js';
import { Avatar, Button, Field, Input, Modal, Textarea } from '../shared/ui.js';
import { getClientLibrary } from '../shared/runtime.js';
import { rememberVerifiedProfile } from '../shared/remembered-profile.js';
import { DeviceSecurityCode, DeviceSecurityComparison, IdentityFrame, Notice, PasswordField, PersonalSetup, SecurityComparison, ShareLink, useIdentityAction, type PersonalSetupValue } from './components.js';
import { rememberFinished, wasFinished } from './progress.js';
import { useIdentityPolling } from './useIdentityPolling.js';
import { createHandoffLink, downloadPrivateFile, parseHandoff, parseRecoveryKit, type IdentityHandoff, type RecoveryKitFile } from './handoff.js';

type Reference = {workspaceId:string;accountId:string;deviceId?:string};
type Pending = {kind:'activation'|'join'|'reset'|'phrase'|'promote'|'pair'|'password';id:string;label:string;workspaceId?:string;accountId?:string;deviceId?:string};
type Route = {page:'home'}|{page:'login';reference:Reference;name?:string;avatar?:AvatarSelection}|{page:'link'}|{page:'activate';operationId?:string}|{page:'recover'}|{page:'pair';operationId?:string}|{page:'ceremony';kind:'join'|'reset'|'phrase'|'promote';localId:string;oldPhrase?:string}|{page:'password';operationId:string};
export interface IdentityGatewayProps {client:ClientRuntime;onReady:()=>void|Promise<void>;initialHandoff?:string}

async function savedSetups(client:ClientRuntime):Promise<Pending[]> {
  const lib=await getClientLibrary(), result:Pending[]=[];
  const activation=await lib.IndexedActivationStore.open();
  try { for(const r of await activation.list())if(r.origin===client.auth.origin&&!['expired','cancelled'].includes(r.state)&&!wasFinished('activation',r.operationId))result.push({kind:'activation',id:r.operationId,label:'Workspace setup'}); }finally{activation.close();}
  for(const r of await client.enrolments.operations.list())if(r.role==='recipient'&&!['cancelled','expired','revoked'].includes(r.state)&&!wasFinished('join',r.localId)&&!wasFinished('promote',r.localId)){const record=await client.enrolments.operations.get('recipient',r.localId);const promote=record?.view?.kind==='promote_owner';result.push({kind:promote?'promote':'join',id:r.localId,label:promote?'Your Owner setup':'Your invitation',workspaceId:r.workspaceId,...(r.accountId?{accountId:r.accountId}:{})});}
  for(const r of await client.recoveries.operations.list())if(r.role==='recipient'&&!['cancelled','expired','revoked'].includes(r.state)&&!wasFinished('reset',r.localId)&&!wasFinished('phrase',r.localId)){
    const record=await client.recoveries.operations.get('recipient',r.localId);
    result.push({kind:record?.role==='recipient'&&record.kit?'phrase':'reset',id:r.localId,label:'Account recovery',workspaceId:r.workspaceId,...(r.accountId?{accountId:r.accountId}:{})});
  }
  for(const r of await client.pairing.store.list())if(r.role==='recipient'&&!r.completed&&!wasFinished('pair',r.operationId))result.push({kind:'pair',id:r.operationId,label:'Device approval',workspaceId:r.workspaceId,accountId:r.accountId,deviceId:r.deviceId});
  const changes=await lib.IndexedPasswordChangeStore.open();try{for(const r of await changes.list())if(r.origin===client.auth.origin&&!wasFinished('password',r.operationId))result.push({kind:'password',id:r.operationId,label:'Password change',workspaceId:r.workspaceId});}finally{changes.close();}
  return result;
}

export function IdentityGateway({client,onReady,initialHandoff}:IdentityGatewayProps) {
  const [route,setRoute]=useState<Route>({page:'home'}),[cards,setCards]=useState<RememberedProfile[]>([]),[pending,setPending]=useState<Pending[]>([]),[handoff,setHandoff]=useState<IdentityHandoff|null>(null),[link,setLink]=useState(''),[password,setPassword]=useState(''),[forget,setForget]=useState<Required<Reference>|null>(null);
  const beginning=useRef<{kind:'join'|'reset';workspaceId:string;localId:string}|null>(null);
  const action=useIdentityAction(), initialized=useRef(false),processedHandoff=useRef(''),[recoveryFile,setRecoveryFile]=useState(''),[oldPhrase,setOldPhrase]=useState('');
  const navigationGeneration=useRef(0),latestIncoming=useRef(initialHandoff);latestIncoming.current=initialHandoff;const entryGeneration=navigationGeneration.current;
  const back=()=>{navigationGeneration.current++;setPassword('');setOldPhrase('');setRecoveryFile('');setLink('');action.setError('');setRoute({page:'home'});void client.remembered.list().then(setCards);};
  useEffect(()=>client.auth.onClear(()=>{setPassword('');setOldPhrase('');setRecoveryFile('');setRoute(r=>r.page==='ceremony'?{page:'ceremony',kind:r.kind,localId:r.localId}:r);}),[client]);
  const handleLink=async(value:string)=>{
    navigationGeneration.current++;
    setPassword('');setOldPhrase('');setRecoveryFile('');if(route.page!=='link')setRoute({page:'home'});
    const parsed=parseHandoff(value,client.auth.origin);setHandoff(parsed);setLink('');
    if(parsed.kind==='signin'){setRoute({page:'login',reference:{workspaceId:parsed.workspaceId,accountId:parsed.accountId}});return;}
    if(parsed.kind==='join'){if(!beginning.current||beginning.current.kind!=='join'||beginning.current.workspaceId!==parsed.workspaceId)beginning.current={kind:'join',workspaceId:parsed.workspaceId,localId:crypto.randomUUID()};const p=await client.enrolments.beginJoin({workspaceId:parsed.workspaceId,code:parsed.code,genesisFingerprint:parsed.genesisFingerprint},beginning.current.localId);beginning.current=null;setRoute({page:'ceremony',kind:'join',localId:p.localId});return;}
    if(parsed.kind==='reset'){if(!beginning.current||beginning.current.kind!=='reset'||beginning.current.workspaceId!==parsed.workspaceId)beginning.current={kind:'reset',workspaceId:parsed.workspaceId,localId:crypto.randomUUID()};const p=await client.recoveries.beginReset(parsed.workspaceId,parsed.code,beginning.current.localId);beginning.current=null;setRoute({page:'ceremony',kind:'reset',localId:p.localId});return;}
    if(client.auth.current()?.localAccess==='unlocked'&&client.auth.current()?.session.workspaceId===parsed.workspaceId){
      if(parsed.kind==='promote'){setRoute({page:'login',reference:{workspaceId:client.auth.current()!.session.workspaceId,accountId:client.auth.current()!.session.accountId,deviceId:client.auth.current()!.session.deviceId!}});return;}
      await onReady();return;
    }
    const currentCards=await client.remembered.list(), matching=currentCards.filter(c=>c.workspaceId===parsed.workspaceId);
    if(matching.length===1){const c=matching[0]!;setRoute({page:'login',reference:{workspaceId:c.workspaceId,accountId:c.accountId,deviceId:c.deviceId},name:c.displayName,...(c.avatar?{avatar:c.avatar}:{})});}
    else setRoute({page:'home'});
  };
  useEffect(()=>{if(initialized.current)return;initialized.current=true;
    const incoming=initialHandoff||(location.hash.startsWith('#access=')?location.href:'');
    if(incoming){processedHandoff.current=incoming;history.replaceState(null,'',location.pathname+location.search);}
    void action.run(async()=>{setCards(await client.remembered.list());setPending(await savedSetups(client));if(incoming)await handleLink(incoming);});
  },[client]);
  useEffect(()=>{if(!initialHandoff||processedHandoff.current===initialHandoff||action.busy)return;
    processedHandoff.current=initialHandoff;history.replaceState(null,'',location.pathname+location.search);
    void action.run(()=>handleLink(initialHandoff));
  },[initialHandoff,action.busy]);
  const enter=async()=>{const current=client.auth.current();if(current?.localAccess!=='unlocked')return;const s=current.session;
    const stillCurrent=()=>client.auth.current()?.session.sessionId===s.sessionId&&client.auth.current()?.localAccess==='unlocked'&&navigationGeneration.current===entryGeneration&&(!latestIncoming.current||latestIncoming.current===processedHandoff.current);
    const directory=await client.directory.current();if(!stillCurrent())return;
    if(!directory.restoreQuarantine&&directory.workspaceId===s.workspaceId&&directory.accountId===s.accountId&&directory.deviceId===s.deviceId&&s.deviceId){
      // Recovery replaces this browser's device. Remove stale convenience cards
      // only after the verified directory proves that their device is inactive.
      for(const card of await client.remembered.list()){if(!stillCurrent())return;if(card.workspaceId===s.workspaceId&&card.accountId===s.accountId&&directory.devices.some(device=>device.id===card.deviceId&&!device.active))await client.remembered.remove({workspaceId:card.workspaceId,accountId:card.accountId,deviceId:card.deviceId});}
      await rememberVerifiedProfile(client,directory,s.sessionId,stillCurrent);
    }
    if(!stillCurrent())return;
    await onReady();};
  const login=()=>action.run(async()=>{
    if(route.page!=='login')return;const chosen=password;
    if(handoff?.kind==='promote'&&client.auth.current()?.localAccess==='unlocked'&&client.auth.current()?.session.workspaceId===handoff.workspaceId&&client.auth.current()?.session.accountId===route.reference.accountId){
      const p=await client.enrolments.claimPromotion({workspaceId:handoff.workspaceId,operationId:handoff.operationId},chosen);setPassword('');setRoute({page:'ceremony',kind:'promote',localId:p.localId});return;
    }
    const result=await client.auth.login(route.reference,chosen);setPassword('');
    if(result.localAccess==='pairing_required'){const existing=(await client.pairing.store.list()).find(r=>r.role==='recipient'&&!r.completed&&!wasFinished('pair',r.operationId)&&r.workspaceId===result.session.workspaceId&&r.accountId===result.session.accountId);setRoute({page:'pair',...(existing?{operationId:existing.operationId}:{})});return;}
    if(handoff?.kind==='promote'){const p=await client.enrolments.claimPromotion({workspaceId:handoff.workspaceId,operationId:handoff.operationId},chosen);setRoute({page:'ceremony',kind:'promote',localId:p.localId});return;}
    await enter();
  });
  const resume=(p:Pending)=>action.run(async()=>{
    if(p.kind==='activation')setRoute({page:'activate',operationId:p.id});
    else if(p.kind==='password')setRoute({page:'password',operationId:p.id});
    else if(p.kind==='pair')setRoute({page:'login',reference:{workspaceId:p.workspaceId!,accountId:p.accountId!}});
    else if((p.kind==='join'||p.kind==='reset')&&!p.accountId){beginning.current={kind:p.kind,workspaceId:p.workspaceId!,localId:p.id};setRoute({page:'link'});}else setRoute({page:'ceremony',kind:p.kind,localId:p.id});
  });
  if(route.page==='activate')return <ActivationFlow client={client} onReady={enter} onBack={back} {...(route.operationId?{operationId:route.operationId}:{})}/>;
  if(route.page==='ceremony')return <CeremonyFlow key={route.localId} client={client} kind={route.kind} localId={route.localId} onReady={enter} onBack={back} {...(route.oldPhrase?{initialOldPhrase:route.oldPhrase}:{})}/>;
  if(route.page==='pair')return <PairingFlow client={client} onReady={enter} onBack={back} {...(route.operationId?{operationId:route.operationId}:{})}/>;
  if(route.page==='password')return <PasswordResume client={client} operationId={route.operationId} onReady={enter} onBack={back}/>;
  if(route.page==='login')return <IdentityFrame title={route.name?`Welcome back, ${route.name.split(' ')[0]}`:'Welcome back'} description={handoff?.kind==='promote'?'Confirm your password to begin your Owner setup.':'Your workspace is right where you left it.'} onBack={back} busy={action.busy}>
    <form className="form-stack" onSubmit={e=>{e.preventDefault();void login();}}><div className="identity-login-profile"><Avatar name={route.name||'Your profile'} selection={route.avatar} size={68}/>{route.name&&<strong>{route.name}</strong>}</div><PasswordField value={password} onChange={setPassword}/><Button type="submit" busy={action.busy}>Open my workspace<ArrowRight size={16}/></Button>{action.error&&<Notice tone="error">{action.error}</Notice>}</form><div className="identity-secondary-links"><Button variant="ghost" disabled={action.busy} onClick={()=>setRoute({page:'recover'})}>Forgot your password?</Button>{route.reference.deviceId&&<Button variant="ghost" disabled={action.busy} onClick={()=>setForget({workspaceId:route.reference.workspaceId,accountId:route.reference.accountId,deviceId:route.reference.deviceId!})}>Forget this device</Button>}</div><Modal open={!!forget} title="Forget this device?" description="Your account and work stay safe. This removes the saved sign-in on this browser. You’ll need approval to use it again." onClose={()=>{if(!action.busy)setForget(null);}} footer={<><Button variant="secondary" disabled={action.busy} onClick={()=>setForget(null)}>Keep this device</Button><Button variant="danger" busy={action.busy} onClick={()=>void action.run(async()=>{if(!forget)return;await client.auth.forget(forget);setForget(null);back();})}>Forget this device</Button></>}><p className="muted">Make sure you can use another approved device, your recovery kit, or get help from an Owner.</p></Modal>
  </IdentityFrame>;
  if(route.page==='link')return <IdentityFrame title="A private way in" description="Open the private link you received, or paste it here. You can also choose a saved link file." onBack={back} busy={action.busy}><form className="form-stack" onSubmit={e=>{e.preventDefault();void action.run(()=>handleLink(link));}}><Field label="Private link"><Textarea value={link} onChange={e=>setLink(e.target.value)} required rows={3} autoComplete="off" spellCheck={false}/></Field><Field label="Or choose a link file"><Input type="file" accept="application/json,.json" onChange={e=>{const file=e.target.files?.[0];e.target.value='';if(file)void action.run(async()=>{if(file.size>12000)throw new Error('Please choose the original private link file.');await handleLink(await file.text());});}}/></Field><Button type="submit" busy={action.busy}>Continue<ArrowRight size={16}/></Button>{action.error&&<Notice tone="error">{action.error}</Notice>}<p className="muted identity-small">Only have a short key? Ask the Owner to send its private link. It takes care of finding the right workspace for you.</p></form></IdentityFrame>;
  if(route.page==='recover')return <IdentityFrame title="Let’s get you back in" description="Members can ask any Owner for a temporary access link. Owners can also use their saved recovery kit." onBack={back} busy={action.busy}><div className="form-stack"><Button variant="secondary" onClick={()=>setRoute({page:'link'})}><KeyRound size={18}/>Use a temporary access link<ArrowRight size={16}/></Button><div className="identity-divider"><span>or recover with your kit</span></div><Field label="Your saved recovery kit"><Input type="file" accept="application/json,.json" onChange={e=>{const file=e.target.files?.[0];e.target.value='';if(file)void action.run(async()=>{if(file.size>12000)throw new Error('Please choose your original recovery kit.');const text=await file.text(),kit=parseRecoveryKit(text,client.auth.origin);setRecoveryFile(text);setOldPhrase(kit.phrase);});}}/></Field>{recoveryFile&&<><Notice>Your recovery kit is ready. It stays on this device.</Notice><Field label="Your 24 recovery words"><Textarea value={oldPhrase} onChange={e=>setOldPhrase(e.target.value)} rows={4} autoComplete="off" spellCheck={false}/></Field><Button busy={action.busy} onClick={()=>void action.run(async()=>{const kit=parseRecoveryKit(recoveryFile,client.auth.origin),phrase=oldPhrase;const begun=await client.recoveries.beginPhrase({origin:kit.application,workspaceId:kit.workspaceId,accountId:kit.accountId,genesisFingerprint:kit.genesisFingerprint});await client.recoveries.provePhrase(begun.localId,phrase);setRecoveryFile('');setOldPhrase('');setRoute({page:'ceremony',kind:'phrase',localId:begun.localId,oldPhrase:phrase});})}>Recover my account<ArrowRight size={16}/></Button></>}{action.error&&<Notice tone="error">{action.error}</Notice>}<p className="muted identity-small">If your kit is unavailable, another active Owner can help. Recovery words are private. Never send them to anyone.</p></div></IdentityFrame>;
  return <IdentityFrame title={cards.length?'A little focus. A fresh start.':'Great work starts here.'} description={cards.length?'Choose your profile to pick up where you left off.':'Bring your people and plans together in one calm, private workspace.'}>
    <div className="form-stack">{handoff?.kind==='approve'&&<Notice>Sign in to review the request shared with you.</Notice>}{handoff?.kind==='promote'&&<Notice>Choose your existing profile to set up your Owner access.</Notice>}
      {cards.length>0&&<div className="identity-profile-list">{cards.filter(c=>!handoff||!['approve','promote'].includes(handoff.kind)||c.workspaceId===handoff.workspaceId).map(card=><button key={`${card.workspaceId}:${card.accountId}:${card.deviceId}`} className="identity-profile-card" disabled={action.busy} onClick={()=>setRoute({page:'login',reference:{workspaceId:card.workspaceId,accountId:card.accountId,deviceId:card.deviceId},name:card.displayName,...(card.avatar?{avatar:card.avatar}:{})})}><Avatar name={card.displayName} selection={card.avatar} size={44}/><span><strong>{card.displayName}</strong><small>Remembered on this device</small></span><ArrowRight size={18}/></button>)}</div>}
      <Button disabled={action.busy} onClick={()=>setRoute({page:'activate'})}><Plus size={18}/>Create a workspace<ArrowRight size={16}/></Button><Button variant="secondary" disabled={action.busy} onClick={()=>setRoute({page:'link'})}><UserRound size={18}/>{cards.length?'Use another profile':'Join a workspace'}<ArrowRight size={16}/></Button>
      {pending.length>0&&<section className="identity-pending"><h3>Pick up where you left off</h3>{pending.map(p=><Button key={`${p.kind}:${p.id}`} variant="ghost" onClick={()=>void resume(p)}><ShieldCheck size={16}/>{p.label}<ArrowRight size={16}/></Button>)}</section>}
      {action.error&&<Notice tone="error">{action.error}</Notice>}<Button variant="ghost" disabled={action.busy} onClick={()=>setRoute({page:'recover'})}>Need help getting back in?</Button><p className="identity-privacy-note"><LockKeyhole size={14}/>Your work stays private. Your team stays connected.</p>
    </div>
  </IdentityFrame>;
}

function ActivationFlow({client,onReady,onBack,operationId:initial}: {client:ClientRuntime;onReady:()=>void|Promise<void>;onBack:()=>void;operationId?:string}) {
  const [id,setId]=useState(initial??''),[key,setKey]=useState(''),[stage,setStage]=useState(initial?'loading':'key'),[kit,setKit]=useState<RecoveryKitFile|null>(null),[saved,setSaved]=useState(false),[password,setPassword]=useState('');
  const [result,setResult]=useState<ActivationResult|null>(null),preparedPassword=useRef(''),action=useIdentityAction(),started=useRef(false);
  useEffect(()=>client.auth.onClear(()=>{preparedPassword.current='';setPassword('');setKit(null);}),[client]);
  const accept=(value:Awaited<ReturnType<ClientRuntime['activation']['resume']>>)=>{if('receipt'in value){setResult(value);setStage(value.state==='finishing_setup'?'finishing':'login');}else setStage(value.state==='prepare_required'?'details':value.state==='reserve_required'?'key':value.state==='password_required'?'resume':value.state);};
  useEffect(()=>{if(started.current)return;started.current=true;if(initial)void action.run(async()=>accept(await client.activation.resume(initial)));},[initial]);
  const check=()=>action.run(async()=>accept(await client.activation.resume(id)));
  const activate=()=>action.run(async()=>{const pass=preparedPassword.current||password;const r=await client.activation.resume(id,pass);accept(r);if('receipt'in r&&r.state==='completed'){const reference={workspaceId:r.receipt.workspaceId,accountId:r.receipt.accountId,deviceId:r.receipt.deviceId};await client.auth.login(reference,pass);preparedPassword.current='';setPassword('');rememberFinished('activation',id);await onReady();}});
  return <IdentityFrame title={stage==='key'?'Make room for what’s next.':stage==='details'?'A workspace that’s yours.':stage==='backup'?'Keep your recovery kit safe.':'Your workspace is taking shape.'} description={stage==='key'?'Start with the activation key you received. One key creates one workspace.':stage==='details'?'A few personal details, a secure password, and you’re on your way.':'Your progress is saved securely on this device.'} onBack={onBack} busy={action.busy}>
    <div className="form-stack">{stage==='key'&&<form className="form-stack" onSubmit={e=>{e.preventDefault();void action.run(async()=>{const local=id||await client.activation.create();setId(local);await client.activation.reserve(local,key.trim());setKey('');setStage('details');});}}><Field label="Activation key"><Input value={key} onChange={e=>setKey(e.target.value)} autoComplete="off" required autoFocus placeholder="Enter your activation key"/></Field><Button busy={action.busy} type="submit">Create my workspace<ArrowRight size={16}/></Button></form>}
    {stage==='details'&&<PersonalSetup client={client} owner workspace busy={action.busy} onSubmit={async value=>{await action.run(async()=>{const k=value.ownerKit!;const recoveryKit=await client.activation.prepare(id,{password:value.password,confirmation:value.confirmation,phrase:k.phrase,challengePositions:k.positions,challengeAnswers:k.answers,displayName:value.displayName,workspaceName:value.workspaceName,avatar:value.avatar});preparedPassword.current=value.password;setKit(recoveryKit);setStage('backup');});}}/>}
    {stage==='backup'&&kit&&<><div className="identity-icon"><FileKey size={28}/></div><p className="muted">This file includes your recovery words and the details needed to find your account. Save it somewhere private, outside this browser.</p><Button variant="secondary" onClick={()=>downloadPrivateFile('workspace-recovery-kit.json',kit)}><Download size={16}/>Save recovery kit</Button><label className="identity-check"><input type="checkbox" checked={saved} onChange={e=>setSaved(e.target.checked)}/>I have saved my recovery kit somewhere safe.</label><Button disabled={!saved} busy={action.busy} onClick={()=>void activate()}>Open my workspace<ArrowRight size={16}/></Button></>}
    {(stage==='resume'||stage==='login')&&<form className="form-stack" onSubmit={e=>{e.preventDefault();void (stage==='login'?action.run(async()=>{if(!result)return;await client.auth.login({workspaceId:result.receipt.workspaceId,accountId:result.receipt.accountId,deviceId:result.receipt.deviceId},password);rememberFinished('activation',id);await onReady();}):activate());}}><Notice>{stage==='login'?'Your workspace is ready. Enter your password to open it.':'You have a saved setup. Enter the password you chose to finish.'}</Notice><PasswordField value={password} onChange={setPassword}/><Button busy={action.busy} type="submit">Continue<ArrowRight size={16}/></Button>{stage==='resume'&&<Button variant="ghost" onClick={()=>void action.run(async()=>{await client.activation.replaceDraft(id);setStage('details');})}>I need to set up my recovery kit again</Button>}</form>}
    {(stage==='loading'||stage==='finishing')&&<><Notice>{stage==='loading'?'Checking your saved progress…':'Your workspace is almost ready. You can check again or come back later.'}</Notice><Button busy={action.busy} onClick={()=>void check()}>Check progress</Button></>}
    {['expired','cancelled'].includes(stage)&&<><Notice>This setup is no longer active. If you already completed it, sign in or use your recovery kit.</Notice><Button onClick={onBack}>Back to sign in</Button></>}{action.error&&<Notice tone="error">{action.error}</Notice>}</div>
  </IdentityFrame>;
}

type CeremonyKind='join'|'reset'|'phrase'|'promote';
interface CeremonyMeta {workspaceId:string;accountId:string;genesisFingerprint:string;owner:boolean;bound:boolean;prepared:boolean;confirmed:boolean;fingerprint:string|null;operationId:string;state:string;isPhrase:boolean;needsRebind?:boolean}
async function ceremonyMeta(client:ClientRuntime,kind:CeremonyKind,id:string):Promise<CeremonyMeta>{
  if(kind==='join'||kind==='promote'){
    const r=await client.enrolments.operations.get('recipient',id);if(!r||!r.accountId||!r.operationId)throw new Error('Please open your original invitation again.');
    return {workspaceId:r.workspaceId,accountId:r.accountId,genesisFingerprint:r.genesisFingerprint,owner:r.view?.kind!=='join_member',bound:!!r.view?.binding,prepared:!!r.prepared,confirmed:!!r.view?.recipientConfirmation,fingerprint:r.view?.transcriptDigest??null,operationId:r.operationId,state:r.view?.state??'starting',isPhrase:false,needsRebind:!!r.prepared&&!!r.view?.binding&&JSON.stringify(r.prepared.draft.transcript.binding)!==JSON.stringify(r.view.binding)};
  }
  const r=await client.recoveries.operations.get('recipient',id);if(!r||r.role!=='recipient'||!r.accountId||!r.operationId)throw new Error('Please open your original recovery link again.');
  return {workspaceId:r.workspaceId,accountId:r.accountId,genesisFingerprint:r.kit?.genesisFingerprint??r.view?.binding?.genesisFingerprint??'',owner:r.view?.binding?.isOwner??false,bound:!!r.view?.binding,prepared:!!r.prepared,confirmed:!!r.view?.recipientConfirmation,fingerprint:r.view?.transcriptDigest??null,operationId:r.operationId,state:r.view?.state??'starting',isPhrase:!!r.kit};
}

function CeremonyFlow({client,kind,localId,onReady,onBack,initialOldPhrase}: {client:ClientRuntime;kind:CeremonyKind;localId:string;onReady:()=>void|Promise<void>;onBack:()=>void;initialOldPhrase?:string}) {
  const [meta,setMeta]=useState<CeremonyMeta|null>(null),[access,setAccess]=useState('pending'),[password,setPassword]=useState(''),[newPhrase,setNewPhrase]=useState(''),[oldPhrase,setOldPhrase]=useState(initialOldPhrase??''),[kit,setKit]=useState<RecoveryKitFile|null>(null),[saved,setSaved]=useState(false),[backupDone,setBackupDone]=useState(false),[retryPrepared,setRetryPrepared]=useState(false);
  const transient=useRef({password:'',phrase:''}),action=useIdentityAction(),started=useRef(false),isEnrolment=kind==='join'||kind==='promote';
  const alive=useRef(true),automatic=kind==='join';
  useEffect(()=>{alive.current=true;return()=>{alive.current=false;transient.current={password:'',phrase:''};};},[]);
  useEffect(()=>client.auth.onClear(()=>{transient.current={password:'',phrase:''};setPassword('');setNewPhrase('');setOldPhrase('');setKit(null);}),[client]);
  const refresh=async()=>{const p=isEnrolment?await client.enrolments.resume(localId):await client.recoveries.resume(localId);const m=await ceremonyMeta(client,kind,localId);if(alive.current){setAccess(p.access);setMeta(m);if(p.access==='content_ready'){rememberFinished(kind,localId);await onReady();}}return {p,m};};
  const advance=async(isCurrent:()=>boolean)=>{
    // Credentials remain in memory only, and are used only for this bound setup.
    const chosen=transient.current.password||password,phrase=transient.current.phrase||newPhrase;
    let p=await client.enrolments.resume(localId,phrase||undefined);
    if(!isCurrent())return;
    const m=await ceremonyMeta(client,kind,localId);
    if(!isCurrent())return;
    if(p.access==='login_required'&&chosen&&p.deviceId){
      await client.auth.login({workspaceId:m.workspaceId,accountId:m.accountId,deviceId:p.deviceId},chosen);
      if(!isCurrent())return;
      p=await client.enrolments.resume(localId,phrase||undefined);
      if(!isCurrent())return;
    }
    setMeta(m);setAccess(p.access);
    if(p.access==='content_ready'){transient.current={password:'',phrase:''};rememberFinished(kind,localId);await onReady();}
  };
  const terminal=meta&&['expired','cancelled','revoked'].includes(meta.state);
  const readyForSetup=meta?.bound&&(!meta.prepared||retryPrepared||(automatic&&meta.needsRebind));
  const polling=useIdentityPolling({enabled:automatic&&!!meta&&!terminal&&!action.busy&&!readyForSetup&&(!kit||backupDone)&&['pending','incomplete_keys'].includes(access),scope:localId,poll:advance});
  useEffect(()=>{if(started.current)return;started.current=true;void action.run(refresh);},[localId]);
  const finish=()=>action.run(async()=>{
    await polling.waitForIdle();if(!alive.current)return;
    if(automatic){await advance(()=>alive.current);return;}
    const {p,m}=await refresh(),chosen=transient.current.password||password,phrase=transient.current.phrase||newPhrase;if(!alive.current)return;
    if(p.access==='login_required'){
      if(!chosen){setAccess('login_required');return;}
      if(!p.deviceId)throw new Error('Please check the request again.');
      await client.auth.login({workspaceId:m.workspaceId,accountId:m.accountId,deviceId:p.deviceId},chosen);
      if(!alive.current)return;
    }
    if(p.access==='login_required'||p.access==='recovery_kit_required'){
      const result=isEnrolment?await client.enrolments.resume(localId,phrase||undefined):await client.recoveries.resume(localId,phrase||undefined);if(!alive.current)return;setAccess(result.access);if(result.access==='content_ready'){transient.current={password:'',phrase:''};rememberFinished(kind,localId);await onReady();}
    }
  });
  const prepare=async(value:PersonalSetupValue)=>{
    await polling.waitForIdle();if(!alive.current)return;
    const p=kind==='promote'?await client.enrolments.preparePromotion(localId,value.password,value.ownerKit!):kind==='join'?await client.enrolments.prepare(localId,value.password,value.confirmation,value.displayName,value.ownerKit,value.avatar):await client.recoveries.prepare(localId,value.password,value.confirmation,value.ownerKit);
    if(!alive.current)return;
    transient.current={password:value.password,phrase:value.ownerKit?.phrase??''};const m=await ceremonyMeta(client,kind,localId);if(!alive.current)return;setMeta(m);setRetryPrepared(false);setAccess('pending');
    if(value.ownerKit){setKit({version:1,language:'english',application:client.auth.origin,workspaceId:m.workspaceId,accountId:m.accountId,genesisFingerprint:m.genesisFingerprint,phrase:value.ownerKit.phrase});setBackupDone(false);}
    if(p.state==='completed')await refresh();
  };
  const confirm=(fingerprint:string)=>void action.run(async()=>{
    await polling.waitForIdle();if(!alive.current)return;
    const pass=transient.current.password||password;
    if(!pass)throw new Error('Please enter the password you chose for this setup.');
    if(isEnrolment)await client.enrolments.confirmRecipient(localId,fingerprint,pass);
    else {await client.recoveries.confirmRecipient(localId,fingerprint,pass);if(kind==='phrase')await client.recoveries.approvePhrase(localId,fingerprint,oldPhrase,pass);}
    if(!alive.current)return;if(automatic)await advance(()=>alive.current);else await refresh();
  });
  const share=meta&&!meta.isPhrase?createHandoffLink({kind:'approve',workspaceId:meta.workspaceId,operationId:meta.operationId,ceremony:isEnrolment?'join':'reset'},client.auth.origin):null;
  return <IdentityFrame title={kind==='join'?'Your place on the team.':kind==='promote'?'A new chapter as an Owner.':'A fresh start for your account.'} description={kind==='join'?'A few simple steps, and you’ll be ready to work together.':'Your people, projects and progress stay with you.'} onBack={onBack} busy={action.busy}>
    <div className="form-stack">{!meta&&<Notice>Checking your saved progress…</Notice>}
      {terminal&&<><Notice>This request is no longer active. Ask an Owner for a fresh private link.</Notice><Button onClick={onBack}>Back to sign in</Button></>}
      {!terminal&&meta&&kit&&!backupDone?<><h2>Your new recovery kit</h2><p className="muted">Save this somewhere private. It replaces your previous kit once your new access is ready.</p><Button variant="secondary" onClick={()=>downloadPrivateFile('workspace-recovery-kit.json',kit)}><Download size={16}/>Save recovery kit</Button><label className="identity-check"><input type="checkbox" checked={saved} onChange={e=>setSaved(e.target.checked)}/>I’ve saved my new kit safely.</label><Button disabled={!saved} onClick={()=>setBackupDone(true)}>Continue<ArrowRight size={16}/></Button></>:
      !terminal&&meta&&<>
        {readyForSetup&&<PersonalSetup client={client} owner={meta.owner} promotion={kind==='promote'} recoveryMode={!isEnrolment} retained={retryPrepared||!!(automatic&&meta.needsRebind)} busy={action.busy} onSubmit={async value=>{await action.run(()=>prepare(value));}}/>}
        {!meta.bound&&meta.isPhrase&&<><Notice>To continue this recovery, open your saved kit again. Your existing password stays active until recovery is complete.</Notice><Button onClick={onBack}>Return to recovery options</Button></>}
        {!meta.bound&&!meta.isPhrase&&<><div className="identity-icon"><ShieldCheck size={28}/></div><h2>An Owner will help you in</h2>{automatic?<Notice>Your request is waiting in the Owner’s Access requests. They can start your setup there. This screen updates automatically.</Notice>:<><p className="muted">Share your request with an Owner. They’ll start a quick security check with you.</p>{share&&<ShareLink link={share} title="Send your approval request"/>}<Button busy={action.busy} onClick={()=>void action.run(refresh)}>Check for approval</Button></>}</>}
        {!readyForSetup&&meta.prepared&&!meta.confirmed&&access==='pending'&&meta.fingerprint&&<>{!transient.current.password&&<PasswordField value={password} onChange={setPassword} label={kind==='promote'?'Your current password':'The password you chose'}/>} {kind==='phrase'&&!oldPhrase&&<Field label="Your previous 24 recovery words"><Textarea value={oldPhrase} onChange={e=>setOldPhrase(e.target.value)} rows={4} autoComplete="off" spellCheck={false}/></Field>}{automatic?<DeviceSecurityComparison key={`${meta.operationId}:${meta.fingerprint}`} fingerprint={meta.fingerprint} onConfirm={confirm} busy={action.busy}/>:<><SecurityComparison fingerprint={meta.fingerprint} onConfirm={confirm} busy={action.busy} phrase={kind==='phrase'}/>{share&&<ShareLink link={share} title="Send the request to your Owner"/>}</>}</>}
        {!readyForSetup&&meta.prepared&&meta.confirmed&&access==='pending'&&<>{kind==='phrase'&&!oldPhrase&&<Field label="Your previous 24 recovery words"><Textarea value={oldPhrase} onChange={e=>setOldPhrase(e.target.value)} rows={4} autoComplete="off" spellCheck={false}/></Field>}{kind==='phrase'&&!transient.current.password&&<PasswordField value={password} onChange={setPassword} label="Your chosen password"/>}<Notice>{automatic?'Your check is complete. Once your Owner confirms, your workspace will open automatically.':`Thanks. Your side is ready. ${kind==='phrase'?'Continue to finish your recovery.':'Your Owner can now complete the approval.'}`}</Notice>{meta.fingerprint&&(automatic?<DeviceSecurityCode fingerprint={meta.fingerprint}/>:<output className="identity-fingerprint" aria-label="Complete security check">{meta.fingerprint.match(/.{1,8}/g)?.join(' ')}</output>)}{!automatic&&<>{share&&<ShareLink link={share} title="Share your approval request"/>}{kind==='phrase'&&<Button busy={action.busy} onClick={()=>confirm(meta.fingerprint!)}>Finish recovery</Button>}<Button busy={action.busy} onClick={()=>void finish()}>Check and continue<ArrowRight size={16}/></Button></>}</>}
        {['login_required','recovery_kit_required','incomplete_keys'].includes(access)&&<form className="form-stack" onSubmit={e=>{e.preventDefault();void finish();}}><Notice>{access==='incomplete_keys'?'Your access is still being prepared. Check again in a moment.':access==='recovery_kit_required'?'Enter the new recovery words you just saved to check your backup.':'Your access is approved. Sign in to finish.'}</Notice>{access==='login_required'&&!transient.current.password&&<PasswordField value={password} onChange={setPassword} label="Your chosen password"/>}{meta.owner&&!transient.current.phrase&&<Field label="Your new 24 recovery words"><Textarea value={newPhrase} onChange={e=>setNewPhrase(e.target.value)} rows={4} autoComplete="off" spellCheck={false} required/></Field>}<Button type="submit" busy={action.busy}>Continue to my workspace<ArrowRight size={16}/></Button></form>}
        {!readyForSetup&&meta.bound&&meta.prepared&&access==='pending'&&!meta.fingerprint&&(automatic?<Notice>Your setup is being checked. This screen updates automatically.</Notice>:<Button busy={action.busy} onClick={()=>void action.run(refresh)}>Check progress</Button>)}
        {meta.prepared&&!terminal&&access==='pending'&&<Button variant="ghost" disabled={action.busy} onClick={()=>void action.run(async()=>{await polling.waitForIdle();await refresh();const m=await ceremonyMeta(client,kind,localId);setMeta(m);setRetryPrepared(true);})}>Resume with another Owner</Button>}
        {automatic&&(polling.error||polling.paused)&&<><Notice tone={polling.error?'error':'info'}>{polling.error||'Still waiting? You can keep waiting or return to this request later.'}</Notice><Button variant="secondary" disabled={action.busy} onClick={polling.retry}>Keep checking</Button></>}
        {automatic&&share&&<details className="identity-share"><summary>Can’t find the request?</summary><ShareLink link={share} title="A direct link to this request" description="Only use this if your Owner cannot find it in Access requests."/></details>}
        {!['login_required','recovery_kit_required','content_ready'].includes(access)&&<Button variant="ghost" disabled={action.busy} onClick={()=>void action.run(async()=>{await polling.waitForIdle();const p=isEnrolment?await client.enrolments.cancel(localId):await client.recoveries.cancel(localId);if(['cancelled','expired','revoked'].includes(p.state)){transient.current={password:'',phrase:''};setMeta(m=>m?{...m,state:p.state}:m);}else await refresh();})}><X size={15}/>Cancel this request</Button>}
      </>}{action.error&&<Notice tone="error">{action.error}</Notice>}
    </div>
  </IdentityFrame>;
}

function PairingFlow({client,onReady,onBack,operationId:initial}: {client:ClientRuntime;onReady:()=>void|Promise<void>;onBack:()=>void;operationId?:string}) {
  const [progress,setProgress]=useState<Awaited<ReturnType<ClientRuntime['pairing']['begin']>>|null>(null);
  const [confirmed,setConfirmed]=useState(false),action=useIdentityAction(),started=useRef(false),alive=useRef(true);
  useEffect(()=>{alive.current=true;return()=>{alive.current=false;};},[]);
  const check=async(id:string,isCurrent:()=>boolean=()=>alive.current)=>{
    const p=await client.pairing.resumeRecipient(id);
    if(!isCurrent())return;
    const saved=await client.pairing.store.get('recipient',id);
    if(!isCurrent())return;
    setProgress(p);setConfirmed(!!saved?.confirmation&&saved.confirmation.body.transcriptDigest===p.fingerprint);
    if(p.state==='content_ready'){rememberFinished('pair',id);await onReady();}
  };
  const terminal=!!progress&&['expired','cancelled'].includes(progress.state);
  const polling=useIdentityPolling({enabled:!!progress&&!terminal&&progress.state!=='content_ready'&&!action.busy,
    scope:progress?.operationId??'starting',poll:async isCurrent=>{if(progress)await check(progress.operationId,isCurrent);}});
  const restart=()=>void action.run(async()=>{
    await polling.waitForIdle();if(!alive.current)return;
    if(progress)rememberFinished('pair',progress.operationId);
    setConfirmed(false);const p=await client.pairing.begin();if(!alive.current)return;setProgress(p);await check(p.operationId);
  });
  useEffect(()=>{if(started.current)return;started.current=true;void action.run(async()=>{
    const p=await client.pairing.begin(initial);if(!alive.current)return;setProgress(p);await check(p.operationId);
  });},[client]);
  const state=client.auth.current()?.session;
  return <IdentityFrame title="Let’s welcome this device." description="Approve it from a device you already use, or ask an Owner to help. Your password has been checked." onBack={onBack} busy={action.busy}>
    <div className="form-stack">
      {!progress&&<Notice>Preparing your request…</Notice>}
      {progress&&!terminal&&!progress.fingerprint&&<Notice>Open Maqbool on your approved device and open the request in the sidebar or Settings → Your account. An Owner can also approve it. This screen updates automatically.</Notice>}
      {progress?.fingerprint&&!confirmed&&['waiting_approver','verifying','confirmed'].includes(progress.state)&&
        <DeviceSecurityComparison key={`${progress.operationId}:${progress.fingerprint}`} fingerprint={progress.fingerprint} busy={action.busy} onConfirm={fingerprint=>void action.run(async()=>{
          await polling.waitForIdle();if(!alive.current)return;await client.pairing.confirmRecipient(progress.operationId,fingerprint);if(!alive.current)return;setConfirmed(true);await check(progress.operationId);
        })}/>}
      {confirmed&&progress&&!terminal&&<><Notice>Your check is complete. Once the other device confirms, your workspace will open automatically.</Notice>{progress.fingerprint&&<DeviceSecurityCode fingerprint={progress.fingerprint}/>}</>}
      {terminal&&progress?<><Notice>This request has ended. Start a fresh request to approve this device.</Notice><Button busy={action.busy} onClick={restart}>Start a new request</Button></>:<>
        {(polling.error||polling.paused)&&<><Notice tone={polling.error?'error':'info'}>{polling.error||'Still waiting? You can keep waiting or return to this request later.'}</Notice><Button variant="secondary" disabled={action.busy} onClick={polling.retry}>Keep checking</Button></>}
        {state&&progress&&<details className="identity-share"><summary>Can’t find the request?</summary><ShareLink link={createHandoffLink({kind:'approve',workspaceId:state.workspaceId,operationId:progress.operationId,ceremony:'pair'},client.auth.origin)} title="A direct link to this request" description="Only use this if your approved device or Owner cannot find it in the request list."/></details>}
      </>}
      {action.error&&<Notice tone="error">{action.error}</Notice>}
      {!terminal&&(action.error||polling.error)&&client.auth.current()?.localAccess==='pairing_required'&&<Button variant="secondary" busy={action.busy} onClick={restart}>Start a new request</Button>}
      <p className="muted identity-small">You can leave this screen and return later. The request will expire if it isn’t approved.</p>
    </div>
  </IdentityFrame>;
}

function PasswordResume({client,operationId,onReady,onBack}:{client:ClientRuntime;operationId:string;onReady:()=>void|Promise<void>;onBack:()=>void}) {
  const [password,setPassword]=useState(''),[state,setState]=useState(''),action=useIdentityAction();
  return <IdentityFrame title="Finish your password change." description="Enter the new password you chose. We’ll check your saved progress before continuing." onBack={onBack} busy={action.busy}><form className="form-stack" onSubmit={e=>{e.preventDefault();void action.run(async()=>{let status=await client.passwordChanges.resume(operationId);setState(status.state);if(status.state==='issued'){await client.passwordChanges.complete(operationId,password);status=await client.passwordChanges.resume(operationId);}if(status.receipt){const r=status.receipt;await client.auth.login({workspaceId:r.workspaceId,accountId:r.accountId,deviceId:r.deviceId},password);await client.passwordChanges.resume(operationId,client.auth.current()!.session);setPassword('');rememberFinished('password',operationId);await onReady();}});}}><PasswordField value={password} onChange={setPassword} label="Your new password"/><Button busy={action.busy} type="submit">Continue<ArrowRight size={16}/></Button>{['cancelled','expired','revoked'].includes(state)&&<Notice>This password change ended before completion. Sign in with your previous password.</Notice>}{action.error&&<Notice tone="error">{action.error}</Notice>}</form></IdentityFrame>;
}
