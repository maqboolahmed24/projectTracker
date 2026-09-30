'use client';
import { useCallback, useEffect, useRef, useState } from 'react';
import { ArrowUpRight, Check, CheckCircle2, FileCheck2 } from 'lucide-react';
import type { EvidenceContext } from '../../src/shared/file-evidence.js';
import type { PlanningTask } from '../../src/shared/planning.js';
import type { ReadableFileEntry, ReadableFileVersion } from '../../src/client/files-controller.js';
import { useApp } from '../shared/context';
import { Badge, Button, Spinner } from '../shared/ui';
import { executable, has, taskEditor, workspaceWritable, type Project } from '../work/shared';
import { bytesLabel, FileIcon, FileNotice, updatedLabel } from './common';
import { FileDetail } from './detail';
import { WithdrawApproval } from './approval';

type EvidenceFile={version:ReadableFileVersion;kind:'source'|'output'};
interface TaskEvidenceProps {
 project:Project;task:PlanningTask;entries:ReadableFileEntry[];onChanged:()=>void|Promise<void>;
 onSetUpReview?:()=>void;onAddOutput?:()=>void;onChooseReviewer?:()=>void;onTaskDetails?:()=>void;
}
export function TaskEvidence({project,task,entries,onChanged,onSetUpReview,onAddOutput,onChooseReviewer,onTaskDetails}:TaskEvidenceProps){
 const {client,directory,reloadProjects,notify}=useApp(),[context,setContext]=useState<EvidenceContext>(),[files,setFiles]=useState<EvidenceFile[]>([]),[loading,setLoading]=useState(true),[busy,setBusy]=useState(false),[error,setError]=useState<unknown>(),[checked,setChecked]=useState(false),[selection,setSelection]=useState<Record<string,File>>({}),[pending,setPending]=useState<string[]>([]),[progress,setProgress]=useState(''),[opened,setOpened]=useState<EvidenceFile>(),[withdraw,setWithdraw]=useState(false),picker=useRef<HTMLInputElement>(null),target=useRef<string|undefined>(undefined),projectId=project.graph.project.id;
 const versionStamp=entries.map(e=>{const link=e.links.find(l=>l.taskId===task.id);return [e.fileId,e.latestVersionId,e.kind,link?.mode,link?.versionId].join(':');}).join('|');
 const readKey=[projectId,task.id,task.revision,project.graph.project.reviewPolicyRevision,versionStamp].join('/'),currentReadKey=useRef(readKey),readSequence=useRef(0),alive=useRef(true);
 currentReadKey.current=readKey;
 const read=useCallback(async()=>{if(!alive.current||currentReadKey.current!==readKey)return;const sequence=++readSequence.current,isCurrent=()=>alive.current&&sequence===readSequence.current&&currentReadKey.current===readKey;setLoading(true);setError(undefined);setChecked(false);setSelection({});try{
  const next=await client.fileEvidence.context(projectId,{taskId:task.id}),refs=next.submission&&['review','done'].includes(task.state)?[...next.submission.body.sources.map(r=>({...r,kind:'source' as const})),...next.submission.body.outputs.map(r=>({...r,kind:'output' as const}))]:[...next.sources.map(r=>({...r,kind:'source' as const})),...next.outputs.map(r=>({...r,kind:'output' as const}))],values:EvidenceFile[]=[];
  for(let i=0;i<refs.length;i+=2){const found=await Promise.all(refs.slice(i,i+2).map(async r=>{const current=entries.find(e=>e.latestVersionId===r.versionId);return {kind:r.kind,version:current?{...current.version,metadata:current.metadata}:await client.files.version(projectId,r.versionId)};}));if(!isCurrent())return;values.push(...found);}
  const attempts=(await client.fileEvidence.pending()).filter(r=>r.taskId===task.id);
  if(!isCurrent())return;setContext(next);setFiles(values);setPending(attempts.map(r=>r.operationId));
 }catch(e){if(isCurrent())setError(e);}finally{if(isCurrent())setLoading(false);}},[client,projectId,task.id,task.revision,project.graph.project.reviewPolicyRevision,versionStamp,readKey]);
 useEffect(()=>{alive.current=true;void read();return()=>{alive.current=false;readSequence.current++;};},[read]);
 const writable=workspaceWritable(directory),preparing=['todo','in_progress'].includes(task.state),submitter=writable&&taskEditor(project,task)&&preparing,active=executable(project,task.phaseId),reviewEnabled=project.graph.project.reviewEnabled;
 const assignedReviewer=has(project,'approve_tasks')&&task.reviewerProfileId===project.authority.accountId&&!task.assigneeIds.includes(project.authority.accountId);
 const hasOutput=files.some(f=>f.kind==='output'),reviewerUploadedOutput=!!task.reviewerProfileId&&files.some(f=>f.kind==='output'&&f.version.manifest.body.binding.accountId===task.reviewerProfileId),reviewer=writable&&assignedReviewer&&!reviewerUploadedOutput;
 const blocked=(project.graph.blockers??[]).some(blocker=>blocker.taskId===task.id&&blocker.state==='open');
 const externals=files.filter(f=>f.version.manifest.body.storage==='external'),allExternal=externals.every(f=>!!selection[f.version.manifest.body.versionId]),sourcesMatch=context?.submission?context.submission.body.sources.map(r=>r.versionId).sort().join('|')===context.sources.map(r=>r.versionId).sort().join('|'):true,outputsMatch=context?.submission?context.submission.body.outputs.map(r=>r.versionId).sort().join('|')===context.outputs.map(r=>r.versionId).sort().join('|'):true,changed=!sourcesMatch||!outputsMatch,approved=!!context?.approval&&!context.revocation&&task.state==='done'&&!changed;
 const canSubmit=submitter&&active&&reviewEnabled&&!!task.reviewerProfileId&&!reviewerUploadedOutput&&hasOutput&&!blocked;
 const canAccept=reviewer&&active&&reviewEnabled&&task.state==='review'&&!blocked&&!changed;
 const canCheckExternal=active&&reviewEnabled&&(submitter||reviewer)&&!busy;
 async function choose(file:File|undefined){const id=target.current;if(!file||!id||!canCheckExternal)return;setBusy(true);setError(undefined);try{const result=await client.files.verifyExternal(projectId,id,file);if(!result.matches)throw {code:'CHANGED_FILE'};setSelection(old=>({...old,[id]:file}));}catch(e){setError(e);}finally{setBusy(false);}}
 async function save(action:'submit'|'accept'|'resume'){
  if(busy||!writable||action==='submit'&&!canSubmit||action==='accept'&&!canAccept)return;
  if(action!=='resume'&&!context){setError({code:'CONFLICT'});return;}
  setBusy(true);setError(undefined);setProgress('');
  try{if(action==='resume'){for(const id of pending)await client.fileEvidence.resume(id);}else await client.fileEvidence[action](projectId,task.id,{reviewedContext:context!,externalFiles:selection,onProgress:(checked,total)=>setProgress('Checking '+checked+' of '+total+' exact versions…')});
   notify(action==='submit'?'Exact versions submitted for review.':action==='accept'?'These versions were accepted.':'The saved review is complete.');await reloadProjects();await onChanged();await read();
  }catch(e){setError(e);try{const attempts=await client.fileEvidence.pending();setPending(attempts.filter(r=>r.taskId===task.id).map(r=>r.operationId));}catch{}}finally{setBusy(false);setProgress('');}
 }
 if(loading)return <div className="file-review-card file-review-loading" role="status"><Spinner/><span>Checking the task’s file versions…</span></div>;
 if((!context||!files.length)&&!error)return null;
 const displayFiles=context?.submission&&['review','done'].includes(task.state)?files:externals;
 const current=opened?.version,detailEntry=current?{fileId:current.manifest.body.fileId,kind:opened!.kind,latestVersionId:current.manifest.body.versionId,version:current,metadata:current.metadata,links:[]}:undefined;
 return <section className="file-review-card stack">
  <div className="section-heading"><div><h3>{approved?'Accepted evidence':context?.submission&&['review','done'].includes(task.state)?'Submitted evidence':'Prepare this task for review'}</h3><p className="muted">{context?.submission&&['review','done'].includes(task.state)?'Submitted '+updatedLabel(context.submission.body.binding.issuedAt):'Tasks with linked files finish with an independent review of their exact sources and outputs.'}</p></div><FileCheck2 size={23}/></div>
  {error!==undefined&&<FileNotice error={error} action={<Button variant="ghost" onClick={()=>void read()}>Refresh review</Button>}/>}
  {context?.revocation&&<FileNotice warning>This approval was withdrawn. New review is needed before delivery.</FileNotice>}
  {changed&&<FileNotice warning>The working files changed after this submission. Submit the new versions for review before they can be accepted.</FileNotice>}
  {approved&&<div className="button-row"><Badge tone="success"><CheckCircle2 size={14}/> Accepted exact versions</Badge>{project.authority.isOwner&&writable&&<Button variant="ghost" onClick={()=>setWithdraw(true)}>Withdraw approval</Button>}</div>}
  {!approved&&preparing&&!reviewEnabled&&<FileNotice warning action={onSetUpReview?<Button variant="secondary" onClick={onSetUpReview}>Set up task review</Button>:undefined}>{onSetUpReview?'Tasks with linked files need an independent review before completion. Turn on review for this project to continue.':'Tasks with linked files need an independent review before completion. Ask an Owner to turn on task review for this project.'}</FileNotice>}
  {!approved&&preparing&&!hasOutput&&<FileNotice warning action={onAddOutput?<Button variant="secondary" onClick={onAddOutput}>Add output</Button>:undefined}>{onAddOutput?'Add at least one finished output before sending this task for review.':'An assignee or task manager needs to add a finished output before this task can be sent for review.'}</FileNotice>}
  {!approved&&preparing&&reviewEnabled&&!task.reviewerProfileId&&<FileNotice warning action={onChooseReviewer?<Button variant="secondary" onClick={onChooseReviewer}>Choose reviewer</Button>:undefined}>{onChooseReviewer?'Choose an independent reviewer before sending this task for review.':'A task manager needs to choose an independent reviewer before this task can be sent for review.'}</FileNotice>}
  {!approved&&reviewerUploadedOutput&&<FileNotice warning action={onChooseReviewer?<Button variant="secondary" onClick={onChooseReviewer}>Choose reviewer</Button>:undefined}>{onChooseReviewer?'Choose a reviewer who did not upload any of this task’s outputs.':'A task manager needs to choose a reviewer who did not upload any of this task’s outputs.'}</FileNotice>}
  {!approved&&(preparing||task.state==='review')&&(!writable||!active||blocked)&&<FileNotice warning action={onTaskDetails?<Button variant="secondary" onClick={onTaskDetails}>Back to task details</Button>:undefined}>{!writable?'Your workspace is read only. An Owner can help restore editing.':!active?`Start or reopen this project${task.phaseId?` and its ${project.graph.project.phaseLabel}`:''} before moving the task forward.`:'Resolve this task’s open blockers before submitting or accepting its work.'}</FileNotice>}
  {displayFiles.length>0&&<div className="file-review-versions">{displayFiles.map(({version,kind})=>{const body=version.manifest.body,external=body.storage==='external';return <article key={body.versionId}><button className="file-evidence-row" onClick={()=>setOpened({version,kind})}><FileIcon name={version.metadata.filename}/><span><strong>{version.metadata.filename}</strong><small className="muted">{version.metadata.documentReference} · {kind==='source'?'Source':'Output'} · Exact v{body.version} · {bytesLabel(body.plainBytes)}</small></span><ArrowUpRight size={16}/></button>{external&&<div className="file-review-external"><Badge tone={selection[body.versionId]?'success':'warning'}>{selection[body.versionId]?<><Check size={13}/> Matches this version</>:'Shared-drive file needs checking'}</Badge><Button variant="secondary" busy={busy} disabled={!canCheckExternal} onClick={()=>{target.current=body.versionId;picker.current?.click();}}>Check selected file</Button></div>}</article>;})}</div>}
  <input type="file" ref={picker} className="sr-only" aria-label="Choose external evidence file to check" onChange={e=>{void choose(e.target.files?.[0]);e.target.value='';}}/>
  {progress&&<p className="muted" role="status">{progress}</p>}
  {pending.length>0?<div className="file-review-actions"><FileNotice warning>A review attempt is saved on this browser. Check it before creating another submission.</FileNotice><Button busy={busy} disabled={!writable} onClick={()=>void save('resume')}>Check and finish saved review</Button></div>:!approved&&reviewEnabled&&active&&(submitter||reviewer&&task.state==='review')&&hasOutput&&!!task.reviewerProfileId&&!reviewerUploadedOutput?<div className="file-review-actions"><label className="check-row"><input type="checkbox" checked={checked} disabled={busy||blocked} onChange={e=>setChecked(e.target.checked)}/><span>{submitter?'I have checked these versions and the task’s acceptance criteria.':'I have reviewed these exact versions and the completed work.'}</span></label>{!allExternal&&<p className="field-hint">Check the shared-drive files on this device before continuing.</p>}<Button busy={busy} disabled={!checked||!allExternal||error!==undefined||!(submitter?canSubmit:canAccept)} onClick={()=>void save(submitter?'submit':'accept')}>{submitter?'Submit exact versions for review':'Accept these versions'}</Button></div>:!assignedReviewer&&task.state==='review'&&<p className="muted">A separate reviewer will accept the submitted work. {directory?.people.find(p=>p.accountId===task.reviewerProfileId)?.displayName??'Your reviewer'} is reviewing this task.</p>}
  {withdraw&&<WithdrawApproval project={project} target={{taskId:task.id}} onClose={()=>setWithdraw(false)} onDone={async()=>{await reloadProjects();await onChanged();await read();}}/>}
  {opened&&detailEntry&&<FileDetail readOnly project={project} entry={detailEntry} pinnedVersionId={detailEntry.latestVersionId} onClose={()=>setOpened(undefined)} onChanged={onChanged}/>}
 </section>;
}
