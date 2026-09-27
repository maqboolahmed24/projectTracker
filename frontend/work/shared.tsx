import { useEffect, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import type { ReadablePlanning, PlanningIntent, PlanningPrivateContent } from '../../src/client/planning-crypto.js';
import type { PlanningTask, PlanningPhase } from '../../src/shared/planning.js';
import type { ReadableReporting } from '../../src/client/reporting-crypto.js';
import { useApp } from '../shared/context';
import { Avatar, Badge, Button, ErrorNotice } from '../shared/ui';
import type { BadgeTone } from '../shared/ui';

export type Project = ReadablePlanning;
export type Person = NonNullable<ReturnType<typeof useApp>['directory']>['people'][number];
export const workspaceWritable=(directory:ReturnType<typeof useApp>['directory'])=>!!directory&&directory.licenceState==='active'&&directory.entitlementState==='activated'&&directory.lifecycle==='active'&&!directory.restoreQuarantine&&!directory.activeRestore&&!directory.activeUpgrade;
export const text = (value: unknown, fallback = ''): string => typeof value === 'string' ? value : fallback;
export function content(project: Project, id: string): Record<string, unknown> { return project.records.find(row => row.id === id)?.content ?? {}; }
export const projectName = (project: Project) => text(content(project, project.graph.project.id).name, 'Untitled project');
export const taskName = (project: Project, id: string) => text(content(project, id).title, 'Untitled task');
export const phaseName = (project: Project, id: string | null) => id ? text(content(project,id).name, 'Untitled wave') : 'Unscheduled work';
export const displayStatus = (state: string) => ({ planned:'Planned',active:'Active',complete:'Complete',cancelled:'Cancelled',todo:'To do',in_progress:'In progress',review:'In review',done:'Done',open:'Open',accepted:'Accepted',resolved:'Resolved' }[state] ?? state);
export const statusTone = (state: string): BadgeTone => {
  if (['done','complete','accepted','resolved'].includes(state)) return 'success';
  if (['active','in_progress'].includes(state)) return 'info';
  if (state === 'review') return 'purple';
  if (state === 'cancelled') return 'danger';
  if (['blocked','paused'].includes(state)) return 'warning';
  return 'neutral';
};
export const has = (project: Project, permission: string) => project.authority.permissions.some(value => value===permission);
export const editable = (project: Project, phaseId?: string | null) => !project.graph.project.archived && !['complete','cancelled'].includes(project.graph.project.state) && (!phaseId || project.graph.phases.some(row => row.id===phaseId && !row.archived && !['complete','cancelled'].includes(row.state)));
export const executable = (project: Project, phaseId?: string|null) => editable(project,phaseId) && project.graph.project.state==='active' && (!phaseId || project.graph.phases.some(row => row.id===phaseId && row.state==='active'));
export const unfinished = (task: PlanningTask) => !['done','cancelled'].includes(task.state);
export const activeTasks = (project: Project) => project.graph.project.archived ? [] : project.graph.tasks.filter(task => !task.phaseId || !project.graph.phases.find(phase => phase.id===task.phaseId)?.archived);
export const taskEditor = (project: Project, task: PlanningTask) => has(project,'manage_tasks') || has(project,'edit_assigned_tasks') && task.assigneeIds.includes(project.authority.accountId);
export function dateLabel(value: unknown): string { if (typeof value!=='string'||!value) return 'No date'; const date = new Date(`${value}T12:00:00`); return Number.isFinite(+date) ? new Intl.DateTimeFormat(undefined,{day:'numeric',month:'short',year:'numeric'}).format(date) : value; }
export const dateValue = (value: unknown) => typeof value==='string' ? value : '';
export const optionalDate = (value: string) => value ? value : undefined;
export function shortDate(value: unknown) { if(typeof value!=='string'||!value)return 'No date';const date=new Date(`${value}T12:00:00`);return Number.isFinite(+date)?new Intl.DateTimeFormat(undefined,{day:'numeric',month:'short'}).format(date):value; }
export function People({ids,people,limit=4}:{ids:readonly string[];people:Person[];limit?:number}) { return <span className="avatar-group" aria-label={ids.map(id=>people.find(p=>p.accountId===id)?.displayName??'Former member').join(', ')}>{ids.slice(0,limit).map(id=>{const person=people.find(p=>p.accountId===id);return <Avatar key={id} selection={person?.avatar} name={person?.displayName??'Former member'} size={28}/>;})}{ids.length>limit&&<span className="avatar-overflow">+{ids.length-limit}</span>}{!ids.length&&<span className="muted">Unassigned</span>}</span>; }
export function DetailList({children}:{children:ReactNode}) {
  return <dl className="task-metadata">{children}</dl>;
}
export function DetailItem({label,children,action}:{label:ReactNode;children:ReactNode;action?:ReactNode}) {
  return <div className="detail-item"><dt className="detail-label">{label}</dt><dd className="detail-value"><div className="detail-content">{children}</div>{action&&<div className="detail-action">{action}</div>}</dd></div>;
}
export function StateBadge({state}:{state:string}) { return <Badge tone={statusTone(state)}>{displayStatus(state)}</Badge>; }
export function useAction(options:{onReview?:(current:unknown)=>void}={}) {
  const {reloadProjects,reloadDirectory,notify}=useApp();
  const [busy,setBusy]=useState(false),[error,setError]=useState<unknown>(null),[retry,setRetry]=useState<(()=>Promise<unknown>)|null>(null),[finishing,setFinishing]=useState(false);
  const alive=useRef(true); useEffect(()=>{alive.current=true;return()=>{alive.current=false;};},[]);
  const inFlight=useRef(false);
  const retryAfter=useRef<(()=>void|Promise<void>)|undefined>(undefined);
  async function run(label:string,work:()=>Promise<unknown>,resume?:()=>Promise<unknown>,after?:()=>void|Promise<void>) {
    if(inFlight.current)return false;
    inFlight.current=true;setBusy(true);setError(null);setRetry(null);setFinishing(false);retryAfter.current=after;
    try {
      let result:unknown;
      try { result=await work(); }
      catch(reason){
        if(alive.current){const code=reason&&typeof reason==='object'&&'code' in reason?String(reason.code):'';
          const uncertain=['TRANSPORT','RETRY_REQUIRED','UNAVAILABLE','STORAGE'].includes(code)||reason instanceof TypeError;
          setError(reason);setRetry(resume&&uncertain?()=>resume:null);}
        return false;
      }
      // A verified write result stands independently of the next view refresh.
      // Never turn a committed creation back into a new, resubmittable draft.
      if(result&&typeof result==='object'&&'state' in result&&result.state==='finishing'){
        if(alive.current){setFinishing(true);setRetry(()=>resume??work);}
        await Promise.all([reloadProjects(),reloadDirectory()]).catch(()=>{});
        return false;
      }
      let refreshed=true;
      try { await Promise.all([reloadProjects(),reloadDirectory()]); } catch { refreshed=false; }
      if(alive.current){
        setError(null);setRetry(null);setFinishing(false);
        notify(refreshed?label:'Your change is saved. Refresh to see the latest view.',refreshed?'success':'info');
        try { await after?.(); } catch { notify('Your change is saved. Refresh to see the latest view.','info'); }
      }
      return true;
    } finally {inFlight.current=false;if(alive.current)setBusy(false);}
  }

  const conflict=!!error&&typeof error==='object'&&'code' in error&&error.code==='CONFLICT';
  const conflictData=conflict&&error&&typeof error==='object'&&'current' in error?error as {current:unknown;unsaved?:unknown}:null;
  const current=conflictData?.current as Project|undefined,unsaved=conflictData?.unsaved as {command?:Record<string,unknown>;projectId?:string}|undefined;
  const target=(unsaved?.command&&(unsaved.command.taskId??unsaved.command.phaseId??unsaved.command.milestoneId??unsaved.command.blockerId))??unsaved?.projectId;
  const latest=current?.records?.find(row=>row.id===target)?.content;
  return {busy:busy||!!retry&&!conflict,error,run,clear:()=>{setError(null);setRetry(null);setFinishing(false);},feedback:finishing&&retry?<div className="notice"><p>Your change has been received and is being prepared.</p><Button variant="secondary" busy={busy} onClick={()=>void run('Your change is ready',retry,retry,retryAfter.current)}>Check progress</Button></div>:error?<div className="stack"><ErrorNotice error={error} {...(retry&&!conflict?{retry:()=>void run('Your change is saved',retry,retry,retryAfter.current)}:{})}/>{conflict&&<><div className="notice"><strong>Latest saved details</strong>{latest?Object.entries(latest).filter(([,value])=>typeof value==='string'&&value).map(([key,value])=><p className="preserve-lines" key={key}>{String(value)}</p>):<p>Review the refreshed record before saving your retained changes.</p>}</div><Button variant="secondary" busy={busy} onClick={async()=>{if(inFlight.current)return;inFlight.current=true;setBusy(true);try{await reloadProjects();options.onReview?.(conflictData?.current);setError(null);setRetry(null);}catch{notify('We could not refresh this change. Please try again.','error');}finally{inFlight.current=false;if(alive.current)setBusy(false);}}}>I’ve reviewed the latest changes</Button></>}</div>:null};
}
export function usePlanningAction(project:Project,holdReview=false) {
  const {client}=useApp(),reviewed=useRef(project.pin);const action=useAction({onReview:current=>{if(current&&typeof current==='object'&&'pin' in current)reviewed.current=(current as Project).pin;}});
  function execute(command:PlanningIntent,label:string,options:{content?:PlanningPrivateContent;outcome?:string;after?:()=>void}={}) {
    const operationId=crypto.randomUUID();return action.run(label,()=>client.planning.execute({projectId:project.graph.project.id,reviewed:holdReview?reviewed.current:project.pin,command,operationId,...(options.content?{content:options.content}:{}),...(options.outcome!==undefined?{outcome:options.outcome}:{})}),()=>client.planning.resume(operationId),options.after);
  }
  return {...action,execute};
}
export function useReport(projectId:string|undefined) {
  const {client}=useApp();const [report,setReport]=useState<ReadableReporting|null>(null),[fresh,setFresh]=useState(false),[unavailable,setUnavailable]=useState(false),watch=useRef<{refocus:()=>void}|null>(null);
  useEffect(()=>{setReport(null);setFresh(false);setUnavailable(false);if(!projectId)return;const watcher=client.reporting.watch({kind:'project',projectId},state=>{setReport(state.value??state.lastCalculated);setFresh(state.status==='current');setUnavailable(state.status!=='current'&&state.reason==='disconnected');});watch.current=watcher;return()=>{watch.current=null;watcher.stop();};},[client,projectId]);
  return {report,fresh,unavailable,retry:()=>watch.current?.refocus(),result:report?.components[0]?.result};
}
export function Section({title,description,actions,children}:{title:string;description?:string;actions?:ReactNode;children:ReactNode}) { return <section className="card stack"><div className="section-heading"><div><h2>{title}</h2>{description&&<p className="muted">{description}</p>}</div>{actions}</div>{children}</section>; }
export function orderedPhases(project:Project):PlanningPhase[]{return [...project.graph.phases].sort((a,b)=>a.displayOrder-b.displayOrder||a.id.localeCompare(b.id));}
