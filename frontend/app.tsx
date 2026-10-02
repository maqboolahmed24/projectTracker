'use client';
import { Component, useCallback, useEffect, useRef, useState, type ErrorInfo, type ReactNode } from 'react';
import { AlertCircle, ArrowRight, Check, CheckCircle2, ChevronDown, CircleHelp, Info, Folder, Home, Inbox, ListTodo, LogOut, Menu, Monitor, Moon, Search, Settings, ShieldCheck, Sun, X } from 'lucide-react';
import { IdentityGateway, IdentityApprovals, parseHandoff } from './identity';
import { readApprovalRequests } from './identity/IdentityApprovals';
import { useIdentityPolling } from './identity/useIdentityPolling';
import { WorkArea } from './work';
import { SettingsArea } from './settings';
import { AppContext, type AppRoute, type Theme } from './shared/context';
import { createClient, type ClientRuntime } from './shared/runtime';
import { rememberVerifiedProfile } from './shared/remembered-profile';
import { Avatar, Badge, Button, EmptyState, ErrorNotice, Input, Modal, Spinner } from './shared/ui';
import { WorkspaceGuidance } from './shared/guidance';
import { projectName, TaskTitle } from './work/shared';
import './shared/polish.css';
import type { WorkspaceDirectory } from '../src/client/directory-crypto.js';
import type { ReadablePlanning } from '../src/client/planning-crypto.js';

let opened:Promise<ClientRuntime>|undefined;
let launchMounted=false;
function currentRoute():AppRoute{
  const parts=location.pathname.split('/').filter(Boolean);
  if(parts[0]==='projects'&&parts[1]){const query=new URLSearchParams(location.search),taskId=query.get('task'),phaseId=query.get('phase');return {page:'project',projectId:parts[1],tab:parts[2]??'overview',...(taskId?{taskId}:phaseId?{phaseId}:{})};}
  if(parts[0]==='settings')return {page:'settings',section:parts[1]??'general'};
  if(parts[0]==='my-work')return {page:'my-work',tab:new URLSearchParams(location.search).get('view')??'assigned'};
  if(parts[0]==='projects'||parts[0]==='inbox')return {page:parts[0]};
  return {page:'home'};
}
function routePath(route:AppRoute){if(route.page==='home')return '/';if(route.page==='project')return `/projects/${route.projectId}/${route.tab??'overview'}${route.taskId?'?task='+encodeURIComponent(route.taskId):route.phaseId?'?phase='+encodeURIComponent(route.phaseId):''}`;if(route.page==='settings')return '/settings/'+(route.section??'general');if(route.page==='my-work'&&route.tab)return '/my-work?view='+encodeURIComponent(route.tab);return '/'+route.page;}
function preference():Theme{try{const p=localStorage.getItem('ukda.appearance');if(p==='light'||p==='dark'||p==='system')return p;}catch{}return 'system';}
function applyTheme(value:Theme){document.documentElement.dataset.theme=value==='system'?(matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light'):value;}
class SafeBoundary extends Component<{children:ReactNode},{failed:boolean}>{state={failed:false};static getDerivedStateFromError(){return {failed:true};}componentDidCatch(_error:Error,_info:ErrorInfo){}render(){return this.state.failed?<div className="startup-error"><EmptyState title="Let’s try that again." description="This page could not open. Reload to return to your saved work." action={<Button onClick={()=>location.reload()}>Reload Maqbool</Button>}/></div>:this.props.children;}}
export default function Product(){return <SafeBoundary><Application/></SafeBoundary>;}

function Application(){
  const [client,setClient]=useState<ClientRuntime|null>(null),[startupError,setStartupError]=useState<unknown>(null),[theme,setThemeState]=useState<Theme>('system'),[systemDark,setSystemDark]=useState(false),[route,setRoute]=useState<AppRoute>({page:'home'});
  const [directory,setDirectory]=useState<WorkspaceDirectory|null>(null),[projects,setProjects]=useState<ReadablePlanning[]>([]),[signedIn,setSignedIn]=useState(false),[idleSession,setIdleSession]=useState<string|null>(null),[loading,setLoading]=useState(false),[loadError,setLoadError]=useState<unknown>(null);
  const [searchOpen,setSearchOpen]=useState(false),[search,setSearch]=useState(''),[menu,setMenu]=useState(false),[mobileNavigation,setMobileNavigation]=useState(false),[help,setHelp]=useState(false),[workspaceMenu,setWorkspaceMenu]=useState(false);
  const sidebar=useRef<HTMLElement>(null),menuTrigger=useRef<HTMLButtonElement>(null),navigationFocus=useRef<'main'|'trigger'>('trigger');
  const navigationOpen=signedIn&&mobileNavigation&&menu;
  const [handoff,setHandoff]=useState<string>(),[approval,setApproval]=useState<{id:number;handoff?:string;onDone?:()=>void|Promise<void>}>(),[toasts,setToasts]=useState<{id:number;message:string;tone:string}[]>([]),[online,setOnline]=useState(true);
  const approvalId=useRef(0),[approvalCount,setApprovalCount]=useState(0);
  const openApprovals=useCallback((handoff?:string,onDone?:()=>void|Promise<void>)=>{setMenu(false);setApproval({id:++approvalId.current,...(handoff?{handoff}:{}),...(onDone?{onDone}:{})});},[]);
  const directoryRead=useRef<{stamp:number;promise:Promise<WorkspaceDirectory>}|null>(null);
  const epoch=useRef(0),clientRef=useRef<ClientRuntime|null>(null),heading=useRef<HTMLElement>(null),notificationId=useRef(0),toastTimers=useRef<ReturnType<typeof setTimeout>[]>([]);
  const notify=useCallback((message:string,tone:'success'|'error'|'info'='success')=>{const id=++notificationId.current;setToasts(old=>[...old.slice(-2),{id,message,tone}]);toastTimers.current.push(setTimeout(()=>setToasts(old=>old.filter(t=>t.id!==id)),5500));},[]);
  const navigate=useCallback((value:AppRoute|string)=>{
    const path=typeof value==='string'?value:routePath(value);if(!path.startsWith('/')||path.startsWith('//'))return;
    const before=currentRoute();history.pushState(null,'',path);const next=currentRoute();
    const sameSurface=before.page==='project'&&next.page==='project'&&before.projectId===next.projectId&&(before.tab??'overview')===(next.tab??'overview');
    const dialogChange=sameSurface&&(before.taskId!==next.taskId||before.phaseId!==next.phaseId);
    navigationFocus.current='main';setRoute(next);setMenu(false);setSearchOpen(false);setSearch('');
    if(!dialogChange){heading.current?.focus({preventScroll:true});window.scrollTo({top:0,behavior:'instant'});}
  },[]);
  const setTheme=useCallback((value:Theme)=>{setThemeState(value);applyTheme(value);try{localStorage.setItem('ukda.appearance',value);}catch{}},[]);
  useEffect(()=>{
    const media=matchMedia('(max-width: 700px)');
    const change=()=>{setMobileNavigation(media.matches);if(!media.matches)setMenu(false);};
    change();media.addEventListener('change',change);
    return()=>media.removeEventListener('change',change);
  },[]);
  useEffect(()=>{
    if(!navigationOpen)return;
    const panel=sidebar.current;if(!panel)return;
    const previousOverflow=document.documentElement.style.overflow;
    document.documentElement.style.overflow='hidden';
    navigationFocus.current='trigger';
    // Move focus after the drawer commits, without overriding a keyboard
    // action the person already made inside it.
    const initialFocus=requestAnimationFrame(()=>{
      if(!panel.isConnected||panel.inert||panel.contains(document.activeElement))return;
      (panel.querySelector<HTMLElement>('[aria-current="page"]')??panel.querySelector<HTMLElement>('a[href]'))?.focus({preventScroll:true});
    });
    const keys=(event:KeyboardEvent)=>{
      if(document.querySelector('dialog[open]'))return;
      if(event.key==='Escape'){event.preventDefault();setMenu(false);return;}
      if(event.key!=='Tab')return;
      const controls=Array.from(panel.querySelectorAll<HTMLElement>('a[href],button:not(:disabled),[tabindex="0"]')).filter(element=>element.tabIndex>=0&&element.getClientRects().length>0);
      const first=controls[0],last=controls.at(-1);if(!first||!last)return;
      if(event.shiftKey&&(document.activeElement===first||!panel.contains(document.activeElement))){event.preventDefault();last.focus();}
      else if(!event.shiftKey&&(document.activeElement===last||!panel.contains(document.activeElement))){event.preventDefault();first.focus();}
    };
    document.addEventListener('keydown',keys);
    return()=>{
      cancelAnimationFrame(initialFocus);
      document.removeEventListener('keydown',keys);
      document.documentElement.style.overflow=previousOverflow;
      if(document.querySelector('dialog[open]'))return;
      const target=navigationFocus.current==='main'||!matchMedia('(max-width: 700px)').matches?heading.current:menuTrigger.current;
      target?.focus({preventScroll:true});
    };
  },[navigationOpen]);

  useEffect(()=>{
    let alive=true;const appearance=preference();setThemeState(appearance);applyTheme(appearance);setRoute(currentRoute());setOnline(navigator.onLine);
    const receiveHandoff=()=>{if(!location.hash.startsWith('#access='))return;const link=location.href;history.replaceState(null,'',location.pathname+location.search);try{const incoming=parseHandoff(link);if(incoming.kind==='approve'){openApprovals(link);if(clientRef.current?.auth.current()?.localAccess==='unlocked'&&clientRef.current.auth.current()?.session.workspaceId===incoming.workspaceId){navigate({page:'settings',section:'security'});return;}}else setApproval(undefined);epoch.current++;setDirectory(null);setProjects([]);setSearch('');setSearchOpen(false);setHandoff(link);setSignedIn(false);}catch{epoch.current++;setDirectory(null);setProjects([]);setSearch('');setSearchOpen(false);setHandoff(link);setSignedIn(false);}};
    receiveHandoff();
    const ready=(opened??=createClient()).then(value=>{if(alive){clientRef.current=value;setClient(value);}return value;}).catch(error=>{opened=undefined;if(alive)setStartupError(error);throw error;});
    const launchReady=ready.catch(()=>{});
    if(!launchMounted){launchMounted=true;const url='/brand/maqbool-launch.js';void import(/* webpackIgnore:true */url).then(module=>module.mountMaqboolLaunch({ready:launchReady,appRoot:document.getElementById('maqbool-root'),theme:appearance==='system'?'auto':appearance,minDuration:1800,maxDuration:8000,stylesheetUrl:'/brand/maqbool-launch.css',logoTarget:'.identity-brand img, .wordmark img'})).catch(()=>{});}
    const pop=()=>{navigationFocus.current='main';setRoute(currentRoute());setMenu(false);},connection=()=>setOnline(navigator.onLine),keys=(event:KeyboardEvent)=>{if((event.metaKey||event.ctrlKey)&&event.key==='k'){event.preventDefault();if(clientRef.current?.auth.current()?.localAccess==='unlocked'){setMenu(false);setSearchOpen(true);}}},visibility=()=>{if(document.visibilityState==='visible'&&clientRef.current?.auth.current()?.localAccess==='unlocked')void clientRef.current.auth.refresh().catch(()=>{});};
    window.addEventListener('hashchange',receiveHandoff);window.addEventListener('popstate',pop);window.addEventListener('online',connection);window.addEventListener('offline',connection);window.addEventListener('keydown',keys);document.addEventListener('visibilitychange',visibility);
    return()=>{alive=false;window.removeEventListener('hashchange',receiveHandoff);window.removeEventListener('popstate',pop);window.removeEventListener('online',connection);window.removeEventListener('offline',connection);window.removeEventListener('keydown',keys);document.removeEventListener('visibilitychange',visibility);toastTimers.current.forEach(clearTimeout);};
  },[]);
  useEffect(()=>{const media=matchMedia('(prefers-color-scheme: dark)'),change=()=>{setSystemDark(media.matches);applyTheme(theme);};change();media.addEventListener('change',change);return()=>media.removeEventListener('change',change);},[theme]);
  useEffect(()=>{if(!client)return;return client.auth.onClear(()=>{epoch.current++;setDirectory(null);setProjects([]);setSignedIn(false);setApprovalCount(0);setIdleSession(null);setSearch('');setSearchOpen(false);setLoadError(null);setLoading(false);});},[client]);
  const readProjects=useCallback(async(value:WorkspaceDirectory)=>{
    if(!client||value.restoreQuarantine)return [];const result:ReadablePlanning[]=[];
    for(let i=0;i<value.projectIds.length;i+=3)result.push(...await Promise.all(value.projectIds.slice(i,i+3).map(id=>client.planning.read(id))));
    return result;
  },[client]);
  const readDirectory=useCallback(()=>{if(!client)throw new Error('AUTH_REQUIRED');const stamp=epoch.current;if(directoryRead.current?.stamp===stamp)return directoryRead.current.promise;const sessionId=client.auth.current()?.session.sessionId;const promise=client.directory.current().then(async value=>{await rememberVerifiedProfile(client,value,sessionId,()=>stamp===epoch.current);return value;}).finally(()=>{if(directoryRead.current?.promise===promise)directoryRead.current=null;});directoryRead.current={stamp,promise};return promise;},[client]);
  const reloadDirectory=useCallback(async()=>{if(!client)return;const stamp=epoch.current;const value=await readDirectory();if(stamp===epoch.current&&client.auth.current()?.localAccess==='unlocked'){setDirectory(value);setIdleSession(client.auth.current()!.session.sessionId);setSignedIn(true);}},[client,readDirectory]);
  const reloadProjects=useCallback(async()=>{if(!client)return;const stamp=epoch.current;const value=await readDirectory(),rows=await readProjects(value);if(stamp!==epoch.current)return;setDirectory(value);setProjects(rows);},[client,readProjects,readDirectory]);
  const enter=useCallback(async()=>{
    if(!client)return;setIdleSession(client.auth.current()?.session.sessionId??null);setSignedIn(true);setLoading(true);setLoadError(null);setHandoff(undefined);const stamp=epoch.current;
    try{const value=await readDirectory();if(stamp!==epoch.current)return;setDirectory(value);const rows=await readProjects(value);if(stamp!==epoch.current)return;setProjects(rows);if(approval?.handoff&&parseHandoff(approval.handoff).workspaceId!==value.workspaceId)setApproval(undefined);if(approval?.handoff&&parseHandoff(approval.handoff).workspaceId===value.workspaceId)navigate({page:'settings',section:'security'});else if(value.restoreQuarantine)navigate({page:'settings',section:'data'});}
    catch(error){if(stamp===epoch.current){setProjects([]);setLoadError(error);}}
    finally{if(stamp===epoch.current)setLoading(false);}
  },[client,readProjects,readDirectory,navigate,approval]);
  const signOut=useCallback(async()=>{if(!client)return;setApproval(undefined);setHandoff(undefined);try{await client.auth.logout();navigate('/');}catch(error){notify('Your work is locked on this device. Reconnect to finish signing out.','error');setStartupError(null);}},[client,navigate,notify]);
  useEffect(()=>{
    if(!client||!idleSession)return;const idleLimit=30*60*1000;let lastActivity=Date.now(),ended=false,timer:ReturnType<typeof setTimeout>;
    const check=()=>{if(ended)return;const remaining=idleLimit-(Date.now()-lastActivity);if(remaining<=0){ended=true;void client.auth.invalidateSession().catch(()=>{});notify('Your workspace locked after 30 minutes without activity. Sign in to continue.','info');return;}clearTimeout(timer);timer=setTimeout(check,remaining);};
    const activity=(event:Event)=>{if(!event.isTrusted||ended)return;if(Date.now()-lastActivity>=idleLimit){check();return;}lastActivity=Date.now();check();};
    for(const event of ['pointerdown','pointermove','keydown'])window.addEventListener(event,activity,{capture:true,passive:true});
    document.addEventListener('visibilitychange',check);window.addEventListener('focus',check);check();
    return()=>{ended=true;clearTimeout(timer);for(const event of ['pointerdown','pointermove','keydown'])window.removeEventListener(event,activity,true);document.removeEventListener('visibilitychange',check);window.removeEventListener('focus',check);};
  },[client,idleSession,notify]);
  useEffect(()=>{if(!client||!signedIn)return;const timer=setInterval(()=>{if(document.visibilityState==='visible'&&navigator.onLine)void client.auth.refresh().catch(()=>{});},30000);return()=>clearInterval(timer);},[client,signedIn]);
  useEffect(()=>{if(!client||!signedIn||loading)return;let refreshing=false;const refresh=()=>{if(refreshing||document.visibilityState!=='visible'||!navigator.onLine)return;refreshing=true;void reloadProjects().catch(()=>{}).finally(()=>{refreshing=false;});};const timer=setInterval(refresh,60000);window.addEventListener('focus',refresh);return()=>{clearInterval(timer);window.removeEventListener('focus',refresh);};},[client,signedIn,loading,reloadProjects]);
  const approvalDiscovery=useIdentityPolling({enabled:!!client&&signedIn&&!!directory&&!loading&&!approval&&!directory.restoreQuarantine,scope:`requests:${idleSession??''}:${directory?.isOwner??false}`,poll:async isCurrent=>{if(!client||!directory)return;const rows=await readApprovalRequests(client,directory.isOwner);if(isCurrent())setApprovalCount(rows.length);}});
  const approvalRoute=routePath(route),lastApprovalRoute=useRef(approvalRoute);
  useEffect(()=>{if(approvalDiscovery.error)setApprovalCount(0);},[approvalDiscovery.error]);
  useEffect(()=>{const moved=lastApprovalRoute.current!==approvalRoute;lastApprovalRoute.current=approvalRoute;if(moved&&approvalDiscovery.paused&&signedIn&&document.visibilityState==='visible'&&navigator.onLine)approvalDiscovery.retry();},[approvalRoute,approvalDiscovery.paused,signedIn]);
  useEffect(()=>{const resume=()=>{if(approvalDiscovery.paused&&signedIn&&document.visibilityState==='visible'&&navigator.onLine)approvalDiscovery.retry();};window.addEventListener('focus',resume);document.addEventListener('visibilitychange',resume);return()=>{window.removeEventListener('focus',resume);document.removeEventListener('visibilitychange',resume);};},[approvalDiscovery.paused,signedIn]);
  const isDark=theme==='dark'||theme==='system'&&systemDark;
  const startupCode=typeof startupError==='object'&&startupError&&'code'in startupError?String(startupError.code):'';
  const me=directory?.people.find(p=>p.accountId===directory.accountId);
  const titles:Record<AppRoute['page'],string>={home:'Home',projects:'Projects','my-work':'My work',inbox:'Inbox',project:'Projects',settings:'Settings'};
  const query=search.trim().toLocaleLowerCase();
  const results=query?projects.flatMap(project=>project.records.filter(r=>['project','task','phase'].includes(r.kind)&&String(r.content.name??r.content.title??'').toLocaleLowerCase().includes(query)).map(record=>({project,record}))).slice(0,30):[];
  const currentProject=projects.find(project=>project.graph.project.id===route.projectId);
  const sectionNames:Record<string,string>={general:'Workspace',workspace:'Workspace',account:'Your account',security:'Your account',profile:'Your account',people:'People',members:'People',teams:'Teams',roles:'Roles & permissions',permissions:'Roles & permissions',data:'Data & privacy',maintenance:'Workspace updates'};
  const currentLabel=route.page==='project'?(route.tab??'overview').replace(/^./,letter=>letter.toUpperCase()):route.page==='settings'?sectionNames[route.section??'general']??'Settings':titles[route.page];
  return <div id="maqbool-root" className="product-root">
    {signedIn&&<a className="skip-link" href="#main-content">Skip to your work</a>}
    {!client?<div className="startup-error">{startupError?<EmptyState title={startupCode==='SECURE_ADDRESS_REQUIRED'?'Open Maqbool in another browser.':'We couldn’t open your workspace.'} description={startupCode==='SECURE_ADDRESS_REQUIRED'?'For this local address, use Chrome or Firefox. Safari needs the secure workspace address provided with your installation.':startupCode==='COOKIES_REQUIRED'?'Allow cookies for Maqbool in your browser, then try again.':'Check your connection and try again.'} action={<Button onClick={()=>location.reload()}>Try again</Button>}/>:<div className="initial-shell"/>}</div>:!signedIn?<><div className="entry-theme"><Button variant="ghost" aria-label={isDark?'Use light appearance':'Use dark appearance'} onClick={()=>setTheme(isDark?'light':'dark')}>{isDark?<Sun size={18}/>:<Moon size={18}/>}</Button></div><IdentityGateway client={client} onReady={enter} {...(handoff?{initialHandoff:handoff}:{})}/></>:<AppContext.Provider value={{client,directory,projects,reloadDirectory,reloadProjects,navigate,notify,theme,setTheme,signOut,openApprovals}}>
      {navigationOpen&&<button className="sidebar-scrim" aria-label="Close navigation" aria-hidden="true" tabIndex={-1} onClick={()=>setMenu(false)}/>}
      <aside id="workspace-navigation" ref={sidebar} className={`sidebar ${navigationOpen?'sidebar-open':''}`} role={mobileNavigation?'dialog':undefined} aria-label={mobileNavigation?'Workspace navigation':undefined} aria-modal={navigationOpen||undefined} aria-hidden={mobileNavigation&&!navigationOpen||undefined} inert={mobileNavigation&&!navigationOpen}><div className="sidebar-header"><a className="wordmark" href="/" onClick={e=>{e.preventDefault();navigate('/');}}><img src="/brand/assets/maqbool-symbol.svg" alt="" width={34} height={34}/><span>Maqbool</span></a><button type="button" className="icon-button sidebar-close" aria-label="Close navigation" onClick={()=>setMenu(false)}><X size={20}/></button></div>
        <button className="workspace-switch" aria-haspopup="dialog" aria-expanded={workspaceMenu} onClick={()=>{setMenu(false);setWorkspaceMenu(true);}}><span className="workspace-initial">{(directory?.workspaceName??'W').slice(0,1).toUpperCase()}</span><span><strong>{directory?.workspaceName??'Your workspace'}</strong><small>Your shared workspace</small></span><ChevronDown size={15}/></button>
        <nav aria-label="Main navigation">{([{page:'home',label:'Home',Icon:Home},{page:'projects',label:'Projects',Icon:Folder},{page:'my-work',label:'My work',Icon:ListTodo},{page:'inbox',label:'Inbox',Icon:Inbox}] as const).map(({page,label,Icon})=><a key={page} href={routePath({page})} className={`nav-link ${route.page===page||(page==='projects'&&route.page==='project')?'is-active':''}`} aria-current={route.page===page||(page==='projects'&&route.page==='project')?'page':undefined} onClick={e=>{e.preventDefault();navigate({page});}}><Icon size={19}/><span>{label}</span></a>)}</nav>
        <div className="sidebar-bottom">{approvalCount>0&&<button className="nav-link" aria-label={directory?.isOwner?'Review access requests':'Review my device requests'} onClick={()=>openApprovals()}><ShieldCheck size={19}/><span>{directory?.isOwner?'Access requests':'My device requests'}</span><Badge tone="info">{approvalCount}</Badge></button>}<button className={`nav-link ${route.page==='settings'?'is-active':''}`} aria-current={route.page==='settings'?'page':undefined} onClick={()=>navigate({page:'settings'})}><Settings size={19}/><span>Settings</span></button><button className="nav-link" onClick={()=>{setMenu(false);setHelp(true);}}><CircleHelp size={19}/><span>A little guidance</span></button><div className="sidebar-profile"><button onClick={()=>navigate({page:'settings',section:'security'})} className="profile-link"><Avatar name={me?.displayName??'Your profile'} selection={me?.avatar} size={36}/><span><strong>{me?.displayName??'Your profile'}</strong><small>{directory?.isOwner?'Owner':'Workspace member'}</small></span></button><button className="icon-button" title="Change appearance" aria-label="Change appearance" onClick={()=>setTheme(isDark?'light':'dark')}>{isDark?<Sun size={17}/>:<Moon size={17}/>}</button></div></div>
      </aside>
      <div className="workspace" inert={navigationOpen}><header className="topbar"><button ref={menuTrigger} className="icon-button mobile-menu" aria-label="Open navigation" aria-expanded={navigationOpen} aria-controls="workspace-navigation" onClick={()=>setMenu(true)}><Menu size={22}/></button><div className="breadcrumbs" aria-label="Current location"><span className="breadcrumb-workspace">{directory?.workspaceName??'Workspace'}</span><span aria-hidden="true">/</span>{currentProject&&<><span className="breadcrumb-project" title={projectName(currentProject)}>{projectName(currentProject)}</span><span aria-hidden="true">/</span></>}<strong className="breadcrumb-page">{currentLabel}</strong></div><div className="topbar-actions"><button type="button" className="icon-button" aria-label="Find your work" title="Find your work (⌘K / Ctrl+K)" aria-haspopup="dialog" aria-expanded={searchOpen} onClick={()=>setSearchOpen(true)}><Search size={20} aria-hidden="true"/></button><button className="icon-button" aria-label="Sign out" onClick={()=>void signOut()}><LogOut size={18}/></button></div></header>
        {!online&&<div className="status-banner" role="status">You’re offline. Reconnect to see changes and save your work.</div>}
        {directory?.licenceState!=='active'&&directory&&<div className="status-banner">Your workspace has limited access. You can still read and export your work.</div>}
        {directory?.deletion&&<div className="status-banner status-warning">This workspace is scheduled to be deleted on {new Date(directory.deletion.deleteAfter).toLocaleDateString()}. {directory.isOwner&&<Button variant="ghost" onClick={()=>navigate({page:'settings',section:'data'})}>Review deletion</Button>}</div>}
        {directory?.activeUpgrade&&<div className="status-banner">An update is in progress. Saved work stays available. {directory.isOwner&&<Button variant="ghost" onClick={()=>navigate({page:'settings',section:'maintenance'})}>Continue update</Button>}</div>}
        <main id="main-content" ref={heading} tabIndex={-1} className="main-content">
          {loading?<div className="loading-state" role="status"><Spinner/><span>Opening your workspace…</span></div>:loadError?<div className="stack"><ErrorNotice error={loadError} retry={()=>void enter()}/><Button variant="secondary" onClick={()=>void signOut()}>Back to sign in</Button></div>:directory&&<>
            {route.page==='settings'?<SettingsArea {...(route.section?{section:route.section}:{})}/>:directory.restoreQuarantine?<EmptyState title="Your workspace needs a quick review." description={directory.isOwner?'Review the restored workspace before everyone continues.':'An Owner is reviewing your restored workspace. Please come back shortly.'} action={directory.isOwner?<Button onClick={()=>navigate({page:'settings',section:'data'})}>Review workspace</Button>:<Button onClick={()=>void enter()}>Check again</Button>}/>:<WorkArea page={route.page} {...(route.projectId?{projectId:route.projectId}:{})} {...(route.taskId?{taskId:route.taskId}:{})} {...(route.phaseId?{phaseId:route.phaseId}:{})} {...(route.tab?{tab:route.tab}:{})}/>}
          </>}
        </main>
      </div>
      {approval&&directory&&!loading&&!loadError&&<Modal key={approval.id} open onClose={()=>{setApproval(undefined);approvalDiscovery.retry();}} title={directory.isOwner?'Approve access':'Approve my device'} description={directory.isOwner?'Help a teammate join, recover their account, or use a new device.':'Approve a new browser or device for your own account.'}><IdentityApprovals client={client} isOwner={directory.isOwner} people={directory.people} {...(approval.handoff?{initialHandoff:approval.handoff}:{})} onDone={async()=>{try{await reloadProjects();}catch{notify('Access is approved. Refresh the page to see the latest workspace.','error');}await approval.onDone?.();}}/></Modal>}
      <Modal open={searchOpen} onClose={()=>setSearchOpen(false)} title="Find your work" description="Search the projects, phases and tasks you can access.">
        <Input autoFocus aria-label="Search your work" placeholder="Search by name…" value={search} onChange={e=>setSearch(e.target.value)}/>
        <div className="search-results">
          {results.map(({project,record})=>{const task=record.kind==='task'?project.graph.tasks.find(task=>task.id===record.id):undefined;return <button key={record.id} onClick={()=>navigate({page:'project',projectId:project.graph.project.id,tab:record.kind==='project'?'overview':'work',...(record.kind==='task'?{taskId:record.id}:record.kind==='phase'?{phaseId:record.id}:{})})}><span className="search-result-icon">{task?.state==='done'?<CheckCircle2 size={18}/>:record.kind==='task'?<ListTodo size={18}/>:<Folder size={18}/>}</span><span><strong>{record.kind==='task'?<TaskTitle state={task?.state}>{String(record.content.title??record.content.name)}</TaskTitle>:String(record.content.title??record.content.name)}</strong><small>{record.kind==='phase'?'Phase':record.kind==='task'?'Task':'Project'}{record.kind!=='project'?` · ${projectName(project)}`:project.graph.project.archived?' · Archived':''}</small></span><ArrowRight size={16}/></button>;})}
          {query&&!results.length&&<div className="search-empty"><p className="muted">No matches. Try another name or browse your projects.</p><Button variant="ghost" onClick={()=>navigate({page:'projects'})}>Browse projects <ArrowRight size={15}/></Button></div>}
          {!query&&<><p className="search-section-label">{projects.length?'Quick access':'Your workspace'}</p>{projects.filter(project=>!project.graph.project.archived).slice(0,5).map(project=><button key={project.graph.project.id} onClick={()=>navigate({page:'project',projectId:project.graph.project.id})}><span className="search-result-icon"><Folder size={18}/></span><span><strong>{projectName(project)}</strong><small>Open project</small></span><ArrowRight size={16}/></button>)}<button onClick={()=>navigate({page:'my-work'})}><span className="search-result-icon"><ListTodo size={18}/></span><span><strong>My work</strong><small>Your tasks and review requests</small></span><ArrowRight size={16}/></button></>}
        </div>
      </Modal>
      <Modal open={workspaceMenu} onClose={()=>setWorkspaceMenu(false)} title={directory?.workspaceName??'Your workspace'}><div className="stack"><Button variant="secondary" onClick={()=>{setWorkspaceMenu(false);navigate({page:'settings'});}}>Workspace settings <ArrowRight size={16}/></Button><Button variant="ghost" onClick={()=>{setWorkspaceMenu(false);void signOut();}}>Switch profile or workspace</Button></div></Modal>
      {help&&<WorkspaceGuidance route={route} onClose={()=>setHelp(false)}/>}
    </AppContext.Provider>}
    <div className="toast-region" aria-live="polite" aria-atomic="false">{toasts.map(t=><div className={`toast toast-${t.tone}`} key={t.id}>{t.tone==='error'?<AlertCircle size={18}/>:t.tone==='info'?<Info size={18}/>:<Check size={18}/>}<span>{t.message}</span><button aria-label="Dismiss notification" onClick={()=>setToasts(old=>old.filter(x=>x.id!==t.id))}><X size={16}/></button></div>)}</div>
  </div>;
}
