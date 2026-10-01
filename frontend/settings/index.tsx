'use client';
import './settings.css';
import { useEffect, useMemo, useRef, useState } from 'react';
import { User, Users, Shield, SlidersHorizontal, Database, RefreshCw, Laptop, KeyRound, ArrowRight } from 'lucide-react';
import { useApp } from '../shared/context';
import { Avatar, Badge, Button, EmptyState, ErrorNotice, Modal, PageHead, Spinner } from '../shared/ui';
import { PasswordChangePanel, createHandoffLink } from '../identity';
import { ShareLink } from '../identity/components';
import { PeopleSettings } from './people';
import { RolesSettings, TeamsSettings } from './roles-teams';
import { DataSettings, RestorePanel, WorkspaceSettings } from './data';
import { MaintenanceSettings } from './maintenance';
import { dateLabel, LoadState, Panel, SecureConfirm, SettingsRefresh, useSettingsLoad, isFinishing } from './common';
export { RestorePanel } from './data';
function AccountSettings() {
  const { client, directory, signOut, navigate, reloadDirectory, openApprovals, notify } = useApp(); const [forget, setForget] = useState(false), [newDevice, setNewDevice] = useState(false), [changePassword, setChangePassword] = useState(false);
  const own = directory?.people.find(p => p.accountId === directory.accountId), devices = directory?.devices.filter(d => d.accountId === directory.accountId && d.active) ?? [];
  // The directory already verifies this profile in the Worker. Reuse it so a
  // separate read cannot overlap the approval dialog's password confirmation.
  return <><PageHead title="Your account" description="Your identity and security in this workspace." eyebrow="Settings"/><Panel title="Profile">{own ? <div className="settings-profile"><Avatar selection={own.avatar} name={own.displayName} size={72}/><div><h3>{own.displayName}</h3><p className="muted">{directory?.workspaceName}</p>{own.owner && <Badge>Owner</Badge>}</div></div> : <EmptyState title="Your profile could not be loaded" description="Refresh your workspace to try again." action={<Button variant="secondary" onClick={()=>void reloadDirectory().catch(()=>notify('Your profile could not be refreshed. Please try again.','error'))}>Refresh profile</Button>}/>}</Panel>
    <Panel title="Password" description="Change your password while keeping access to your encrypted work." actions={<Button variant="secondary" onClick={()=>setChangePassword(true)}>Change password</Button>}/>
    {changePassword&&<Modal open onClose={()=>setChangePassword(false)} title="Change your password"><PasswordChangePanel client={client} showHeading={false} onChanged={async()=>{await reloadDirectory();setChangePassword(false);}}/></Modal>}
    <Panel title="Approved devices" description="Your current browser is approved to open your workspace."><div className="settings-row"><div className="person-cell"><Laptop size={24}/><div><strong>This browser</strong><p className="muted">{devices.some(d => d.current) ? 'Approved and unlocked' : 'Device approval required'}</p></div></div><Badge tone="success">Current</Badge></div>{devices.length > 1 && <p className="muted">{devices.length - 1} other approved {devices.length === 2 ? 'device' : 'devices'}.</p>}<p className="muted">On a shared computer, forget this browser when you leave. You will need to approve it again to return.</p><Button variant="secondary" onClick={() => setForget(true)}>Forget this browser</Button></Panel>
    <Panel title="Use another device" description="Open a private sign-in link on your other device, then enter your password and approve it here."><Button variant="secondary" onClick={()=>setNewDevice(true)}>Create sign-in link</Button></Panel>
    {newDevice&&directory&&<Modal open onClose={()=>setNewDevice(false)} title="Use another device" footer={<Button variant="secondary" onClick={()=>setNewDevice(false)}>Done</Button>}><ShareLink link={createHandoffLink({kind:'signin',workspaceId:directory.workspaceId,accountId:directory.accountId})} title="Your private sign-in link" description="Keep this link private and open it on your own device. Your password and a separate device approval are still required."/></Modal>}
    <Panel title={directory?.isOwner?'Access requests':'My device requests'} description={directory?.isOwner?'Review a private request or continue an approval you started on this device.':'Approve your other browser or device, or continue an approval you started here.'}><Button variant="secondary" onClick={()=>openApprovals()}>{directory?.isOwner?'Review access requests':'Review my device requests'} <ArrowRight size={16}/></Button></Panel>
    {directory?.isOwner && <Panel title="Recovery kit" description="Your personal recovery kit lets you regain access if you lose your password."><div className="notice"><KeyRound size={21}/><p>Keep the 24-word phrase and its workspace details somewhere private. It cannot be displayed again here. Each Owner has their own recovery kit.</p></div><p className="muted">If another person cannot sign in, create a private recovery link from their entry in People.</p><Button variant="secondary" onClick={() => navigate({page:'settings',section:'people'})}>Help someone sign in <ArrowRight size={15}/></Button></Panel>}
    {forget && directory && <SecureConfirm open onClose={() => setForget(false)} title="Forget this browser?" description="Local keys and remembered sign-in details for this account will be removed. This does not delete your workspace or revoke other devices." confirmLabel="Forget and sign out" danger perform={async () => { await client.auth.forget({workspaceId:directory.workspaceId,accountId:directory.accountId,deviceId:directory.deviceId}); await signOut(); }}/>}</>;
}
type PendingItem = { key: string; operationId: string; label: string; detail: string; returnsCompletedReceipt: boolean; resume: () => Promise<unknown> };
function InterruptedSaves() {
  const { client, directory, reloadDirectory, reloadProjects, notify } = useApp(); const [checked,setChecked]=useState(false);
  const data = useSettingsLoad(async () => {
    if(!checked)return {items:[] as PendingItem[],unavailable:false};
    const groups = await Promise.allSettled([client.roles.pending(),client.accessChanges.pending(),client.teams.pending(),client.reporting.pending(),client.lifecycle.pending(),client.upgrades.pending(),client.restoration.pending()]);
    const names = ['Role change','Access change','Team change','Reporting change','Privacy request','Workspace update','Recovery verification'];
    const controllers = [client.roles,client.accessChanges,client.teams,client.reporting,client.lifecycle,client.upgrades,client.restoration];
    const items: PendingItem[] = [];
    for (let i = 0; i < groups.length; i++) {
      const group = groups[i]!; if (group.status === 'rejected') continue;
      for (const row of group.value) {
        if (typeof row !== 'string' && 'workspaceId' in row && row.workspaceId !== directory?.workspaceId) continue;
        const operationId = typeof row === 'string' ? row : row.operationId;
        const name = typeof row !== 'string' && 'targetAccountId' in row ? directory?.people.find(p => p.accountId === row.targetAccountId)?.displayName : undefined;
        items.push({key:`${i}:${operationId}`,operationId,label:names[i]!,detail:name ? `For ${name}` : 'Saved on this browser',returnsCompletedReceipt:i===3,resume:()=>controllers[i]!.resume(operationId)});
      }
    }
    return {items,unavailable:groups.some(g=>g.status==='rejected')};
  },[checked]); const [selected, setSelected] = useState<PendingItem>();
  return <Panel title="Check interrupted saves" description="If a connection stopped during saving, check the saved attempt before trying again." actions={<Button variant="secondary" busy={checked&&data.loading} onClick={()=>{if(checked)data.reload();else setChecked(true);}}>Check saved attempts</Button>}>
    {checked&&<LoadState loading={data.loading} error={data.error} retry={data.reload}>{data.value?.unavailable&&<div className="notice notice-warning">Some saved attempts could not be checked.<Button variant="ghost" onClick={data.reload}>Try again</Button></div>}{data.value?.items.length?<><p className="muted">These attempts may already have completed. Check an attempt to confirm its result or finish saving it.</p><div className="settings-list">{data.value.items.map(item=><div className="settings-row" key={item.key}><div><strong>{item.label}</strong><p className="muted">{item.detail}</p></div><Button variant="secondary" onClick={()=>setSelected(item)}>Check and finish</Button></div>)}</div></>:!data.value?.unavailable&&<p className="muted">No saved attempts on this browser.</p>}</LoadState>}
    {selected&&<SecureConfirm open onClose={()=>setSelected(undefined)} title={`Check ${selected.label.toLowerCase()}?`} description="This may already be saved. Check its result and finish the original change if needed." confirmLabel="Check and finish" perform={async()=>{const result=await selected.resume();const completed=selected.returnsCompletedReceipt||!!result&&typeof result==='object'&&'state'in result&&result.state==='completed';if(completed)notify('The saved change is complete.','success');else if(!isFinishing(result))throw new Error('Saved change completion was not confirmed');return result;}} onDone={async()=>{await reloadDirectory();await reloadProjects();}}/>}
  </Panel>;
}
const sections = [
  {id:'account',label:'Your account',icon:User,owner:false}, {id:'workspace',label:'Workspace',icon:SlidersHorizontal,owner:false},
  {id:'people',label:'People',icon:Users,owner:false}, {id:'teams',label:'Teams',icon:Users,owner:false},
  {id:'roles',label:'Roles & permissions',icon:Shield,owner:true}, {id:'data',label:'Data & privacy',icon:Database,owner:false},
  {id:'maintenance',label:'Workspace updates',icon:RefreshCw,owner:true},
];
export function SettingsArea({section='workspace'}:{section?:string}) {
  const {client,directory,navigate,reloadDirectory}=useApp();const [version,setVersion]=useState(0);
  const refresh=useMemo(()=>({version,refresh:()=>setVersion(v=>v+1)}),[version]);
  useEffect(()=>client.auth.onClear(()=>setVersion(v=>v+1)),[client]);
  const current = section==='general'?'workspace':section==='profile'?'account':section==='security'?'account':section==='members'?'people':section==='permissions'?'roles':section;
  const navigation = useRef<HTMLElement>(null);
  useEffect(() => {
    const nav = navigation.current; if (!nav) return;
    const revealCurrent = () => {
      if (nav.scrollWidth <= nav.clientWidth) return;
      const active = nav.querySelector<HTMLElement>('[aria-current="page"]'); if (!active) return;
      const viewport = nav.getBoundingClientRect(), item = active.getBoundingClientRect();
      // Scroll this row alone. scrollIntoView would also move the page away
      // from its heading when following a settings link or resizing a window.
      if (item.left < viewport.left) nav.scrollLeft += item.left - viewport.left - 8;
      else if (item.right > viewport.right) nav.scrollLeft += item.right - viewport.right + 8;
    };
    revealCurrent();
    const observer = new ResizeObserver(revealCurrent); observer.observe(nav);
    return () => observer.disconnect();
  }, [current, directory?.isOwner, directory?.restoreQuarantine]);

  if (!directory) return <div role="status" className="settings-loading"><Spinner/> Opening workspace settings…</div>;
  if (directory.restoreQuarantine) return <SettingsRefresh.Provider value={refresh}><div className="settings-content"><PageHead title="Review recovered workspace" description="The workspace stays closed until its recovered content has been checked."/>{directory.isOwner && directory.activeRestore ? <RestorePanel restoreId={directory.activeRestore.restoreId} onDone={reloadDirectory}/> : <EmptyState title="An Owner needs to review this workspace" description="Current security changes remain in place while the review is completed." action={<Button variant="secondary" onClick={()=>void reloadDirectory()}>Check again</Button>}/>}</div></SettingsRefresh.Provider>;
  const selected=sections.find(item=>item.id===current), allowed=selected && (!selected.owner||directory.isOwner);
  return <SettingsRefresh.Provider value={refresh}><div className="settings-layout"><nav ref={navigation} className="settings-nav" aria-label="Settings sections">{sections.filter(item=>!item.owner||directory.isOwner).map(item=><button type="button" key={item.id} className={item.id===current?'active':''} aria-current={item.id===current?'page':undefined} onClick={()=>navigate({page:'settings',section:item.id})}><item.icon size={18}/>{item.label}</button>)}</nav><div className="settings-content">
    {directory.lifecycle==='pending_deletion'&&<div className="notice notice-warning"><div><strong>Workspace deletion is scheduled</strong><p>Ordinary work is read-only. Deletion is due {dateLabel(directory.deletion?.deleteAfter)}.</p></div><Button variant="secondary" onClick={()=>navigate({page:'settings',section:'data'})}>Review deletion</Button></div>}
    {directory.licenceState!=='active'&&<div className="notice notice-warning">Your workspace licence currently restricts access. You can still review your account and download available work.</div>}
    {!allowed?<EmptyState title={current==='integrations'?'Integrations are not available':'Settings unavailable'} description="You can manage your workspace using the available settings." action={<Button variant="secondary" onClick={()=>navigate({page:'settings',section:'workspace'})}>Back to workspace settings <ArrowRight size={16}/></Button>}/>:current==='account'?<AccountSettings/>:current==='people'?<PeopleSettings/>:current==='teams'?<TeamsSettings/>:current==='roles'?<RolesSettings/>:current==='data'?<DataSettings/>:current==='maintenance'?<MaintenanceSettings/>:<WorkspaceSettings/>}{allowed&&<InterruptedSaves/>}
  </div></div></SettingsRefresh.Provider>;
}
