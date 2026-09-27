'use client';
import { useContext, useEffect, useState } from 'react';
import { UserPlus, ShieldCheck, Search, Copy, Users } from 'lucide-react';
import type { DirectoryPerson } from '../../src/client/directory-crypto.js';
import type { ReadableRole } from '../../src/client/roles-controller.js';
import type { EnrolmentList } from '../../src/shared/enrolment-api.js';
import { useApp } from '../shared/context';
import { Avatar, Badge, Button, EmptyState, ErrorNotice, Field, Input, Modal, PageHead, Select } from '../shared/ui';
import { createHandoffLink } from '../identity';
import { useIdentityPolling } from '../identity/useIdentityPolling';
import { CheckOption, dateLabel, LoadState, Panel, PasswordRefresh, projectName, SecureConfirm, SettingsRefresh, toggleId, useSettingsAction, useSettingsLoad, workspaceEditable } from './common';
export async function readAllRoles(client: ReturnType<typeof useApp>['client']) {
  const all: ReadableRole[] = []; let afterRoleId: string | undefined;
  for (let page = 0; page < 100; page++) { const result = await client.roles.list({ ...(afterRoleId ? { afterRoleId } : {}), limit: 100 }); all.push(...result.roles); if (!result.nextRoleId) return all; if (result.nextRoleId === afterRoleId) throw new Error('CONFLICT'); afterRoleId = result.nextRoleId; }
  throw new Error('CONFLICT');
}
function ProjectChoices({ selected, onChange, disabled = false }: { selected: string[]; onChange: (value: string[]) => void; disabled?: boolean }) {
  const { projects } = useApp();
  return <fieldset className="settings-choice-list"><legend>Project access</legend><p className="muted">Only selected projects will be available. Team membership does not grant access.</p>{projects.length ? projects.map(project => <CheckOption key={project.graph.project.id} checked={selected.includes(project.graph.project.id)} disabled={disabled} onChange={value => onChange(toggleId(selected, project.graph.project.id, value))}>{projectName(project)}</CheckOption>) : <p className="muted">There are no projects yet.</p>}</fieldset>;
}
function PrivateLink({ title, link, expiresAt, onClose, revoke }: { title: string; link: string; expiresAt?: string; onClose: () => void; revoke?: () => Promise<unknown> }) {
  const action = useSettingsAction(), { notify } = useApp();
  return <Modal open onClose={onClose} title={title} description="Share this private link through a channel you already trust. The other person will still need your approval." footer={<>{revoke && <Button variant="danger" busy={action.busy} onClick={() => void action.run(revoke, 'The link has been revoked.').then(ok => { if (ok) onClose(); })}>Revoke link</Button>}<Button variant="secondary" onClick={onClose}>Done</Button></>}>
    <Field label="Private link" hint={expiresAt ? `Expires ${dateLabel(expiresAt)}. The link is shown only while this window is open.` : 'The link is shown only while this window is open.'}><Input readOnly value={link} onFocus={e => e.target.select()}/></Field><Button variant="secondary" onClick={() => void action.run(async () => { await navigator.clipboard.writeText(link); notify('Private link copied.', 'success'); })}><Copy size={16}/> Copy link</Button>{!!action.error && <ErrorNotice error={action.error}/>}
  </Modal>;
}
function InvitePerson({ roles, onClose }: { roles: ReadableRole[]; onClose: () => void }) {
  const { client, directory, reloadDirectory } = useApp(); const [name, setName] = useState(''), [roleId, setRoleId] = useState(roles.find(r => r.template === 'member')?.id ?? ''), [projects, setProjects] = useState<string[]>([]);
  const [link, setLink] = useState<{ value: string; expiresAt: string; operationId: string }>();
  const role = roles.find(r => r.id === roleId), owner = role?.template === 'owner';
  useEffect(() => client.auth.onClear(() => { setName(''); setLink(undefined); }), [client]);
  if (!directory) return null;
  if (link) return <PrivateLink title={`Invite ${name}`} link={link.value} expiresAt={link.expiresAt} onClose={onClose} revoke={() => client.enrolments.revokeJoin({ workspaceId: directory.workspaceId, operationId: link.operationId })}/>;
  return <SecureConfirm open layout="form" onClose={onClose} title="Invite a person" description="Choose their starting access, then share a private invitation link." confirmLabel="Create invitation" disabled={!name.trim() || !role} perform={async operationId => {
    const issued = await client.enrolments.issueJoin({ kind: owner ? 'join_owner' : 'join_member', roleId, projectIds: owner ? [] : projects, displayName: name.trim(), operationId });
    setLink({ value: createHandoffLink({ kind: 'join', workspaceId: directory.workspaceId, code: issued.code, genesisFingerprint: directory.genesisFingerprint }), expiresAt: issued.expiresAt, operationId: issued.operationId });
    await reloadDirectory(); return issued;
  }} onDone={() => false}>
    <Field label="Name"><Input value={name} maxLength={200} autoComplete="off" onChange={e => setName(e.target.value)}/></Field>
    <Field label="Role"><Select value={roleId} onChange={e => setRoleId(e.target.value)}>{roles.filter(r => r.state === 'active').map(r => <option key={r.id} value={r.id}>{r.displayName}</option>)}</Select></Field>
    {owner ? <div className="notice"><ShieldCheck size={20}/><p>Owners have equal authority over the workspace and all its projects. Each Owner creates their own recovery kit.</p></div> : <ProjectChoices selected={projects} onChange={setProjects}/>}
  </SecureConfirm>;
}
function ManagePerson({ person, roles, onClose }: { person: DirectoryPerson; roles: ReadableRole[]; onClose: () => void }) {
  const { client, directory, reloadDirectory, reloadProjects, signOut, notify } = useApp(); const [action, setAction] = useState<'access'|'suspend'|'remove'|'promote'|'reset'>('access');
  const [roleId, setRoleId] = useState(!person.owner && roles.some(r => r.id === person.roleId && r.template !== 'owner' && r.state === 'active') ? person.roleId : roles.find(r => r.template === 'member')?.id ?? ''), [projectIds, setProjectIds] = useState(person.projectIds);
  const [link, setLink] = useState<{ value: string; expiresAt?: string; resetId?: string }>();
  useEffect(() => client.auth.onClear(() => setLink(undefined)), [client]);
  if (!directory) return null;
  const current = person.accountId === directory.accountId, lastOwner = person.owner && directory.people.filter(p => p.owner && p.state === 'active').length <= 1;
  const labels = { access: person.state === 'suspended' ? 'Reactivate member' : person.owner ? 'Change to member' : 'Save access', suspend: 'Suspend access', remove: 'Remove person', promote: 'Invite to become an Owner', reset: 'Create recovery link' };
  if (link) return <PrivateLink title={action === 'reset' ? `Help ${person.displayName} sign in` : `Make ${person.displayName} an Owner`} link={link.value} {...(link.expiresAt ? { expiresAt: link.expiresAt } : {})} onClose={onClose} {...(link.resetId ? { revoke: () => client.recoveries.revokeReset(directory.workspaceId, link.resetId!) } : {})}/>;
  const disabled = (['remove','suspend'].includes(action) || action === 'access' && person.owner) && lastOwner || action === 'access' && !roleId || (action === 'promote' || action === 'access' && person.state === 'suspended') && !workspaceEditable(directory);
  return <SecureConfirm open layout="form" onClose={onClose} title={person.displayName} description={current ? 'You are changing your own access.' : 'Review this person’s access before confirming.'} confirmLabel={labels[action]} danger={action === 'remove' || action === 'suspend'} disabled={disabled} perform={async operationId => {
    let result: unknown;
    if (action === 'access') result = await (person.owner ? client.accessChanges.demoteOwner({ accountId: person.accountId, roleId, projectIds, operationId }) : person.state === 'suspended' ? client.accessChanges.reactivateMember({ accountId: person.accountId, roleId, projectIds, operationId }) : client.accessChanges.setAccess({ accountId: person.accountId, roleId, projectIds, operationId }));
    if (action === 'suspend') result = await client.accessChanges.suspend({ accountId: person.accountId, operationId });
    if (action === 'remove') result = await client.accessChanges.remove({ accountId: person.accountId, operationId });
    if (action === 'promote') { const issued = await client.enrolments.beginPromotion(person.accountId, operationId); setLink({ value: createHandoffLink({ kind: 'promote', workspaceId: directory.workspaceId, operationId: issued.operationId }), expiresAt: issued.expiresAt }); return issued; }
    if (action === 'reset') { const issued = await client.recoveries.issueReset(person.accountId, operationId); setLink({ value: createHandoffLink({ kind: 'reset', workspaceId: directory.workspaceId, code: issued.code }), expiresAt: issued.expiresAt, resetId: issued.resetId }); return issued; }
    if (result && typeof result === 'object' && 'access' in result && result.access === 'revoked') { notify('Your access has changed. Sign in again to continue.', 'info'); await signOut(); }
    return result;
  }} onDone={async () => { if (action === 'reset' || action === 'promote') return false; await reloadDirectory(); await reloadProjects(); return true; }}>
    <Field label="Action"><Select value={action} onChange={e => setAction(e.target.value as typeof action)}><option value="access">{person.owner ? 'Change Owner to a member' : person.state === 'suspended' ? 'Reactivate as a member' : 'Change role and projects'}</option>{person.state === 'active' && <option value="suspend">Suspend access</option>}<option value="remove">Remove from workspace</option>{person.state === 'active' && !current && !person.owner && <option value="promote">Invite to become an Owner</option>}{person.state === 'active' && !current && <option value="reset">Help with sign-in</option>}</Select></Field>
    {action === 'access' && <><Field label="Role"><Select value={roleId} onChange={e => setRoleId(e.target.value)}>{roles.filter(r => r.state === 'active' && r.template !== 'owner').map(r => <option key={r.id} value={r.id}>{r.displayName}</option>)}</Select></Field><ProjectChoices selected={projectIds} onChange={setProjectIds}/>{person.owner && <p className="muted">This ends their Owner authority and retires their Owner recovery phrase. Their existing password can still be used.</p>}{person.state === 'suspended' && <p className="muted">They will need to approve a device again. Reactivation does not restore Owner authority.</p>}</>}
    {action === 'suspend' && <p>Signing in and access from existing devices will stop. Shared work remains, and this person can be reactivated as a member later.</p>}
    {action === 'remove' && <p>This permanently removes this person’s access and current assignments. Shared work and history remain with attribution as Former member.</p>}
    {action === 'promote' && <p>They will have the same authority as every other Owner. They must create their own recovery kit and complete an approval with you.</p>}
    {action === 'reset' && <p>A private recovery link lasts fifteen minutes. You will compare the full verification code with them before approving their new sign-in.</p>}
    {disabled && lastOwner && <div className="notice notice-warning">Invite and activate another Owner before changing the last Owner’s access.</div>}
  </SecureConfirm>;
}
function Invitations({ onApprove }: { onApprove: (value: string) => void }) {
  const { client, directory } = useApp(); const { refresh, version } = useContext(SettingsRefresh); const [liveInvitations, setLiveInvitations] = useState<EnrolmentList['invitations']>(); const loadInvitations = async () => {
    const rows: EnrolmentList['invitations'] = []; let after: string | undefined;
    for (let i = 0; i < 100; i++) { const page = await client.enrolments.listInvitations({ limit: 50, ...(after ? { after } : {}) }); rows.push(...page.invitations); if (!page.nextCursor) return rows; after = page.nextCursor; }
    throw new Error('CONFLICT');
  }; const data = useSettingsLoad(loadInvitations); const [revoke, setRevoke] = useState<EnrolmentList['invitations'][number]>();
  const sessionId = client.auth.current()?.session.sessionId ?? '';
  useEffect(() => { setLiveInvitations(undefined); }, [version]);
  useEffect(() => client.auth.onClear(() => setLiveInvitations(undefined)), [client]);
  const polling = useIdentityPolling({ enabled: !!sessionId && !revoke && !data.loading, scope: `invitations:${sessionId}:${version}`, poll: async isCurrent => { const rows = await loadInvitations(); if (isCurrent()) setLiveInvitations(rows); } });
  const invitations = liveInvitations ?? data.value;
  return <Panel title="Pending invitations" description="Current invitations and Owner requests across your workspace." actions={<PasswordRefresh onDone={data.reload}/>}>
    <LoadState loading={data.loading} error={data.error} retry={data.reload}>{!invitations?.length ? <p className="muted">No invitations are waiting.</p> : <div className="settings-list">{invitations.map(invite => <div className="settings-row" key={invite.operationId}><div><strong>{directory?.people.find(p => p.accountId === invite.accountId)?.displayName ?? (invite.kind === 'join_owner' ? 'New Owner invitation' : 'New member invitation')}</strong><p className="muted">{invite.state === 'issued' ? invite.recipientStarted ? 'Ready for your security check' : 'Waiting for the recipient' : 'Approval in progress'} · Expires {dateLabel(invite.expiresAt)}</p></div><div className="settings-row-actions">{(invite.recipientStarted || invite.state !== 'issued') && <Button variant="secondary" onClick={() => onApprove(createHandoffLink({ kind: 'approve', workspaceId: directory!.workspaceId, operationId: invite.operationId, ceremony: 'join' }))}>Review approval</Button>}{invite.kind !== 'promote_owner' && <Button variant="ghost" onClick={() => setRevoke(invite)}>Revoke</Button>}</div></div>)}</div>}</LoadState>
    {(polling.paused || polling.error) && <Button variant="ghost" onClick={polling.retry}>Resume invitation updates</Button>}
    {revoke && <SecureConfirm open onClose={() => setRevoke(undefined)} title="Revoke this invitation?" description="The private link will stop working. You can create a new invitation later." confirmLabel="Revoke invitation" danger perform={() => client.enrolments.revokeJoin({ workspaceId: directory!.workspaceId, operationId: revoke.operationId })} onDone={refresh}/>}
  </Panel>;
}
export function PeopleSettings() {
  const { client, directory, reloadDirectory, reloadProjects, openApprovals } = useApp(), { refresh } = useContext(SettingsRefresh); const roles = useSettingsLoad(() => directory?.isOwner ? readAllRoles(client) : Promise.resolve([]));
  const reload = useSettingsAction();
  const refreshPeople = async () => { await reloadDirectory(); await reloadProjects(); refresh(); };
  const [search, setSearch] = useState(''), [invite, setInvite] = useState(false), [selected, setSelected] = useState<DirectoryPerson>();
  if (!directory) return null;
  const people = directory.people.filter(p => p.displayName.toLocaleLowerCase().includes(search.toLocaleLowerCase()));
  return <><PageHead title="People" description="The people you plan, build and move forward with." eyebrow="Workspace settings" actions={<><Button variant="secondary" busy={reload.busy} onClick={()=>void reload.run(refreshPeople)}>Refresh people</Button>{directory.isOwner && <Button onClick={() => setInvite(true)} disabled={!roles.value?.length || !workspaceEditable(directory)}><UserPlus size={17}/> Invite person</Button>}</>}/>{!!reload.error&&<ErrorNotice error={reload.error}/>}
    <Panel title={`${directory.people.filter(p => p.state === 'active').length} active people`} description="Every Owner has equal authority. Roles control project permissions."><Field label={<><Search size={15}/> Find a person</>}><Input type="search" value={search} onChange={e => setSearch(e.target.value)} placeholder="Search names"/></Field>{!!roles.error && directory.isOwner && <ErrorNotice error={roles.error} retry={roles.reload}/>}
      {people.length ? <div className="table-wrap"><table className="settings-table"><thead><tr><th scope="col">Person</th><th scope="col">Role</th><th scope="col">Access</th>{directory.isOwner && <th scope="col"><span className="sr-only">Actions</span></th>}</tr></thead><tbody>{people.map(p => <tr key={p.accountId}><td><div className="person-cell"><Avatar selection={p.avatar} name={p.displayName}/><div><strong>{p.displayName}</strong>{p.accountId === directory.accountId && <span className="muted"> You</span>}</div></div></td><td>{p.owner ? 'Owner' : roles.value?.find(r => r.id === p.roleId)?.displayName ?? 'Member'}</td><td><Badge tone={p.state === 'active' ? 'success' : p.state === 'suspended' ? 'warning' : 'neutral'}>{p.state === 'active' ? 'Active' : p.state === 'suspended' ? 'Suspended' : 'Removed'}</Badge></td>{directory.isOwner && <td>{p.state !== 'removed' && <Button variant="ghost" disabled={!roles.value?.length} onClick={() => setSelected(p)}>Manage<span className="sr-only"> {p.displayName}</span></Button>}</td>}</tr>)}</tbody></table></div> : <EmptyState title="No matching people" description="Try another name." icon={<Users/>}/>}
    </Panel>
    {directory.isOwner && <><Invitations onApprove={link=>openApprovals(link,refreshPeople)}/><Panel title="Access requests" description="Finish an invitation or help someone regain access."><Button variant="secondary" onClick={()=>openApprovals(undefined,refreshPeople)}>Review access requests</Button></Panel></>}
    {invite && roles.value && <InvitePerson roles={roles.value} onClose={() => setInvite(false)}/>}{selected && roles.value && <ManagePerson key={selected.accountId} person={selected} roles={roles.value} onClose={() => setSelected(undefined)}/>}
  </>;
}
