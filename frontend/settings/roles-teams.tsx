'use client';
import { useState } from 'react';
import { Plus, Users, Shield, History } from 'lucide-react';
import type { ReadableRole } from '../../src/client/roles-controller.js';
import type { TeamsPage, ReadableTeamHistory } from '../../src/client/teams-crypto.js';
import { useApp } from '../shared/context';
import { Avatar, Badge, Button, EmptyState, Field, Input, Modal, PageHead, Textarea } from '../shared/ui';
import { CheckOption, dateLabel, LoadState, Panel, PasswordRefresh, SecureConfirm, toggleId, useSettingsLoad, workspaceEditable } from './common';
import { readAllRoles } from './people';
const permissionChoices = [
  ['read_project', 'View projects', 'Read project plans and work.'],
  ['comment', 'Comment and post updates', 'Contribute to conversations and progress updates.'],
  ['create_tasks', 'Create tasks', 'Add work to a project.'],
  ['edit_assigned_tasks', 'Update assigned work', 'Move and update tasks assigned to them.'],
  ['manage_tasks', 'Manage tasks', 'Manage tasks, assignments and task reviewers.'],
  ['approve_tasks', 'Approve tasks', 'Review other people’s submitted work.'],
  ['plan_projects', 'Plan projects', 'Manage phases, milestones and project closure.'],
  ['download_files', 'Download files', 'Save project files and delivery packages to their device.'],
] as const;
type Permission = typeof permissionChoices[number][0];
function RoleEditor({ role, onClose }: { role?: ReadableRole; onClose: () => void }) {
  const { client } = useApp(); const [name, setName] = useState(role?.displayName ?? ''), [permissions, setPermissions] = useState<Permission[]>(role?.permissions ?? ['read_project']);
  return <SecureConfirm open onClose={onClose} title={role ? 'Edit role' : 'Create a role'} description="Choose the project permissions people need. Owner authority is managed separately." confirmLabel={role ? 'Save role' : 'Create role'} disabled={!name.trim()} perform={operationId => role ? client.roles.update({ roleId: role.id, expectedRevision: role.revision, displayName: name.trim(), permissions, operationId }) : client.roles.create({ displayName: name.trim(), permissions, operationId })}>
    <Field label="Role name"><Input value={name} maxLength={200} onChange={e => setName(e.target.value)} autoFocus/></Field><fieldset className="settings-choice-list"><legend>Permissions</legend>{permissionChoices.map(([id, title, description]) => <CheckOption key={id} checked={permissions.includes(id)} disabled={id === 'read_project'} onChange={checked => setPermissions(toggleId(permissions, id, checked) as Permission[])}><strong>{title}</strong><span className="muted">{description}</span></CheckOption>)}</fieldset>
    {role && <div className="notice">Existing access keeps its current permissions until an Owner reapplies this role in People.</div>}
  </SecureConfirm>;
}
export function RolesSettings() {
  const { client, directory } = useApp(); const data = useSettingsLoad(() => directory?.isOwner ? readAllRoles(client) : Promise.resolve([]));
  const [editing, setEditing] = useState<ReadableRole | 'new'>(), [retiring, setRetiring] = useState<ReadableRole>();
  if (!directory?.isOwner) return <EmptyState title="Roles are managed by Owners" description="Ask an Owner if your project access needs to change." icon={<Shield/>}/>;
  return <><PageHead title="Roles & permissions" description="Clear responsibilities, with access that fits the work." eyebrow="Workspace settings" actions={<Button disabled={!workspaceEditable(directory)} onClick={() => setEditing('new')}><Plus size={17}/> Create role</Button>}/><Panel title="Workspace roles" description="Built-in roles are fixed. Custom roles can be edited or retired." actions={<PasswordRefresh onDone={data.reload}/>}><LoadState loading={data.loading} error={data.error} retry={data.reload}>
    <div className="settings-role-grid">{data.value?.map(role => <article className="settings-role-card" key={role.id}><header><h3>{role.displayName}</h3><Badge tone={role.state === 'retired' ? 'neutral' : role.template === 'owner' ? 'warning' : 'success'}>{role.state === 'retired' ? 'Retired' : role.template === 'custom' ? 'Custom' : 'Built-in'}</Badge></header>{role.template === 'owner' && <p>Equal authority over the workspace, people and all ordinary projects.</p>}<ul className="settings-permissions">{permissionChoices.filter(([id]) => role.permissions.includes(id)).map(([id, label]) => <li key={id}>{label}</li>)}</ul>{role.template === 'custom' && role.state === 'active' && <footer><Button variant="secondary" disabled={!workspaceEditable(directory)} onClick={() => setEditing(role)}>Edit role</Button><Button variant="ghost" disabled={!workspaceEditable(directory)} onClick={() => setRetiring(role)}>Retire</Button></footer>}</article>)}</div>
  </LoadState></Panel>{editing && <RoleEditor key={editing === 'new' ? 'new' : editing.id} {...(editing !== 'new' ? { role: editing } : {})} onClose={() => setEditing(undefined)}/>}{retiring && <SecureConfirm open onClose={() => setRetiring(undefined)} title={`Retire ${retiring.displayName}?`} description="The role must no longer be used by people, project access or pending invitations." confirmLabel="Retire role" danger perform={operationId => client.roles.retire({ roleId: retiring.id, expectedRevision: retiring.revision, operationId })}/>}</>;
}
type Team = TeamsPage['records'][number];
function TeamEditor({ team, onClose }: { team?: Team; onClose: () => void }) {
  const { client, directory } = useApp(); const [name, setName] = useState(team?.name ?? ''), [description, setDescription] = useState(team?.description ?? ''), [memberIds, setMemberIds] = useState(team?.memberIds ?? []);
  return <SecureConfirm open onClose={onClose} title={team ? 'Edit team' : 'Create a team'} description="Teams organise people and tasks. Project access is managed separately." confirmLabel={team ? 'Save team' : 'Create team'} disabled={!name.trim()} perform={operationId => team ? client.teams.edit({ teamId: team.teamId, expectedRevision: team.revision, name: name.trim(), description, memberIds, operationId }) : client.teams.create({ name: name.trim(), description, memberIds, operationId })}>
    <Field label="Team name"><Input value={name} maxLength={200} onChange={e => setName(e.target.value)} autoFocus/></Field><Field label="Description" hint="Optional"><Textarea value={description} maxLength={10000} onChange={e => setDescription(e.target.value)}/></Field><fieldset className="settings-choice-list"><legend>People</legend>{directory?.people.filter(p => p.state === 'active').map(person => <CheckOption key={person.accountId} checked={memberIds.includes(person.accountId)} onChange={value => setMemberIds(toggleId(memberIds, person.accountId, value))}><span className="person-cell"><Avatar selection={person.avatar} name={person.displayName} size={28}/>{person.displayName}</span></CheckOption>)}</fieldset>
  </SecureConfirm>;
}
function TeamHistory({ team, onClose }: { team: Team; onClose: () => void }) {
  const { client, directory } = useApp(); const data = useSettingsLoad<ReadableTeamHistory>(() => client.teams.history(team.teamId), [team.teamId]);
  const person = (id: string) => directory?.people.find(p => p.accountId === id)?.displayName ?? 'Former member';
  return <Modal open onClose={onClose} title={`${team.name} history`} description="Verified changes to this team." footer={<Button variant="secondary" onClick={onClose}>Done</Button>}><LoadState loading={data.loading} error={data.error} retry={data.reload}><ol className="settings-history">{data.value?.records.slice().reverse().map(record => <li key={record.operationId}><div><strong>{record.action === 'create' ? 'Team created' : record.action === 'upgrade_content' ? 'Workspace update' : 'Team updated'}</strong><span className="muted"> by {person(record.actorId)} · {dateLabel(record.signedAt ?? record.serverRecordedAt)}</span></div><p>{record.after.name}</p>{record.after.description && <p className="muted">{record.after.description}</p>}<p className="muted">{record.after.memberIds.length ? record.after.memberIds.map(person).join(', ') : 'No members'}</p></li>)}</ol></LoadState></Modal>;
}
export function TeamsSettings() {
  const { client, directory } = useApp(); const data = useSettingsLoad(async () => {
    const all: Team[] = []; let after: string | undefined;
    for (let i = 0; i < 100; i++) { const page = await client.teams.list({ limit: 100, ...(after ? { after } : {}) }); all.push(...page.records); if (!page.nextCursor) return all; if (page.nextCursor === after) throw new Error('CONFLICT'); after = page.nextCursor; } throw new Error('CONFLICT');
  }); const [editing, setEditing] = useState<Team | 'new'>(), [history, setHistory] = useState<Team>(), [search, setSearch] = useState('');
  const teams = data.value?.filter(team => team.name.toLocaleLowerCase().includes(search.toLocaleLowerCase()));
  return <><PageHead title="Teams" description="Give people a shared place in the work." eyebrow="Workspace settings" actions={directory?.isOwner && <Button disabled={!workspaceEditable(directory)} onClick={() => setEditing('new')}><Plus size={17}/> Create team</Button>}/><Panel title="Your teams" description="Membership groups people and tasks; it does not change project permissions."><Field label="Find a team"><Input type="search" value={search} onChange={e => setSearch(e.target.value)} placeholder="Search teams"/></Field><LoadState loading={data.loading} error={data.error} retry={data.reload}>{teams?.length ? <div className="settings-team-grid">{teams.map(team => <article className="settings-team-card" key={team.teamId}><h3>{team.name}</h3>{team.description && <p className="muted">{team.description}</p>}<div className="settings-team-people">{team.memberIds.map(id => { const person = directory?.people.find(p => p.accountId === id); return person ? <span key={id} className="person-cell"><Avatar selection={person.avatar} name={person.displayName} size={28}/>{person.displayName}</span> : <span key={id}>Former member</span>; })}{!team.memberIds.length && <p className="muted">No members yet</p>}</div><footer>{directory?.isOwner && <Button variant="secondary" disabled={!workspaceEditable(directory)} onClick={() => setEditing(team)}>Edit team</Button>}<Button variant="ghost" onClick={() => setHistory(team)}><History size={15}/> History</Button></footer></article>)}</div> : <EmptyState title={search ? 'No matching teams' : 'Bring a team together'} description={search ? 'Try another name.' : 'Create a team to group people and organise their work.'} icon={<Users/>} {...(directory?.isOwner && !search ? { action: <Button disabled={!workspaceEditable(directory)} onClick={() => setEditing('new')}>Create your first team</Button> } : {})}/>}</LoadState></Panel>
    {editing && <TeamEditor key={editing === 'new' ? 'new' : editing.teamId} {...(editing !== 'new' ? { team: editing } : {})} onClose={() => setEditing(undefined)}/>}{history && <TeamHistory key={history.teamId} team={history} onClose={() => setHistory(undefined)}/>}
  </>;
}
