import { useEffect, useRef, useState } from 'react';
import { ArrowRight, Check, ShieldCheck } from 'lucide-react';
import type { ClientRuntime } from '../../src/client/runtime.js';
import type { AuthSessionResult } from '../../src/shared/auth.js';
import { Button, Field, Input, Textarea } from '../shared/ui.js';
import { DeviceSecurityCode, DeviceSecurityComparison, Notice, PasswordField, SecurityComparison, useIdentityAction } from './components.js';
import { parseHandoff, type IdentityHandoff } from './handoff.js';
import { rememberFinished } from './progress.js';
import { getClientLibrary } from '../shared/runtime.js';
import { useIdentityPolling } from './useIdentityPolling.js';

type ApprovalHandoff = Extract<IdentityHandoff, { kind: 'approve' }>;
export interface ApprovalRequest { kind: 'join'|'reset'|'pair'; workspaceId: string; operationId: string; accountId?: string }
const endedStates = ['completed', 'finishing', 'expired', 'cancelled', 'revoked'];
const discoveryReads = new WeakMap<ClientRuntime, { scope: string; promise: Promise<ApprovalRequest[]> }>();
/** Discovery contains public request references only. Opening a request never claims it. */
export function readApprovalRequests(client: ClientRuntime, isOwner: boolean): Promise<ApprovalRequest[]> {
  const session = client.auth.current()?.session;
  if (!session) return Promise.resolve([]);
  const scope = `${session.sessionId}:${isOwner}`, previous = discoveryReads.get(client);
  if (previous?.scope === scope) return previous.promise;
  const current = () => { if (client.auth.current()?.session.sessionId !== session.sessionId) throw Object.assign(new Error('CANCELLED'), { code: 'CANCELLED' }); };
  const promise = (async () => {
    const rows: ApprovalRequest[] = [];
    if (isOwner) {
      let after: string | undefined;
      for (let page = 0; page < 100; page++) {
        current(); const result = await client.enrolments.listInvitations({ limit: 50, ...(after ? { after } : {}) }); current();
        for (const item of result.invitations) if (item.recipientStarted || item.state !== 'issued') rows.push({ kind: 'join', workspaceId: result.workspaceId, operationId: item.operationId, accountId: item.accountId });
        if (!result.nextCursor) break;
        if (result.nextCursor === after || page === 99) throw Object.assign(new Error('CONFLICT'), { code: 'CONFLICT' });
        after = result.nextCursor;
      }
      for (const item of await client.recoveries.operations.list()) if (item.role === 'owner' && item.workspaceId === session.workspaceId && item.operationId && !endedStates.includes(item.state)) rows.push({ kind: 'reset', workspaceId: item.workspaceId, operationId: item.operationId, ...(item.accountId ? { accountId: item.accountId } : {}) });
    }
    let after: string | undefined;
    for (let page = 0; page < 100; page++) {
      current(); const result = await client.pairing.listPending({ limit: 50, ...(after ? { after } : {}) }); current();
      for (const item of result.requests) if (!item.approverAccountId || item.approverAccountId === session.accountId && item.approverDeviceId === session.deviceId) rows.push({ kind: 'pair', workspaceId: result.workspaceId, operationId: item.operationId, accountId: item.accountId });
      if (!result.nextCursor) break;
      if (result.nextCursor === after || page === 99) throw Object.assign(new Error('CONFLICT'), { code: 'CONFLICT' });
      after = result.nextCursor;
    }
    current(); return rows;
  })().finally(() => { if (discoveryReads.get(client)?.promise === promise) discoveryReads.delete(client); });
  discoveryReads.set(client, { scope, promise }); return promise;
}
export interface IdentityApprovalsProps { client: ClientRuntime; initialHandoff?: string; onDone?: () => void|Promise<void>; isOwner?: boolean; people?: readonly { accountId: string; displayName: string }[] }
export function IdentityApprovals({ client, initialHandoff, onDone, isOwner = true, people = [] }: IdentityApprovalsProps) {
  const [link, setLink] = useState(''), [selected, setSelected] = useState<ApprovalHandoff|null>(null), [pending, setPending] = useState<ApprovalRequest[]>([]);
  const action = useIdentityAction(), seenHandoff = useRef('');
  const sessionId = client.auth.current()?.session.sessionId ?? '';
  const polling = useIdentityPolling({ enabled: !selected && !action.busy && !!sessionId, scope: `approvals:${sessionId}:${isOwner}`, poll: async isCurrent => {
    const rows = await readApprovalRequests(client, isOwner); if (isCurrent()) setPending(rows);
  } });
  useEffect(() => client.auth.onClear(() => { setLink(''); setSelected(null); setPending([]); }), [client]);
  const select = (handoff: IdentityHandoff) => {
    if (handoff.kind !== 'approve') throw new Error('Please use the approval request sent by the person setting up their access.');
    if (handoff.workspaceId !== client.auth.current()?.session.workspaceId) throw new Error('Please sign in to the workspace this request belongs to.');
    setSelected(handoff); setLink(''); action.setError('');
  };
  useEffect(() => {
    if (!initialHandoff || seenHandoff.current === initialHandoff || action.busy) return;
    void action.run(async () => { seenHandoff.current = initialHandoff; select(parseHandoff(initialHandoff, client.auth.origin)); });
  }, [initialHandoff, action.busy]);
  if (selected) return <ApprovalDetail key={`${selected.workspaceId}:${selected.ceremony}:${selected.operationId}`} client={client} selected={selected} onBack={() => { setSelected(null); polling.retry(); }} beforeAction={polling.waitForIdle} {...(onDone ? { onDone } : {})}/>;
  return <section className="form-stack identity-approvals" aria-busy={action.busy}>
    <section className="identity-pending"><h3>{isOwner?'Access requests':'My device requests'}</h3>{pending.length ? pending.map((request, index) => {
      const name = people.find(person => person.accountId === request.accountId)?.displayName;
      const title = request.kind === 'join' ? 'Workspace invitation' : request.kind === 'reset' ? 'Account recovery' : 'Device approval';
      return <Button key={`${request.kind}:${request.operationId}`} variant="secondary" disabled={action.busy} onClick={() => select({ version: 1, kind: 'approve', origin: client.auth.origin, workspaceId: request.workspaceId, operationId: request.operationId, ceremony: request.kind })}><ShieldCheck size={16}/>{title}{name ? ` · ${name}` : pending.filter(row => row.kind === request.kind).length > 1 ? ` ${index + 1}` : ''}<ArrowRight size={16}/></Button>;
    }) : <p className="muted">{isOwner?'New requests will appear here automatically. Keep this window open while the other person starts.':'Your device requests will appear here automatically. Keep this window open while you sign in on your other device.'}</p>}</section>
    {(polling.paused || polling.error) && <><Notice>{polling.error || 'Automatic updates have paused. Resume when you’re ready.'}</Notice><Button variant="secondary" onClick={polling.retry}>Resume updates</Button></>}
    <details><summary>Use a private approval link</summary><form className="form-stack" onSubmit={event => { event.preventDefault(); void action.run(async () => select(parseHandoff(link, client.auth.origin))); }}><p className="muted">{isOwner?'Use this if someone has already sent you an approval request.':'Use this if you saved an approval request from your other device.'}</p><Field label="Private approval link"><Textarea rows={3} value={link} onChange={event => setLink(event.target.value)} required spellCheck={false} autoComplete="off" disabled={action.busy}/></Field><Field label="Or choose a saved request"><Input type="file" accept="application/json,.json" disabled={action.busy} onChange={event => { const file = event.target.files?.[0]; event.target.value = ''; if (file) void action.run(async () => { if (file.size > 12000) throw new Error('Please choose the original request file.'); select(parseHandoff(await file.text(), client.auth.origin)); }); }}/></Field><Button type="submit" busy={action.busy}>Review request<ArrowRight size={16}/></Button></form></details>
    {action.error && <Notice tone="error">{action.error}</Notice>}
  </section>;
}

type ApprovalStatus = { state: string; fingerprint: string|null; binding: string|null; recipientConfirmed: boolean; approverConfirmed: boolean; modern: boolean };
function ApprovalDetail({ client, selected, onBack, onDone, beforeAction }: { client: ClientRuntime; selected: ApprovalHandoff; onBack: () => void; onDone?: () => void|Promise<void>; beforeAction: () => Promise<void> }) {
  const [password, setPassword] = useState(''), [status, setStatus] = useState<ApprovalStatus|null>(null), [claimed, setClaimed] = useState(false), [done, setDone] = useState(false), [finalizing, setFinalizing] = useState(false), [confirmed, setConfirmed] = useState<string|null>(null), [changed, setChanged] = useState(false);
  const action = useIdentityAction(), alive = useRef(true), expectedBinding = useRef<string|null>(null), intent = useRef<{ fingerprint: string; binding: string|null; sessionId: string }|null>(null);
  const acceptedSession = useRef(client.auth.current()?.session);
  const sessionId = acceptedSession.current?.sessionId ?? '', reference = { workspaceId: selected.workspaceId, operationId: selected.operationId };
  const sameIdentity = (left: AuthSessionResult, right: AuthSessionResult) => (['workspaceId', 'accountId', 'deviceId', 'credentialGeneration', 'sessionGeneration', 'dataGeneration', 'accessLevel', 'absoluteExpiresAt'] as const).every(field => left[field] === right[field]);
  const current = () => { const present = client.auth.current(), accepted = acceptedSession.current; return alive.current && !!present && !!accepted && present.localAccess === 'unlocked' && present.session.sessionId === accepted.sessionId && sameIdentity(present.session, accepted); };
  const clearIntent = () => { intent.current = null; setConfirmed(null); };
  useEffect(() => { alive.current = true; const detach = client.auth.onClear(() => { alive.current = false; intent.current = null; setPassword(''); setStatus(null); setConfirmed(null); }); return () => { alive.current = false; intent.current = null; detach(); }; }, [client]);
  // Reauthentication intentionally rotates the session. Adopt only this exact
  // explicit result, while keeping unrelated sessions and cleared auth rejected.
  const reauthenticate = async (secret: string) => {
    const previous = acceptedSession.current;
    if (!previous || !current()) return false;
    clearIntent();
    const result = await client.auth.reauthenticate(secret), present = client.auth.current();
    if (!alive.current || acceptedSession.current !== previous) return false;
    if (!present || result.localAccess !== 'unlocked' || present.localAccess !== 'unlocked' ||
      present.session.sessionId !== result.session.sessionId || !sameIdentity(result.session, previous) || !sameIdentity(present.session, result.session)) {
      throw new Error('Please sign in again before continuing this request.');
    }
    acceptedSession.current = result.session;
    return true;
  };
  const readStatus = async (): Promise<ApprovalStatus> => {
    if (selected.ceremony === 'pair') {
      const progress = await client.pairing.inspect(selected.operationId);
      return { ...progress, binding: progress.fingerprint, modern: true };
    }
    let view;
    try { view = await client.enrolments.inspectApproval(reference); } catch (error) {
      if (current() && error && typeof error === 'object' && 'code' in error && error.code === 'CONFLICT') { clearIntent(); expectedBinding.current = null; setStatus(null); setClaimed(false); setChanged(true); }
      throw error;
    }
    return { state: view.state, fingerprint: view.transcriptDigest, binding: view.binding ? JSON.stringify(view.binding) : null, recipientConfirmed: !!view.recipientConfirmation, approverConfirmed: !!view.authorizerConfirmation, modern: view.kind !== 'promote_owner' };
  };
  const accept = (next: ApprovalStatus) => {
    if (expectedBinding.current !== null && next.binding !== expectedBinding.current && selected.ceremony !== 'pair') {
      clearIntent(); setStatus(null); setClaimed(false); setChanged(true); expectedBinding.current = null;
      throw new Error('Please start the security check again. This request changed while you were here.');
    }
    if (intent.current && (next.fingerprint !== intent.current.fingerprint || next.binding !== intent.current.binding || intent.current.sessionId !== acceptedSession.current?.sessionId || endedStates.includes(next.state))) clearIntent();
    setStatus(next);
  };
  const complete = async (isCurrent: () => boolean) => {
    if (!isCurrent()) return; setDone(true); setPassword(''); clearIntent(); await onDone?.();
  };
  const finish = async (next: ApprovalStatus, isCurrent: () => boolean) => {
    const authorized = intent.current;
    if (!authorized || !isCurrent() || !current() || authorized.sessionId !== acceptedSession.current?.sessionId || authorized.fingerprint !== next.fingerprint || authorized.binding !== next.binding || !next.recipientConfirmed || endedStates.includes(next.state)) return;
    if (selected.ceremony === 'pair' && !next.approverConfirmed) return;
    setFinalizing(true);
    try {
      if (selected.ceremony === 'pair') await client.pairing.approve(selected.operationId);
      else await client.enrolments.approve(reference, authorized.fingerprint);
      if (isCurrent() && current()) await complete(isCurrent);
    } catch (error) { if (isCurrent()) clearIntent(); throw error; }
    // Success disables polling before a directory refresh may finish. Cleanup
    // belongs to this mounted operation, not the now-cancelled polling token.
    finally { if (alive.current) setFinalizing(false); }
  };
  const polling = useIdentityPolling({ enabled: claimed && !done && !action.busy && selected.ceremony !== 'reset' && !endedStates.includes(status?.state ?? ''), scope: `approval:${sessionId}:${selected.ceremony}:${selected.operationId}`, poll: async isCurrent => {
    const next = await readStatus(); if (!isCurrent() || !current()) return; accept(next);
    if (next.state === 'completed' || next.state === 'finishing') { await complete(isCurrent); return; }
    await finish(next, isCurrent);
  } });
  useEffect(() => { if (polling.error || polling.paused) clearIntent(); }, [polling.error, polling.paused]);
  const claim = () => void action.run(async () => {
    try {
      await beforeAction(); await discoveryReads.get(client)?.promise.catch(() => {}); await polling.waitForIdle(); if (!current()) return;
      if (password) { const secret = password; setPassword(''); if (!await reauthenticate(secret)) return; } if (!current()) return;
      clearIntent(); expectedBinding.current = null; setChanged(false);
      const progress = selected.ceremony === 'pair' ? await client.pairing.claim(selected.operationId) : selected.ceremony === 'join' ? await client.enrolments.claim(reference) : await client.recoveries.claim(reference);
      if (!current()) return;
      const next = selected.ceremony === 'reset' ? { state: progress.state, fingerprint: progress.fingerprint, binding: null, recipientConfirmed: false, approverConfirmed: false, modern: false } : await readStatus();
      if (!current()) return; expectedBinding.current = next.binding; setStatus(next); setClaimed(true); polling.retry();
    } catch (error) { if (current()) clearIntent(); throw error; }
  });
  const approve = (fingerprint: string) => void action.run(async () => {
    try {
      await polling.waitForIdle(); if (!current()) return;
      if (password) { const secret = password; setPassword(''); if (!await reauthenticate(secret)) return; } if (!current()) return;
      if (selected.ceremony === 'reset') { await client.recoveries.approve(reference, fingerprint); if (current()) await complete(current); return; }
      let next = await readStatus(); if (!current()) return; accept(next);
      if (!/^[0-9a-f]{64}$/.test(fingerprint) || next.fingerprint !== fingerprint || endedStates.includes(next.state)) throw new Error('Please compare the current security check before continuing.');
      if (selected.ceremony === 'pair') { await client.pairing.confirmApprover(selected.operationId, fingerprint); if (!current()) return; next = await readStatus(); if (!current()) return; accept(next); if (next.fingerprint !== fingerprint) throw new Error('Please compare the current security check before continuing.'); }
      intent.current = { fingerprint, binding: next.binding, sessionId: acceptedSession.current!.sessionId }; setConfirmed(fingerprint);
      await finish(next, current);
    } catch (error) { if (current()) clearIntent(); throw error; }
  });
  const busy = action.busy || finalizing, fingerprint = status?.fingerprint, ended = status && ['expired', 'cancelled', 'revoked'].includes(status.state);
  return <section className="form-stack identity-approvals" aria-busy={busy}>
    {done ? <><div className="identity-icon"><Check size={28}/></div><h3>Access approved</h3><p className="muted">The other person can now continue on their device.</p></> : <>
      <div className="identity-request-summary"><ShieldCheck size={24}/><div><h3>{selected.ceremony === 'join' ? 'Workspace invitation' : selected.ceremony === 'reset' ? 'Account recovery' : 'New device'}</h3><p className="muted">Only approve if you know the person and have checked this request with them.</p></div></div>
      {ended ? <Notice>This request has ended. Ask the other person to start a new request.</Notice> : <>
        {!claimed && <>{changed && <Notice>This request changed. Start the security check again to continue.</Notice>}<PasswordField value={password} onChange={setPassword} label="Confirm your password"/><Button busy={busy} disabled={!password} onClick={claim}>Start security check<ArrowRight size={16}/></Button></>}
        {claimed && !fingerprint && <><Notice>{selected.ceremony === 'reset' ? 'The request is ready for the other person. Ask them to complete their details, then check again.' : 'The other person can now set up their access. This screen will update when their security check is ready.'}</Notice>{selected.ceremony === 'reset' && <Button busy={busy} onClick={claim}>Check their progress</Button>}</>}
        {fingerprint && <>{confirmed === fingerprint ? <><Notice>Your check is complete. Waiting for the other person to compare the codes.</Notice><DeviceSecurityCode fingerprint={fingerprint}/></> : status.modern ? <DeviceSecurityComparison key={`${selected.operationId}:${fingerprint}`} fingerprint={fingerprint} onConfirm={approve} busy={busy}/> : <SecurityComparison key={`${selected.operationId}:${fingerprint}`} fingerprint={fingerprint} onConfirm={approve} busy={busy}/>}
          {(action.error || polling.error) && <PasswordField value={password} onChange={setPassword} label="Confirm your password again" required={false}/>} {selected.ceremony === 'reset' && <Button variant="ghost" busy={busy} onClick={claim}>Refresh this request</Button>}</>}
        {claimed && selected.ceremony !== 'reset' && (polling.paused || polling.error) && <><Notice>{polling.error || 'Automatic updates have paused. Resume to compare the latest request.'}</Notice><Button variant="secondary" disabled={busy} onClick={() => { clearIntent(); polling.retry(); }}>Resume updates</Button></>}
      </>}
    </>}
    <Button variant="ghost" disabled={busy} onClick={onBack}>Back to requests</Button>
    {action.error && <Notice tone="error">{action.error}</Notice>}
  </section>;
}

export interface PasswordChangePanelProps {client:ClientRuntime;onChanged?:()=>void|Promise<void>;showHeading?:boolean}
export function PasswordChangePanel({client,onChanged,showHeading=true}:PasswordChangePanelProps){
  const [current,setCurrent]=useState(''),[next,setNext]=useState(''),[confirm,setConfirm]=useState(''),[saved,setSaved]=useState(false),[operation,setOperation]=useState<ReturnType<Crypto['randomUUID']>|null>(null),[done,setDone]=useState(false),action=useIdentityAction();
  useEffect(()=>client.auth.onClear(()=>{setCurrent('');setNext('');setConfirm('');}),[client]);
  const change=()=>action.run(async()=>{const session=client.auth.current()?.session;if(!session)throw new Error('Please sign in again to continue.');const password=next,complete=onChanged;
    (await getClientLibrary()).password.validateNewPassword(password);if(password!==confirm)throw new Error('Your passwords don’t match.');
    await client.auth.reauthenticate(current);
    const id=operation??crypto.randomUUID();setOperation(id);
    const status=await client.passwordChanges.begin(session.workspaceId,id);
    if(status.state==='issued'&&!saved){await client.passwordChanges.prepare(id,password,confirm);setSaved(true);}
    const result=await client.passwordChanges.complete(id,password),r=result.receipt;
    await client.auth.login({workspaceId:r.workspaceId,accountId:r.accountId,deviceId:r.deviceId},password);
    await client.passwordChanges.resume(id,client.auth.current()!.session);rememberFinished('password',id);
    // Completing the change clears auth and unmounts Settings. Finish relogin and
    // notify the application even though this particular panel has gone away.
    await complete?.();setCurrent('');setNext('');setConfirm('');setDone(true);
  });
  return <section className="form-stack"><header>{showHeading&&<h2>Change your password</h2>}<p className="muted">Keep using this device. Your other devices will need to sign in and be approved again.</p></header>{done?<Notice tone="success">Your password has been updated.</Notice>:<form className="form-stack" onSubmit={e=>{e.preventDefault();void change();}}><PasswordField value={current} onChange={setCurrent} label="Current password"/><PasswordField value={next} onChange={setNext} label="New password" newPassword/><PasswordField value={confirm} onChange={setConfirm} label="Confirm new password" newPassword/><Button type="submit" busy={action.busy}>Update password<ArrowRight size={16}/></Button>{operation&&<p className="muted identity-small">If the connection stops, return to the sign-in screen and choose your saved password change.</p>}</form>}{action.error&&<Notice tone="error">{action.error}</Notice>}</section>;
}
