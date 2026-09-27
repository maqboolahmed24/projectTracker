'use client';
import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from 'react';
import { useApp } from '../shared/context';
import { Button, ErrorNotice, Field, Input, Modal, Spinner } from '../shared/ui';
import type { WorkspaceDirectory } from '../../src/client/directory-crypto.js';
export function workspaceEditable(directory: WorkspaceDirectory | null) {
  return !!directory && directory.lifecycle === 'active' && directory.licenceState === 'active' && directory.entitlementState === 'activated' && !directory.activeUpgrade && !directory.restoreQuarantine;
}
export const SettingsRefresh = createContext({ version: 0, refresh: () => {} });
export function useSettingsLoad<T>(loader: () => Promise<T>, dependencies: unknown[] = []) {
  const { client } = useApp(), { version } = useContext(SettingsRefresh);
  const [value, setValue] = useState<T>(), [error, setError] = useState<unknown>(), [loading, setLoading] = useState(true), [retry, setRetry] = useState(0);
  const latest = useRef(loader); latest.current = loader;
  useEffect(() => { let active = true; setLoading(true); setError(undefined);
    void latest.current().then(v => { if (active) setValue(v); }).catch(e => { if (active) setError(e); }).finally(() => { if (active) setLoading(false); });
    const clear = client.auth.onClear(() => { active = false; setValue(undefined); setError(undefined); });
    return () => { active = false; clear(); };
  }, [client, version, retry, ...dependencies]);
  return { value, error, loading, reload: useCallback(() => setRetry(n => n + 1), []) };
}
export function LoadState({ loading, error, retry, children }: { loading: boolean; error: unknown; retry: () => void; children: ReactNode }) {
  if (error) return <ErrorNotice error={error} retry={retry}/>;
  if (loading) return <div className="settings-loading" role="status"><Spinner/> Loading…</div>;
  return <>{children}</>;
}
export function Panel({ title, description, children, actions }: { title: string; description?: ReactNode; children?: ReactNode; actions?: ReactNode }) {
  return <section className="settings-panel"><header className="settings-panel-head"><div><h2>{title}</h2>{description && <p className="muted">{description}</p>}</div>{actions}</header>{children}</section>;
}
export function dateLabel(value: string | null | undefined) { if (!value) return 'Not recorded'; const date = new Date(value); return Number.isFinite(date.getTime()) ? date.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }) : 'Not recorded'; }
export function isFinishing(value: unknown) { return !!value && typeof value === 'object' && 'state' in value && value.state === 'finishing'; }
export function useSettingsAction() {
  const { notify, client } = useApp(), { refresh } = useContext(SettingsRefresh);
  const [busy, setBusy] = useState(false), [error, setError] = useState<unknown>(); const epoch = useRef(0), inFlight = useRef(false);
  useEffect(() => client.auth.onClear(() => { epoch.current++; inFlight.current = false; setError(undefined); setBusy(false); }), [client]);
  const run = async (work: () => Promise<unknown>, success?: string) => {
    if (inFlight.current) return false; inFlight.current = true; const version = epoch.current; setBusy(true); setError(undefined);
    try { const result = await work(); if (version !== epoch.current) return false;
      if (isFinishing(result)) notify('The change is being completed. Open Check interrupted saves to continue.', 'info'); else if (success) notify(success, 'success');
      return true;
    } catch (e) { if (version === epoch.current) setError(e); return false; }
    finally { if (version === epoch.current) { inFlight.current = false; setBusy(false); refresh(); } }
  };
  return { busy, error, run, clearError: () => setError(undefined) };
}
/** Password stays in this mounted dialog and is cleared before the mutation begins. */
export function SecureConfirm({ open, onClose, title, description, children, confirmLabel = 'Confirm', danger = false, disabled = false, layout = 'content', perform, onDone }: {
  open: boolean; onClose: () => void; title: string; description?: ReactNode; children?: ReactNode; confirmLabel?: string; danger?: boolean; disabled?: boolean; layout?:'content'|'detail'|'form';
  perform: (operationId: string) => Promise<unknown>; onDone?: () => void | boolean | Promise<void | boolean>;
}) {
  const { client, notify } = useApp(), action = useSettingsAction(); const [password, setPassword] = useState(''), [operationId] = useState(() => crypto.randomUUID()), [locked, setLocked] = useState(false);
  useEffect(() => client.auth.onClear(() => setPassword('')), [client]);
  useEffect(() => { if (!open) setPassword(''); }, [open]);
  const submit = async () => {
    let finishing = false;
    const ok = await action.run(async () => { const secret = password; setPassword(''); await client.auth.reauthenticate(secret); setLocked(true); const result = await perform(operationId); finishing = isFinishing(result); return result; });
    if (ok) {
      // A pending receipt has its own continuation notice. Do not run a callback
      // that assumes completion, or describe a later refresh error as finished.
      if (finishing) { onClose(); return; }
      try { if (await onDone?.() !== false) onClose(); }
      catch { notify('The action finished, but the latest view could not be loaded. Refresh to see the result.', 'info'); onClose(); }
    }
  };
  return <Modal open={open} layout={layout} onClose={() => { if (!action.busy) onClose(); }} title={title} description={description} footer={<><Button variant="secondary" disabled={action.busy} onClick={onClose}>Cancel</Button><Button variant={danger ? 'danger' : 'primary'} busy={action.busy} disabled={disabled || !password} onClick={() => void submit()}>{confirmLabel}</Button></>}>
    {children && <fieldset className="settings-confirm-fields" disabled={action.busy || locked}>{children}</fieldset>}{locked && !!action.error && <p className="muted">This attempt may already be saved. Continue with the same details, or close this window and open Check interrupted saves before starting again.</p>}<Field label="Confirm your password" hint="This protects changes to your workspace."><Input type="password" autoComplete="current-password" value={password} disabled={action.busy} onChange={e => setPassword(e.target.value)} onKeyDown={e => { if (e.key === 'Enter' && password && !disabled && !action.busy) { e.preventDefault(); void submit(); } }}/></Field>{!!action.error && <ErrorNotice error={action.error}/>}
  </Modal>;
}
export function PasswordRefresh({ onDone }: { onDone?: () => void }) {
  const [open, setOpen] = useState(false);
  return <><Button variant="secondary" onClick={() => setOpen(true)}>Confirm password</Button>{open && <SecureConfirm open onClose={() => setOpen(false)} title="Confirm your password" description="Confirm it to view or change security settings." perform={async () => undefined} {...(onDone ? {onDone} : {})}/>}</>;
}
export function CheckOption({ checked, onChange, children, disabled = false }: { checked: boolean; onChange: (value: boolean) => void; children: ReactNode; disabled?: boolean }) {
  return <label className="settings-check"><input type="checkbox" checked={checked} disabled={disabled} onChange={e => onChange(e.target.checked)}/><span>{children}</span></label>;
}
export function toggleId(values: string[], id: string, selected: boolean) { return selected ? [...new Set([...values, id])] : values.filter(value => value !== id); }
export function projectName(project: { records: { kind: string; content: Record<string, unknown> }[] }) { const record = project.records.find(r => r.kind === 'project'); return typeof record?.content.name === 'string' ? record.content.name : 'Project'; }
