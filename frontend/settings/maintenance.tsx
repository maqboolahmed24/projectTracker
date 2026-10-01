'use client';

import { useEffect, useRef, useState } from 'react';
import { Check, Pause, RefreshCw, ShieldCheck } from 'lucide-react';
import { useApp } from '../shared/context';
import { customerError } from '../shared/errors';
import { Badge, Button, EmptyState, PageHead, Spinner } from '../shared/ui';
import { contentSchemaRegistry } from '../../src/shared/content-schema.js';
import { LoadState, Panel, PasswordRefresh, SecureConfirm, useSettingsLoad } from './common';
import { RestorePanel } from './data';
import { runWorkspaceUpdate, type UpdateProgress, type UpdateStage } from './update-runner';
import './updates.css';

const currentContentSchema = Math.max(...Object.keys(contentSchemaRegistry).map(Number));

function updateError(error: unknown) {
  const code = error && typeof error === 'object' && 'code' in error ? error.code : '';
  if (code === 'UPDATE_WAITING') return 'The last step is still being confirmed. Continue to check that saved step before moving on.';
  if (code === 'UPDATE_STALLED') return 'The update has paused because the next step could not be confirmed. Your completed progress is saved.';
  return customerError(error);
}

export function MaintenanceSettings() {
  const { client, directory, reloadDirectory, reloadProjects } = useApp();
  const upToDate = directory?.writeSchema === currentContentSchema && !directory.activeUpgrade;
  const data = useSettingsLoad(
    () => directory?.isOwner && !upToDate ? client.upgrades.progress(directory.activeUpgrade?.migrationId) : Promise.resolve(null),
    [directory?.writeSchema, directory?.activeUpgrade?.migrationId],
  );
  const [progress, setProgress] = useState<UpdateProgress>();
  const [stage, setStage] = useState<UpdateStage>('checking');
  const [running, setRunning] = useState(false);
  const [pausing, setPausing] = useState(false);
  const [stopped, setStopped] = useState(false);
  const [completed, setCompleted] = useState(false);
  const [failure, setFailure] = useState<unknown>();
  const [refreshFailed, setRefreshFailed] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [confirm, setConfirm] = useState(false);
  const generation = useRef(0), stop = useRef(false), inFlight = useRef(false);

  useEffect(() => {
    const clear = client.auth.onClear(() => {
      generation.current++; stop.current = true; inFlight.current = false;
      setRunning(false); setProgress(undefined); setFailure(undefined); setConfirm(false); setCompleted(false);
    });
    return () => { generation.current++; stop.current = true; clear(); };
  }, [client]);

  async function refreshWorkspace() {
    const version = generation.current;
    setRefreshing(true);
    try {
      await reloadDirectory();
      if (version !== generation.current) return;
      await reloadProjects();
      if (version === generation.current) setRefreshFailed(false);
    } catch {
      if (version === generation.current) setRefreshFailed(true);
    } finally {
      if (version === generation.current) setRefreshing(false);
    }
  }

  function begin() {
    if (inFlight.current) return;
    inFlight.current = true; stop.current = false;
    const version = ++generation.current;
    let publishedActive = !!directory?.activeUpgrade;
    setRunning(true); setPausing(false); setStopped(false); setFailure(undefined); setRefreshFailed(false);
    void runWorkspaceUpdate({
      upgrades: client.upgrades,
      shouldStop: () => stop.current || version !== generation.current,
      onProgress: value => {
        if (version !== generation.current) return;
        setProgress(value);
        if (value.state === 'active' && !publishedActive) {
          publishedActive = true;
          void reloadDirectory().catch(() => {});
        }
      },
      onStage: value => { if (version === generation.current) setStage(value); },
    }).then(async result => {
      if (version !== generation.current) return;
      if (result.state === 'completed') {
        setCompleted(true);
        await refreshWorkspace();
      } else {
        setStopped(true);
        await reloadDirectory().catch(() => {});
        if (version !== generation.current) return;
        // The current batch may have committed while Pause was requested.
        // Refresh its verified count before presenting the saved position.
        try {
          const saved = await client.upgrades.progress();
          if (version === generation.current) setProgress(saved);
        } catch { /* The next continuation will verify the saved operation. */ }
      }
    }).catch(error => {
      if (version === generation.current) { setFailure(error); setStopped(true); }
    }).finally(() => {
      if (version !== generation.current) return;
      inFlight.current = false; setRunning(false); setPausing(false);
    });
  }

  if (!directory?.isOwner) return <EmptyState title="Workspace updates are managed by Owners" description="An Owner will help if your workspace needs an update." icon={<ShieldCheck/>}/>;
  const view = progress ?? data.value;
  const done = completed || upToDate || view?.state === 'completed';
  const pausedByWorkspace = view?.state === 'paused';
  const aborted = view?.state === 'aborted';
  const percent = view ? Math.min(100, Math.round(view.completed / Math.max(1, view.total) * 100)) : 0;
  const phase = done ? 3 : stage === 'finishing' || (view?.state === 'active' && view.completed === view.total) ? 2 : view?.state === 'active' ? 1 : 0;
  const resuming = stopped || view?.state === 'active';
  const status = done ? 'Up to date' : running ? (pausing ? 'Pausing after this step' : stage === 'finishing' ? 'Finishing up' : stage === 'waiting' ? 'Confirming saved progress' : 'Updating automatically') : aborted ? 'Update stopped' : pausedByWorkspace || stopped ? 'Progress saved' : 'Update available';

  return <>
    <PageHead title="Workspace updates" description="Keep your workspace ready for the latest features." eyebrow="Settings"/>
    <Panel title="Content update" description={done ? 'Everything is ready for your next piece of work.' : 'Your existing content and history stay protected throughout the update.'}>
      <LoadState loading={!done && !view && data.loading} error={!done && !view ? data.error : undefined} retry={data.reload}>
        <div className={`workspace-update ${done ? 'is-complete' : ''}`}>
          <div className="workspace-update-summary">
            <span className="workspace-update-icon" aria-hidden="true">{done ? <Check size={23}/> : running ? <Spinner/> : <ShieldCheck size={23}/>}</span>
            <div><Badge tone={done ? 'success' : running ? 'info' : pausedByWorkspace || stopped ? 'warning' : 'neutral'}>{status}</Badge>
              <h3>{done ? 'Your workspace is up to date.' : running ? 'We’ll take it from here.' : aborted ? 'This update has stopped.' : pausedByWorkspace ? 'Waiting for workspace access.' : resuming ? 'Ready to pick up where you left off.' : 'An update is ready.'}</h3>
              <p>{done ? 'Everything is ready for your team’s next steps.' : running ? 'Each step is verified and saved before the next one starts.' : aborted ? 'Check the latest workspace status before starting another update.' : pausedByWorkspace ? 'The update can continue when workspace restrictions are lifted.' : 'Confirm once. We’ll work through the update and finish it automatically.'}</p>
            </div>
          </div>
          {!done && view && <>
            <ol className="workspace-update-steps" aria-label="Update stages">{['Prepare', 'Update content', 'Finish'].map((name,index) => <li key={name} className={phase === index ? 'is-current' : phase > index ? 'is-done' : ''} aria-current={phase === index ? 'step' : undefined}><span aria-hidden="true">{phase > index ? <Check size={12}/> : index + 1}</span>{name}</li>)}</ol>
            <div className="workspace-update-progress">
              <div><span aria-live="polite">{view.completed} of {view.total} records updated</span><strong>{percent}%</strong></div>
              <progress max={Math.max(1,view.total)} value={view.completed} aria-label="Workspace update progress"/>
            </div>
            {!!failure && <div className="notice notice-warning" role="alert">{updateError(failure)}</div>}
            <div className="workspace-update-footer">
              <p>{running ? 'Keep this page open. Pausing finishes the current step and saves your place.' : 'Ordinary editing pauses during the update. Saved work remains available to read.'}</p>
              {running ? <Button variant="secondary" disabled={pausing} onClick={() => { stop.current = true; setPausing(true); }}><Pause size={15}/>{pausing ? 'Pausing…' : 'Pause after this step'}</Button> : !pausedByWorkspace && view.state !== 'aborted' ? <Button onClick={() => setConfirm(true)}>{resuming ? <RefreshCw size={15}/> : null}{resuming ? 'Continue update' : 'Start update'}</Button> : <Button variant="secondary" onClick={() => { setProgress(undefined); data.reload(); }}>Check status</Button>}
            </div>
          </>}
          {done && refreshFailed && <div className="notice notice-warning" role="status"><span>The update is complete. We couldn’t refresh the workspace view.</span><Button variant="ghost" busy={refreshing} onClick={() => void refreshWorkspace()}>Refresh workspace</Button></div>}
        </div>
      </LoadState>
      {!done && !view && !!data.error && <PasswordRefresh onDone={data.reload}/>}
    </Panel>
    {directory.activeRestore && <RestorePanel restoreId={directory.activeRestore.restoreId} onDone={reloadProjects}/>}
    {confirm && <SecureConfirm open onClose={() => setConfirm(false)} title={resuming ? 'Continue workspace update?' : 'Start workspace update?'} description="Ordinary editing will pause. This page will verify each step, update your content, and finish automatically. You can pause after any step." confirmLabel={resuming ? 'Continue update' : 'Start update'} perform={async () => { begin(); }}/>}
  </>;
}
