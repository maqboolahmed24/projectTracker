import { z } from 'zod';
import { identifier } from '../shared/contracts.js';
import { canonicalJson, digestObject } from '../shared/crypto.js';
import { upgradeContext, upgradeReceipt, upgradeView, UPGRADE_MAX_MANIFEST_RECORDS, UPGRADE_MAX_CONTEXT_BYTES,
  type UpgradeContext, type UpgradeStart, type UpgradeFinish, type UpgradeBatch, type UpgradeView, type UpgradeReceipt,
  type upgradeContextRequest, type upgradeStatusRequest } from '../shared/upgrade-api.js';
import { verifySecurityHistory, type SecurityHistoryInput } from '../shared/security-history.js';
import { accessDelivery } from '../shared/access-change.js';
import { AuthenticatedHttp, AuthClientError, type AuthController, type AuthRequestOptions } from './auth-controller.js';
import type { AccessChangeController, AccessChangeTransport } from './access-change-controller.js';
import type { PlanningTransport } from './planning-controller.js';
import type { TeamsTransport } from './teams-controller.js';
import type { CollaborationTransport } from './collaboration-controller.js';
import type { UpgradeNativeProof } from './encrypted-upgrades-crypto.js';
import { teamHistoryPage, TEAM_HISTORY_MAX_BYTES, type TeamHistoryPage } from '../shared/teams.js';
import { TEAM_HISTORY_MAX_REVISIONS } from './teams-crypto.js';
import { IndexedPairingStore } from './pairing.js';
import { IndexedPlanningStore } from './planning-store.js';
import { IndexedCollaborationStore } from './collaboration-store.js';
import { IndexedUpgradeStore, storedUpgradeRequest, upgradeRequestBinding, type StoredUpgradeRequest } from './upgrade-store.js';
import { assertOnline, WriteError } from './write-state.js';

type ContextRequest = z.infer<typeof upgradeContextRequest>;
type StatusRequest = z.infer<typeof upgradeStatusRequest>;
export interface UpgradeTransport {
  readonly origin: string;
  context(input: ContextRequest, options?: AuthRequestOptions): Promise<UpgradeContext>;
  start(input: UpgradeStart, options?: AuthRequestOptions): Promise<UpgradeView>;
  batch(input: UpgradeBatch, options?: AuthRequestOptions): Promise<UpgradeView>;
  finish(input: UpgradeFinish, options?: AuthRequestOptions): Promise<UpgradeView>;
  status(input: StatusRequest, options?: AuthRequestOptions): Promise<UpgradeView>;
}
export class HttpUpgradeTransport extends AuthenticatedHttp implements UpgradeTransport {
  constructor(origin: string, private readonly csrf: () => string | undefined, fetcher?: typeof fetch) { super(origin, fetcher); }
  private request<T>(path: string, body: unknown, schema: z.ZodType<T>, options?: AuthRequestOptions) {
    const csrfToken = this.csrf(); if (!csrfToken) throw new AuthClientError('AUTH_REQUIRED');
    return this.post(`/v1/upgrades/${path}`, body, schema, { ...options, csrfToken });
  }
  context(input: ContextRequest, options?: AuthRequestOptions) { return this.request('context', input, upgradeContext, options); }
  start(input: UpgradeStart, options?: AuthRequestOptions) { return this.request('start', input, upgradeView, options); }
  batch(input: UpgradeBatch, options?: AuthRequestOptions) { return this.request('batch', input, upgradeView, options); }
  finish(input: UpgradeFinish, options?: AuthRequestOptions) { return this.request('finish', input, upgradeView, options); }
  status(input: StatusRequest, options?: AuthRequestOptions) { return this.request('status', input, upgradeView, options); }
  protected override responseLimit(path: string) { return path.startsWith('/v1/upgrades/') ? UPGRADE_MAX_CONTEXT_BYTES : super.responseLimit(path); }
}
const same = (a: unknown, b: unknown) => canonicalJson(a) === canonicalJson(b);
const recordKey = (ref: { kind: string; id: string }) => `${ref.kind}:${ref.id}`;
const identityKind = (kind: string) => ['workspace', 'profile', 'role'].includes(kind);
const planningKind = (kind: string): kind is 'project' | 'phase' | 'milestone' | 'task' | 'blocker' => ['project', 'phase', 'milestone', 'task', 'blocker'].includes(kind);
export interface UpgradeOperationResult { state: 'completed' | 'finishing'; migrationId: string; operationId: string; receipt: UpgradeReceipt }

/** One explicit batch per advance(). No automatic reconnect, rebase, or upgrade loop. */
export class UpgradeController {
  private epoch = 0;
  private mutationRunning = false;
  private readonly requests = new Set<AbortController>();
  private readonly running = new Set<Promise<unknown>>();
  constructor(private readonly auth: AuthController, private readonly transport: UpgradeTransport,
    private readonly operations: IndexedUpgradeStore, private readonly pins: IndexedPairingStore, private readonly planningPins: IndexedPlanningStore,
    private readonly collaborationPins: IndexedCollaborationStore,
    private readonly access: Pick<AccessChangeController, 'refreshKeys'>,
    private readonly security: Pick<AccessChangeTransport, 'delivery' | 'deliveryHistory'>,
    private readonly native: { planning: Pick<PlanningTransport, 'context'>; teams: Pick<TeamsTransport, 'context' | 'history'>; collaboration: Pick<CollaborationTransport, 'context'> },
    private readonly options: { trustedServiceKeys?: Record<string, string>; onWrite?: () => void } = {}) {
    if ([transport.origin, operations.origin, pins.origin, planningPins.origin, collaborationPins.origin].some(origin => origin !== auth.origin)) throw new WriteError('CONFLICT');
  }
  clear() { this.epoch++; for (const request of this.requests) request.abort(); this.requests.clear(); }
  attachAuthLifecycle() { const clear = this.auth.onClear(() => this.clear()), forget = this.auth.onForget(ref => this.forgetDevice(ref)); return () => { clear(); forget(); }; }
  async forgetDevice(reference: { workspaceId: string; accountId: string; deviceId: string }) {
    this.clear(); await Promise.allSettled([...this.running]); await this.operations.forgetDevice(reference);
  }
  private session() {
    const current = this.auth.current();
    if (current?.localAccess !== 'unlocked' || !current.session.deviceId) throw new AuthClientError('AUTH_REQUIRED');
    return { ...current.session, deviceId: current.session.deviceId };
  }
  private check(epoch: number) { if (epoch !== this.epoch) throw new AuthClientError('CANCELLED'); }
  private run<T>(work: (signal: AbortSignal, epoch: number) => Promise<T>, mutation = false): Promise<T> {
    if (mutation && this.mutationRunning) return Promise.reject(new WriteError('RETRY_REQUIRED'));
    if (mutation) this.mutationRunning = true;
    const request = new AbortController(), epoch = this.epoch; this.requests.add(request);
    const result = (async () => { try { const value = await work(request.signal, epoch); this.check(epoch); return value; }
      finally { this.requests.delete(request); if (mutation) this.mutationRunning = false; } })();
    this.running.add(result); void result.finally(() => this.running.delete(result)).catch(() => {}); return result;
  }
  private async keys(signal: AbortSignal, epoch: number) {
    const session = this.session(), pin = await this.pins.pin(session.workspaceId); this.check(epoch);
    if (!pin) throw new AuthClientError('CONTEXT_MISMATCH');
    await this.access.refreshKeys(); this.check(epoch);
    const delivery = accessDelivery.parse(await this.security.delivery({ workspaceId: session.workspaceId }, { signal })); this.check(epoch);
    const response = await this.security.deliveryHistory({ workspaceId: session.workspaceId, operationId: crypto.randomUUID() }, { signal }); this.check(epoch);
    if (!same(response.anchor, response.current) || !same(delivery.current, response.current) || delivery.workspaceId !== session.workspaceId ||
      delivery.accountId !== session.accountId || delivery.deviceId !== session.deviceId) throw new WriteError('CONFLICT');
    const history: SecurityHistoryInput = { workspaceId: session.workspaceId, origin: this.auth.origin, genesisFingerprint: pin.genesisFingerprint,
      genesis: response.genesis, transitions: response.transitions, expected: response.anchor, pin, trustedServiceKeys: this.options.trustedServiceKeys ?? {} };
    const state = await verifySecurityHistory(history); this.check(epoch);
    const person = state.profiles[session.accountId], device = state.devices[session.deviceId];
    if (!person?.active || !person.owner || !device?.active || device.accountId !== session.accountId ||
      person.credentialGeneration !== session.credentialGeneration || person.sessionGeneration !== session.sessionGeneration || state.dataGeneration !== session.dataGeneration)
      throw new WriteError('RESTRICTED');
    return { history, accountId: session.accountId, deviceId: session.deviceId, materials: delivery.materials };
  }
  private async inventory(migrationId: string | undefined, operationId: string, signal: AbortSignal, epoch: number) {
    const workspaceId = this.session().workspaceId, request = { workspaceId, operationId: identifier.parse(operationId), ...(migrationId ? { migrationId: identifier.parse(migrationId) } : {}) };
    const context = upgradeContext.parse(await this.transport.context(request, { signal })); this.check(epoch);
    const b = context.binding, session = this.session();
    if (b.workspaceId !== workspaceId || b.operationId !== operationId || migrationId && b.migrationId !== migrationId ||
      b.accountId !== session.accountId || b.deviceId !== session.deviceId || b.dataGeneration !== session.dataGeneration) throw new WriteError('CONFLICT');
    const records = [...context.records], seen = new Set(records.map(r => recordKey(r.reference))), cursors = new Set<string>();
    let next = context.nextCursor;
    const stable = (page: UpgradeContext) => { const { issuedAt: _issued, expiresAt: _expires, ...binding } = page.binding;
      return { binding, state: page.state, manifest: page.manifest, completed: page.completed, start: page.start, finish: page.finish }; };
    if (seen.size !== records.length) throw new WriteError('CONFLICT');
    for (let page = 1; next !== null; page++) {
      if (page >= Math.ceil(UPGRADE_MAX_MANIFEST_RECORDS / 32) || cursors.has(next) || !records.length || next !== recordKey(records.at(-1)!.reference)) throw new WriteError('CONFLICT');
      cursors.add(next);
      const response = upgradeContext.parse(await this.transport.context({ ...request, migrationId: b.migrationId, after: next }, { signal })); this.check(epoch);
      if (!same(stable(context), stable(response))) throw new WriteError('CONFLICT');
      for (const record of response.records) {
        const key = recordKey(record.reference); if (seen.has(key) || key <= next) throw new WriteError('CONFLICT'); seen.add(key); records.push(record);
      }
      next = response.nextCursor;
    }
    if (records.length !== context.manifest.length || !same(records.map(r => recordKey(r.reference)), context.manifest.map(recordKey)) ||
      b.manifestDigest !== await digestObject(context.manifest) || b.completedDigest !== await digestObject(context.completed) ||
      b.manifestCount !== context.manifest.length || b.completedCount !== context.completed.length) throw new WriteError('CONFLICT');
    return { context, records };
  }
  private async begin(signal: AbortSignal, epoch: number) {
    assertOnline();
    if ((await this.pending()).length) throw new WriteError('RETRY_REQUIRED'); this.check(epoch);
    return this.keys(signal, epoch);
  }
  private async remember(value: StoredUpgradeRequest, signal: AbortSignal, epoch: number) {
    const record = storedUpgradeRequest.parse(value); this.check(epoch);
    await this.operations.put(record); this.check(epoch);
    return this.submit(record, signal, epoch);
  }
  private async submit(record: StoredUpgradeRequest, signal: AbortSignal, epoch: number): Promise<UpgradeOperationResult> {
    assertOnline(); const session = this.session(), b = upgradeRequestBinding(record);
    if (record.origin !== this.auth.origin || record.workspaceId !== session.workspaceId || record.accountId !== session.accountId || record.deviceId !== session.deviceId ||
      record.dataGeneration !== session.dataGeneration || 'credentialGeneration' in b && b.credentialGeneration !== session.credentialGeneration ||
      'sessionGeneration' in b && b.sessionGeneration !== session.sessionGeneration) throw new WriteError('CONFLICT');
    const requestHash = await digestObject(record.payload), ref = { workspaceId: record.workspaceId, migrationId: record.migrationId,
      operationId: record.operationId, dataGeneration: record.dataGeneration, requestHash };
    let result = upgradeView.parse(await this.transport.status(ref, { signal })); this.check(epoch);
    if (result.state === 'absent') {
      if (result.receipt || !('expiresAt' in b) || Date.parse(b.expiresAt) <= Date.now()) throw new WriteError('CONFLICT');
      result = record.kind === 'start' ? await this.transport.start(record.payload, { signal }) : record.kind === 'finish' ? await this.transport.finish(record.payload, { signal }) :
        await this.transport.batch({ workspaceId: record.workspaceId, migrationId: record.migrationId, kind: record.kind, payload: record.payload }, { signal });
      this.check(epoch); result = upgradeView.parse(result);
    }
    const receipt = upgradeReceipt.parse(result.receipt), manifestDigest = record.kind === 'start' || record.kind === 'finish' ? record.payload.body.binding.manifestDigest :
      ('upgrade' in record.payload.mutation.body ? record.payload.mutation.body.upgrade?.manifestDigest : undefined);
    if (result.state === 'absent' || receipt.workspaceId !== record.workspaceId || receipt.migrationId !== record.migrationId || receipt.operationId !== record.operationId ||
      receipt.actorId !== record.accountId || receipt.dataGeneration !== record.dataGeneration || receipt.requestHash !== requestHash || receipt.manifestDigest !== manifestDigest ||
      receipt.kind !== (record.kind === 'start' || record.kind === 'finish' ? record.kind : 'batch')) throw new WriteError('CONFLICT');
    if (result.state === 'completed') {
      await this.confirmCommitted(record, signal, epoch); this.check(epoch);
      await this.operations.remove(record.workspaceId, record.operationId); this.check(epoch); this.options.onWrite?.();
    }
    return { state: result.state, migrationId: record.migrationId, operationId: record.operationId, receipt };
  }
  private async confirmCommitted(record: StoredUpgradeRequest, signal: AbortSignal, epoch: number) {
    const keys = await this.keys(signal, epoch);
    if (record.kind === 'start' || record.kind === 'finish' || record.kind === 'identity') {
      const committed = record.kind === 'identity' ? { ...record.payload.mutation, upgradeItems: record.payload.upgradeItems } : record.payload;
      const expected = await digestObject(committed), actual = await Promise.all(keys.history.transitions.map(transition => digestObject(transition)));
      if (!actual.includes(expected)) throw new WriteError('CONFLICT');
    } else if (record.kind === 'planning') {
      const b = record.payload.mutation.body.binding, context = await this.native.planning.context({ workspaceId: b.workspaceId, projectId: b.projectId, operationId: b.operationId }, { signal }); this.check(epoch);
      const pin = await this.planningPins.pin({ workspaceId: b.workspaceId, projectId: b.projectId }); this.check(epoch);
      const view = await this.auth.worker.readPlanning({ ...keys, context, ...(pin ? { pin } : {}) }, { signal }); this.check(epoch);
      if (!context.history.some(mutation => same(mutation, record.payload.mutation))) throw new WriteError('CONFLICT');
      await this.planningPins.recordPin(view.pin); this.check(epoch);
    } else if (record.kind === 'collaboration') {
      const b = record.payload.mutation.body.binding, reference = { workspaceId: b.workspaceId, projectId: b.projectId, entryId: b.entryId };
      const context = await this.native.collaboration.context({ ...reference, operationId: b.operationId, kind: b.kind }, { signal }); this.check(epoch);
      if (!context.entry || !context.entry.events?.some(payload => same(payload, record.payload))) throw new WriteError('CONFLICT');
      const pin = await this.planningPins.pin(reference), entryPin = await this.collaborationPins.pin(reference); this.check(epoch);
      const view = await this.auth.worker.readCollaboration({ ...keys, context: context.planning, entries: [context.entry], includeHidden: true,
        ...(pin ? { pin } : {}), ...(entryPin ? { entryPins: [entryPin] } : {}) }, { signal }); this.check(epoch);
      if (view.records.length !== 1) throw new WriteError('CONFLICT');
      await this.planningPins.recordPin(view.planningPin); this.check(epoch);
      await this.collaborationPins.recordPin(view.records[0]!.pin); this.check(epoch);
    } else {
      const b = record.payload.mutation.body.binding, pages: TeamHistoryPage[] = [];
      let afterRevision = '0', anchor: TeamHistoryPage['anchor'] | undefined, count = 0, bytes = 0;
      while (count < TEAM_HISTORY_MAX_REVISIONS) {
        const page = teamHistoryPage.parse(await this.native.teams.history({ workspaceId: b.workspaceId, teamId: b.teamId, afterRevision, ...(anchor ? { anchor } : {}), limit: 100 }, { signal })); this.check(epoch);
        count += page.records.length; bytes += new TextEncoder().encode(canonicalJson(page)).byteLength;
        if (count > TEAM_HISTORY_MAX_REVISIONS || bytes > TEAM_HISTORY_MAX_BYTES || page.workspaceId !== b.workspaceId || page.teamId !== b.teamId ||
          anchor && !same(page.anchor, anchor) || page.securityHead !== keys.history.expected.securityHead || page.securityVersion !== keys.history.expected.securityVersion ||
          page.dataGeneration !== record.dataGeneration || page.records[0]!.payload.envelope.header.revision !== String(BigInt(afterRevision) + 1n) ||
          page.complete !== (page.nextRevision === null)) throw new WriteError('CONFLICT');
        pages.push(page); anchor = page.anchor;
        if (page.complete) break;
        if (page.nextRevision !== page.records.at(-1)!.payload.envelope.header.revision || BigInt(page.nextRevision!) <= BigInt(afterRevision)) throw new WriteError('CONFLICT');
        afterRevision = page.nextRevision!;
      }
      if (!pages.at(-1)?.complete || !pages.some(page => page.records.some(entry => same(entry.payload, record.payload)))) throw new WriteError('CONFLICT');
      await this.auth.worker.readTeamHistory({ ...keys, pages }, { signal }); this.check(epoch);
    }
    await this.pins.recordVerifiedHistory(keys.history); this.check(epoch);
  }
  private stored(kind: StoredUpgradeRequest['kind'], payload: unknown, context: UpgradeContext): StoredUpgradeRequest {
    const b = context.binding;
    return storedUpgradeRequest.parse({ version: 1, kind, origin: this.auth.origin, workspaceId: b.workspaceId, accountId: b.accountId, deviceId: b.deviceId,
      operationId: b.operationId, migrationId: b.migrationId, dataGeneration: b.dataGeneration, payload });
  }
  progress(migrationId?: string) { return this.run(async (signal, epoch) => {
    const keys = await this.keys(signal, epoch), { context } = await this.inventory(migrationId, crypto.randomUUID(), signal, epoch);
    if (context.binding.securityHead !== keys.history.expected.securityHead || context.binding.securityVersion !== keys.history.expected.securityVersion) throw new WriteError('CONFLICT');
    return { state: context.state, migrationId: context.binding.migrationId, completed: context.completed.length, total: context.manifest.length, writeSchema: context.binding.writeSchema };
  }); }
  start(operationId = crypto.randomUUID()) { return this.run(async (signal, epoch) => {
    const keys = await this.begin(signal, epoch), { context } = await this.inventory(undefined, operationId, signal, epoch);
    if (context.state !== 'available') throw new WriteError('RESTRICTED');
    const payload = await this.auth.worker.prepareUpgradeStart({ ...keys, context }, { signal }); this.check(epoch);
    return this.remember(this.stored('start', payload, context), signal, epoch);
  }, true); }
  advance(migrationId: string, operationId = crypto.randomUUID()) { return this.run(async (signal, epoch) => {
    const keys = await this.begin(signal, epoch), { context, records } = await this.inventory(migrationId, operationId, signal, epoch);
    if (context.state !== 'active') throw new WriteError('RESTRICTED');
    const first = records.find(record => record.reference.schema === 1);
    if (!first) return { state: 'ready_to_finish' as const, migrationId, completed: context.completed.length, total: context.manifest.length };
    const upgrade = { migrationId, manifestDigest: context.binding.manifestDigest }, ref = first.reference;
    let stored: StoredUpgradeRequest;
    if (identityKind(ref.kind)) {
      const selected = records.filter(record => record.reference.schema === 1 && identityKind(record.reference.kind)).slice(0, 32);
      const payload = await this.auth.worker.prepareIdentityUpgrade({ ...keys, context, records: selected }, { signal }); this.check(epoch);
      stored = this.stored('identity', payload, context);
    } else if (planningKind(ref.kind)) {
      const current = await this.native.planning.context({ workspaceId: context.binding.workspaceId, projectId: ref.projectId!, operationId }, { signal }); this.check(epoch);
      const pin = await this.planningPins.pin({ workspaceId: context.binding.workspaceId, projectId: ref.projectId! }); this.check(epoch);
      const selected = records.filter(record => record.reference.schema === 1 && record.reference.projectId === ref.projectId && planningKind(record.reference.kind)).slice(0, 32)
        .map(record => ({ kind: record.reference.kind as 'project' | 'phase' | 'milestone' | 'task' | 'blocker', id: record.reference.id }));
      const payload = await this.auth.worker.preparePlanning({ ...keys, context: current, ...(pin ? { pin } : {}), command: { action: 'upgrade_content', records: selected }, upgrade }, { signal }); this.check(epoch);
      stored = this.stored('planning', payload, context);
    } else if (ref.kind === 'team') {
      const current = await this.native.teams.context({ workspaceId: context.binding.workspaceId, operationId, teamId: ref.id, action: 'upgrade_content' }, { signal }); this.check(epoch);
      const payload = await this.auth.worker.prepareTeamUpgrade({ ...keys, context: current, ...upgrade }, { signal }); this.check(epoch);
      stored = this.stored('team', payload, context);
    } else {
      if (ref.kind !== 'comment' && ref.kind !== 'update') throw new WriteError('CONFLICT');
      const current = await this.native.collaboration.context({ workspaceId: context.binding.workspaceId, operationId, projectId: ref.projectId!, entryId: ref.id, kind: ref.kind }, { signal }); this.check(epoch);
      const pin = await this.planningPins.pin({ workspaceId: context.binding.workspaceId, projectId: ref.projectId! }); this.check(epoch);
      const entryPin = await this.collaborationPins.pin({ workspaceId: context.binding.workspaceId, projectId: ref.projectId!, entryId: ref.id }); this.check(epoch);
      const payload = await this.auth.worker.prepareCollaborationUpgrade({ ...keys, context: current, ...(pin ? { pin } : {}), ...(entryPin ? { entryPin } : {}), ...upgrade }, { signal }); this.check(epoch);
      stored = this.stored('collaboration', payload, context);
    }
    return this.remember(stored, signal, epoch);
  }, true); }
  finish(migrationId: string, operationId = crypto.randomUUID()) { return this.run(async (signal, epoch) => {
    const keys = await this.begin(signal, epoch), { context, records } = await this.inventory(migrationId, operationId, signal, epoch);
    if (context.state !== 'active' || context.completed.length !== context.manifest.length || records.some(record => record.reference.schema !== 2)) throw new WriteError('RESTRICTED');
    const proofs: UpgradeNativeProof[] = [], projects = new Set<string>();
    for (const record of records) {
      const ref = record.reference;
      if (planningKind(ref.kind)) {
        if (projects.has(ref.projectId!)) continue; projects.add(ref.projectId!);
        proofs.push({ kind: 'planning', context: await this.native.planning.context({ workspaceId: context.binding.workspaceId, projectId: ref.projectId!, operationId }, { signal }) });
      } else if (ref.kind === 'team') {
        proofs.push({ kind: 'team', context: await this.native.teams.context({ workspaceId: context.binding.workspaceId, operationId, teamId: ref.id, action: 'upgrade_content' }, { signal }) });
      } else if (ref.kind === 'comment' || ref.kind === 'update') {
        proofs.push({ kind: 'collaboration', context: await this.native.collaboration.context({ workspaceId: context.binding.workspaceId, operationId, projectId: ref.projectId!, entryId: ref.id, kind: ref.kind }, { signal }) });
      }
      this.check(epoch);
    }
    const payload = await this.auth.worker.prepareUpgradeFinish({ ...keys, context, records, proofs }, { signal }); this.check(epoch);
    return this.remember(this.stored('finish', payload, context), signal, epoch);
  }, true); }
  pending() { const session = this.session(); return this.operations.list({ workspaceId: session.workspaceId, accountId: session.accountId, deviceId: session.deviceId }); }
  resume(operationId: string) { return this.run(async (signal, epoch) => {
    const record = await this.operations.get(this.session().workspaceId, identifier.parse(operationId)); this.check(epoch);
    if (!record) throw new WriteError('CONFLICT'); return this.submit(record, signal, epoch);
  }, true); }
  discard(operationId: string) { return this.run(async (signal, epoch) => {
    assertOnline(); const session = this.session(), record = await this.operations.get(session.workspaceId, identifier.parse(operationId)); this.check(epoch);
    if (!record || record.accountId !== session.accountId || record.deviceId !== session.deviceId || record.dataGeneration !== session.dataGeneration) throw new WriteError('CONFLICT');
    const result = await this.transport.status({ workspaceId: record.workspaceId, migrationId: record.migrationId, operationId: record.operationId,
      dataGeneration: record.dataGeneration, requestHash: await digestObject(record.payload) }, { signal }); this.check(epoch);
    if (result.state !== 'absent' || result.receipt) throw new WriteError('RETRY_REQUIRED');
    await this.operations.remove(record.workspaceId, record.operationId); this.check(epoch);
  }, true); }
}
