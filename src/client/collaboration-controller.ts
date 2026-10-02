import { z } from 'zod';
import { assertOnline, isWriteConflict, WriteConflict, WriteError } from './write-state.js';
import { identifier } from '../shared/contracts.js';
import { canonicalJson, digestObject } from '../shared/crypto.js';
import { collaborationContext, collaborationHistory, collaborationListRequest, collaborationPage, collaborationReceipt, collaborationView,
  assertCollaborationCurrentBinding, validateCollaborationPayload, verifyCollaborationEntry,
  type CollaborationCommand, type CollaborationContext, type CollaborationHistory, type CollaborationPage, type CollaborationPayload,
  type CollaborationReceipt, type CollaborationView } from '../shared/collaboration.js';
import { verifySecurityHistory, type SecurityHistoryInput } from '../shared/security-history.js';
import type { PlanningContext } from '../shared/planning-api.js';
import { AuthenticatedHttp, AuthClientError, type AuthController, type AuthRequestOptions } from './auth-controller.js';
import { IndexedPairingStore } from './pairing.js';
import { IndexedPlanningStore } from './planning-store.js';
import type { PlanningTransport } from './planning-controller.js';
import type { AccessChangeController } from './access-change-controller.js';
import { planningSecurityResolver } from './planning-crypto.js';
import { CollaborationClientError, type ReadCollaborationInput, type ReadableCollaboration, type ReadableCollaborationEntry } from './collaboration-crypto.js';
import { IndexedCollaborationStore, type StoredCollaborationOperation } from './collaboration-store.js';

type Kind = 'comment' | 'update';
type Reference = { workspaceId: string; projectId: string; operationId: string };
type EntryReference = Reference & { entryId: string; kind: Kind };
type ListRequest = z.input<typeof collaborationListRequest>;
const same = (a: unknown, b: unknown) => canonicalJson(a) === canonicalJson(b);
export interface CollaborationTransport {
  readonly origin: string;
  context(input: EntryReference, options?: AuthRequestOptions): Promise<CollaborationContext>;
  save(payload: CollaborationPayload, options?: AuthRequestOptions): Promise<CollaborationView>;
  status(input: Reference & { dataGeneration: string; requestHash: string }, options?: AuthRequestOptions): Promise<CollaborationView>;
  list(input: ListRequest, options?: AuthRequestOptions): Promise<CollaborationPage>;
  history(input: EntryReference, options?: AuthRequestOptions): Promise<CollaborationHistory>;
}
export class HttpCollaborationTransport extends AuthenticatedHttp implements CollaborationTransport {
  constructor(origin: string, private readonly csrfToken: () => string | undefined, fetcher?: typeof fetch) { super(origin, fetcher); }
  private request<T>(path: string, body: unknown, schema: z.ZodType<T>, options?: AuthRequestOptions): Promise<T> {
    const csrfToken = this.csrfToken(); if (!csrfToken) throw new AuthClientError('AUTH_REQUIRED');
    return this.post(`/v1/collaboration/${path}`, body, schema, { ...options, csrfToken });
  }
  context(input: EntryReference, options?: AuthRequestOptions) { return this.request('context', input, collaborationContext, options); }
  save(input: CollaborationPayload, options?: AuthRequestOptions) { return this.request('save', input, collaborationView, options); }
  status(input: Reference & { dataGeneration: string; requestHash: string }, options?: AuthRequestOptions) { return this.request('status', input, collaborationView, options); }
  list(input: ListRequest, options?: AuthRequestOptions) { return this.request('list', collaborationListRequest.parse(input), collaborationPage, options); }
  history(input: EntryReference, options?: AuthRequestOptions) { return this.request('history', input, collaborationHistory, options); }
  protected override responseLimit(path: string): number { return ['/v1/collaboration/context', '/v1/collaboration/list', '/v1/collaboration/history'].includes(path) ? 24 * 1024 * 1024 : super.responseLimit(path); }
}
export interface CollaborationProgress { state: 'completed'; operationId: string; projectId: string; entryId: string; kind: Kind; receipt: CollaborationReceipt }
export interface PostCommentInput { projectId: string; taskId: string; text: string; entryId?: string; operationId?: string }
export interface PostUpdateInput { projectId: string; phaseId?: string | null; text: string; entryId?: string; operationId?: string }
export interface HideCollaborationInput { projectId: string; entryId: string; kind: Kind; reason: string; operationId?: string; reviewed: {revision:string;head:string} }
export interface CollaborationReadInput { projectId: string; kind: Kind; taskId?: string; phaseId?: string; includeHidden?: boolean; anchor?: string; after?: string; limit?: number }
export interface ReadableCollaborationPage { records: ReadableCollaborationEntry[]; anchor: string; nextCursor: string | null; complete: boolean }
export class CollaborationController {
  private epoch = 0;
  private readonly requests = new Set<AbortController>();
  private readonly running = new Set<Promise<unknown>>();
  constructor(private readonly auth: AuthController, private readonly transport: CollaborationTransport, private readonly operations: IndexedCollaborationStore,
    private readonly pins: IndexedPairingStore, private readonly planningPins: IndexedPlanningStore,
    private readonly access: Pick<AccessChangeController, 'refreshKeys'>, private readonly security: Pick<PlanningTransport, 'history'>,
    private readonly options: { trustedServiceKeys?: Record<string, string> } = {}) {
    if ([transport.origin, operations.origin, pins.origin, planningPins.origin].some((origin) => origin !== auth.origin)) throw new CollaborationClientError('CONFLICT');
  }
  clear(): void { this.epoch++; for (const request of this.requests) request.abort(); this.requests.clear(); }
  attachAuthLifecycle(): () => void { const clear = this.auth.onClear(() => this.clear()), forget = this.auth.onForget((ref) => this.forgetDevice(ref)); return () => { clear(); forget(); }; }
  async forgetDevice(reference: { workspaceId: string; accountId: string; deviceId: string }): Promise<void> {
    this.clear(); await Promise.allSettled([...this.running]); await this.operations.forgetDevice(reference);
  }
  private check(epoch: number): void { if (epoch !== this.epoch) throw new CollaborationClientError('CANCELLED'); }
  private run<T>(work: (signal: AbortSignal, epoch: number) => Promise<T>): Promise<T> {
    const request = new AbortController(), epoch = this.epoch; this.requests.add(request);
    const promise = work(request.signal, epoch).then((result) => { this.check(epoch); return result; }); this.running.add(promise);
    void promise.finally(() => { this.requests.delete(request); this.running.delete(promise); }).catch(() => {}); return promise;
  }
  private session() { const current = this.auth.current(); if (current?.localAccess !== 'unlocked' || !current.session.deviceId) throw new AuthClientError('AUTH_REQUIRED'); return current.session; }
  private async historyInput(context: PlanningContext, signal: AbortSignal, epoch: number): Promise<SecurityHistoryInput> {
    const b = context.binding, session = this.session(), pin = await this.pins.pin(session.workspaceId); this.check(epoch);
    if (!pin) throw new CollaborationClientError('TRUST_REQUIRED');
    if (b.workspaceId !== session.workspaceId || b.accountId !== session.accountId || b.deviceId !== session.deviceId) throw new CollaborationClientError('CONFLICT');
    const response = await this.security.history({ workspaceId: b.workspaceId, projectId: b.projectId, operationId: b.operationId }, { signal }); this.check(epoch);
    if (!same(response.anchor, response.current)) throw new CollaborationClientError('CONFLICT');
    const input: SecurityHistoryInput = { workspaceId: b.workspaceId, origin: this.auth.origin, genesisFingerprint: pin.genesisFingerprint,
      genesis: response.genesis, transitions: response.transitions, expected: response.anchor, pin, trustedServiceKeys: this.options.trustedServiceKeys ?? {} },
      state = await verifySecurityHistory(input); this.check(epoch);
    const profile = state.profiles[session.accountId], device = state.devices[session.deviceId!];
    if (!profile?.active || !device?.active || device.accountId !== session.accountId || profile.credentialGeneration !== session.credentialGeneration ||
      profile.sessionGeneration !== session.sessionGeneration || state.dataGeneration !== session.dataGeneration) throw new CollaborationClientError('CONFLICT');
    return input;
  }
  private async opened(context: PlanningContext, entries: ReadCollaborationInput['entries'], includeHidden: boolean, signal: AbortSignal, epoch: number) {
    const session = this.session(), history = await this.historyInput(context, signal, epoch), pin = await this.planningPins.pin({ workspaceId: session.workspaceId, projectId: context.binding.projectId }); this.check(epoch);
    const entryPins = [];
    for (const entry of entries) {
      const entryId = entry.origin.kind === 'post' ? entry.origin.payload.mutation.body.binding.entryId : entry.origin.entryId,
        known = await this.operations.pin({ workspaceId: session.workspaceId, projectId: context.binding.projectId, entryId }); this.check(epoch); if (known) entryPins.push(known);
    }
    const input: ReadCollaborationInput = { context, entries, history, accountId: session.accountId, deviceId: session.deviceId!, includeHidden, entryPins, ...(pin ? { pin } : {}) },
      view = await this.auth.worker.readCollaboration(input, { signal }); this.check(epoch);
    await this.planningPins.recordPin(view.planningPin); this.check(epoch); await this.pins.recordVerifiedHistory(history); this.check(epoch);
    for (const entry of view.records) { await this.operations.recordPin(entry.pin); this.check(epoch); }
    return { input, view };
  }
  private async current(reference: EntryReference, signal: AbortSignal, epoch: number) {
    const context = collaborationContext.parse(await this.transport.context(reference, { signal })); this.check(epoch);
    if (Object.entries(reference).some(([key, value]) => context.binding[key as keyof typeof reference] !== value)) throw new CollaborationClientError('INVALID_COLLABORATION');
    const opened = await this.opened(context.planning, context.entry ? [context.entry] : [], true, signal, epoch);
    return { context, ...opened };
  }
  private async committed(receiptValue: CollaborationReceipt, record: StoredCollaborationOperation, signal: AbortSignal, epoch: number): Promise<CollaborationProgress> {
    const receipt = collaborationReceipt.parse(receiptValue), payload = record.payload, b = payload.mutation.body.binding,
      command=payload.mutation.body.command,revision = 'expectedRevision' in command ? String(BigInt(command.expectedRevision)+1n) : '1';
    if (receipt.workspaceId !== b.workspaceId || receipt.projectId !== b.projectId || receipt.operationId !== b.operationId || receipt.entryId !== b.entryId ||
      receipt.kind !== b.kind || receipt.dataGeneration !== b.dataGeneration || receipt.revision !== revision || receipt.requestHash !== await digestObject(payload) ||
      receipt.head !== await digestObject(payload.mutation) || !same(receipt.mutation, payload.mutation)) throw new CollaborationClientError('INVALID_COLLABORATION'); this.check(epoch);
    const history = collaborationHistory.parse(await this.transport.history({ workspaceId: b.workspaceId, projectId: b.projectId, operationId: b.operationId, entryId: b.entryId, kind: b.kind }, { signal })); this.check(epoch);
    const present = history.entry.origin.kind === 'post' && same(history.entry.origin.payload, payload) || history.entry.moderation !== null && same(history.entry.moderation, payload)||history.entry.events?.some(event=>same(event,payload));
    if (!present) throw new CollaborationClientError('INVALID_COLLABORATION'); await this.opened(history.planning, [history.entry], true, signal, epoch);
    return { state: 'completed', operationId: b.operationId, projectId: b.projectId, entryId: b.entryId, kind: b.kind, receipt };
  }
  private async finish(record: StoredCollaborationOperation, signal: AbortSignal, epoch: number): Promise<CollaborationProgress> {
    assertOnline();
    const b = record.payload.mutation.body.binding, session = this.session();
    if (record.workspaceId !== session.workspaceId || record.accountId !== session.accountId || record.deviceId !== session.deviceId || b.dataGeneration !== session.dataGeneration) throw new CollaborationClientError('CONFLICT');
    await this.access.refreshKeys(); this.check(epoch);
    const reference = { workspaceId: b.workspaceId, projectId: b.projectId, operationId: b.operationId },
      status = collaborationView.parse(await this.transport.status({ ...reference, dataGeneration: b.dataGeneration, requestHash: await digestObject(record.payload) }, { signal })); this.check(epoch);
    if (status.state === 'completed') { if (!status.receipt) throw new CollaborationClientError('INVALID_COLLABORATION'); return this.committed(status.receipt, record, signal, epoch); }
    if (status.receipt || Date.parse(b.expiresAt) <= Date.now()) throw new CollaborationClientError('EXPIRED');
    const current = await this.current({ ...reference, entryId: b.entryId, kind: b.kind }, signal, epoch), security = await verifySecurityHistory(current.input.history); this.check(epoch);
    await assertCollaborationCurrentBinding(b, current.context.planning, new Date());
    const prior = current.context.entry ? await verifyCollaborationEntry(current.context.entry, current.context.planning, planningSecurityResolver(current.input.history, security)) : null;
    await validateCollaborationPayload(record.payload, b, current.context.planning.graph, prior); this.check(epoch);
    const saved = collaborationView.parse(await this.transport.save(record.payload, { signal })); this.check(epoch);
    if (saved.state !== 'completed' || !saved.receipt) throw new CollaborationClientError('INVALID_COLLABORATION'); return this.committed(saved.receipt, record, signal, epoch);
  }
  private change(value: PostCommentInput | PostUpdateInput | HideCollaborationInput, action: 'post_comment' | 'post_update' | 'hide'): Promise<CollaborationProgress> {
    const input=structuredClone(value);
    return this.run(async (signal, epoch) => {
      assertOnline();if(action==='hide'&&!('reviewed' in input&&input.reviewed))throw new WriteError('REVIEW_REQUIRED');
      const session = this.session(), kind: Kind = action === 'post_comment' ? 'comment' : action === 'post_update' ? 'update' : (input as HideCollaborationInput).kind,
        reference: EntryReference = { workspaceId: session.workspaceId, projectId: identifier.parse(input.projectId), operationId: input.operationId ?? crypto.randomUUID(),
          entryId: identifier.parse(input.entryId ?? crypto.randomUUID()), kind };
      if (await this.operations.get(reference.workspaceId, reference.operationId)) throw new CollaborationClientError('CONFLICT'); this.check(epoch);
      await this.access.refreshKeys(); this.check(epoch); const current = await this.current(reference, signal, epoch), prior = current.view.records[0];
      if(action==='hide'&&prior&&'reviewed' in input&&(input.reviewed.revision!==prior.revision||input.reviewed.head!==prior.head))throw new WriteConflict(reference.operationId,prior,input);
      let command: CollaborationCommand;
      if (action === 'post_comment') command = { action, entryId: reference.entryId, taskId: (input as PostCommentInput).taskId };
      else if (action === 'post_update') command = { action, entryId: reference.entryId, phaseId: (input as PostUpdateInput).phaseId ?? null };
      else { if (!prior) throw new CollaborationClientError('NOT_FOUND'); if (prior.hidden) throw new CollaborationClientError('CONFLICT');
        command = { action: kind === 'comment' ? 'hide_comment' : 'hide_update', entryId: reference.entryId, expectedRevision: prior.revision, previousHead: prior.head, originalDigest: prior.originalDigest }; }
      const payload = await this.auth.worker.prepareCollaboration({ context: current.context, history: current.input.history, accountId: session.accountId, deviceId: session.deviceId!, command,
        ...(current.input.pin ? { pin: current.input.pin } : {}), ...(prior ? { entryPin: prior.pin } : {}),
        ...(action === 'hide' ? { reason: (input as HideCollaborationInput).reason } : { text: (input as PostCommentInput).text }) }, { signal }); this.check(epoch);
      const record: StoredCollaborationOperation = { version: 1, origin: this.auth.origin, workspaceId: reference.workspaceId, operationId: reference.operationId, accountId: session.accountId, deviceId: session.deviceId!, payload };
      await this.operations.put(record); this.check(epoch); const readback = await this.operations.get(reference.workspaceId, reference.operationId); this.check(epoch);
      if (!readback || !same(record, readback)) throw new CollaborationClientError('STORAGE');
      try{return await this.finish(readback, signal, epoch);}catch(error){if(action==='hide'&&isWriteConflict(error))throw new WriteConflict(reference.operationId,await this.history(reference),input);throw error;}
    });
  }
  postComment(input: PostCommentInput) { return this.change(input, 'post_comment'); }
  postUpdate(input: PostUpdateInput) { return this.change(input, 'post_update'); }
  hide(input: HideCollaborationInput) { return this.change(input, 'hide'); }
  resume(operationId: string): Promise<CollaborationProgress> { return this.run(async (signal, epoch) => {
    assertOnline();
    const session = this.session(), record = await this.operations.get(session.workspaceId, identifier.parse(operationId)); this.check(epoch);
    if (!record) throw new CollaborationClientError('NOT_FOUND'); return this.finish(record, signal, epoch);
  }); }
  pending() { const session = this.session(); return this.operations.list({ workspaceId: session.workspaceId, accountId: session.accountId, deviceId: session.deviceId! }); }
  read(input: CollaborationReadInput): Promise<ReadableCollaborationPage> { return this.run(async (signal, epoch) => {
    const request = collaborationListRequest.parse({ ...input, workspaceId: this.session().workspaceId });
    await this.access.refreshKeys(); this.check(epoch);
    const page = collaborationPage.parse(await this.transport.list(request, { signal })); this.check(epoch);
    if (page.planning.binding.projectId !== request.projectId || request.anchor !== undefined && request.anchor !== page.anchor || page.complete !== (page.nextCursor === null)) throw new CollaborationClientError('INVALID_COLLABORATION');
    const { view } = await this.opened(page.planning, page.entries, request.includeHidden === true, signal, epoch);
    if (view.records.some((record, index) => record.kind !== request.kind || request.taskId !== undefined && record.taskId !== request.taskId ||
      request.phaseId !== undefined && record.phaseId !== request.phaseId || request.after !== undefined && record.entryId <= request.after ||
      index > 0 && record.entryId <= view.records[index - 1]!.entryId) || page.nextCursor !== null && page.nextCursor !== view.records.at(-1)?.entryId) throw new CollaborationClientError('INVALID_COLLABORATION');
    return { records: view.records, anchor: page.anchor, nextCursor: page.nextCursor, complete: page.complete };
  }); }
  history(input: { projectId: string; entryId: string; kind: Kind }): Promise<ReadableCollaborationEntry> { return this.run(async (signal, epoch) => {
    const reference = { ...input, workspaceId: this.session().workspaceId, operationId: crypto.randomUUID() };
    await this.access.refreshKeys(); this.check(epoch); const history = collaborationHistory.parse(await this.transport.history(reference, { signal })); this.check(epoch);
    if (history.planning.binding.projectId !== input.projectId) throw new CollaborationClientError('INVALID_COLLABORATION');
    const { view } = await this.opened(history.planning, [history.entry], true, signal, epoch), entry = view.records[0];
    if (!entry || entry.entryId !== input.entryId || entry.kind !== input.kind) throw new CollaborationClientError('INVALID_COLLABORATION'); return entry;
  }); }
}
