import { z } from 'zod';
import { identifier } from '../shared/contracts.js';
import { canonicalJson, digestObject } from '../shared/crypto.js';
import { PLANNING_MAX_BYTES, planningContext, planningReceipt, planningView, validatePlanningPayload, verifyPlanningBinding,
  type PlanningContext, type PlanningPayload, type PlanningReceipt, type PlanningView } from '../shared/planning-api.js';
import { verifySecurityHistory, type SecurityHistoryInput } from '../shared/security-history.js';
import { AuthenticatedHttp, AuthClientError, type AuthController, type AuthRequestOptions } from './auth-controller.js';
import { IndexedPairingStore, readSecurityHistoryPages, historyResponse, type PairingHistoryResponse } from './pairing.js';
import { IndexedPlanningStore, planningPin, type PlanningPin, type StoredPlanningOperation } from './planning-store.js';
import { PlanningClientError, taskPrivateData, type PlanningIntent, type PlanningPrivateContent, type ReadablePlanning } from './planning-crypto.js';
import type { AccessChangeController } from './access-change-controller.js';
import type { ReadReportingSettingsInput } from './reporting-settings-crypto.js';
import { assertOnline, isWriteConflict, WriteConflict, WriteError } from './write-state.js';

type Reference = { workspaceId: string; projectId: string; operationId: string };
type StatusReference = Reference & { dataGeneration: string; requestHash: string };
const same = (a: unknown, b: unknown) => canonicalJson(a) === canonicalJson(b);
export interface PlanningTransport {
  readonly origin: string;
  context(input: Reference, options?: AuthRequestOptions): Promise<PlanningContext>;
  save(payload: PlanningPayload, options?: AuthRequestOptions): Promise<PlanningReceipt>;
  status(input: StatusReference, options?: AuthRequestOptions): Promise<PlanningView>;
  history(input: Reference, options?: AuthRequestOptions): Promise<PairingHistoryResponse>;
}
export class HttpPlanningTransport extends AuthenticatedHttp implements PlanningTransport {
  constructor(origin: string, private readonly csrfToken: () => string | undefined, fetcher?: typeof fetch) { super(origin, fetcher); }
  private request<T>(path: string, body: unknown, schema: z.ZodType<T>, options?: AuthRequestOptions): Promise<T> {
    const csrfToken = this.csrfToken(); if (!csrfToken) throw new AuthClientError('AUTH_REQUIRED');
    return this.post(`/v1/work/planning/${path}`, body, schema, { ...options, csrfToken });
  }
  context(input: Reference, options?: AuthRequestOptions) { return this.request('context', input, planningContext, options); }
  async save(input: PlanningPayload, options?: AuthRequestOptions) {
    const view = await this.request('save', input, planningView, options);
    if (view.state !== 'completed' || !view.receipt) throw new PlanningClientError('INVALID_PLANNING'); return view.receipt;
  }
  status(input: StatusReference, options?: AuthRequestOptions) { return this.request('status', input, planningView, options); }
  history(input: Reference, options?: AuthRequestOptions) {
    return readSecurityHistoryPages(input.operationId, 'current', (page) => { const { mode: _mode, ...cursor } = page;
      return this.request('history', { workspaceId: input.workspaceId, projectId: input.projectId, ...cursor }, historyResponse, options); });
  }
  protected override responseLimit(path: string): number { return path === '/v1/work/planning/context' ? PLANNING_MAX_BYTES : path === '/v1/work/planning/history' ? 3 * 1024 * 1024 : super.responseLimit(path); }
}
export interface PlanningProgress { state: 'completed'; operationId: string; projectId: string; receipt: PlanningReceipt }
/** Existing-target commands require the checkpoint returned by the caller's reviewed read. */
export interface ExecutePlanningInput { projectId: string; operationId?: string; command: PlanningIntent; reviewed?: PlanningPin; content?: PlanningPrivateContent; outcome?: string }
export interface CreateTaskInput { projectId: string; title: string; taskId?: string; operationId?: string; description?: string;
  startDate?: string; dueDate?: string; priority?: 'low' | 'normal' | 'high'; acceptanceCriteria?: string;
  assigneeIds?: string[]; leadProfileId?: string | null; phaseId?: string | null; milestoneId?: string | null; teamId?: string | null; reviewerProfileId?: string | null }
export class PlanningController {
  private epoch = 0;
  private readonly requests = new Set<AbortController>();
  private readonly running = new Set<Promise<unknown>>();
  constructor(private readonly auth: AuthController, private readonly transport: PlanningTransport, private readonly operations: IndexedPlanningStore,
    private readonly pins: IndexedPairingStore, private readonly access: Pick<AccessChangeController, 'refreshKeys'>,
    private readonly options: { trustedServiceKeys?: Record<string, string>; closingSettings?: () => Promise<ReadReportingSettingsInput>; onWrite?: () => void } = {}) {
    if (auth.origin !== transport.origin || auth.origin !== operations.origin || auth.origin !== pins.origin) throw new PlanningClientError('CONFLICT');
  }
  clear(): void { this.epoch++; for (const request of this.requests) request.abort(); this.requests.clear(); }
  attachAuthLifecycle(): () => void { const clear = this.auth.onClear(() => this.clear()), forget = this.auth.onForget((ref) => this.forgetDevice(ref)); return () => { clear(); forget(); }; }
  async forgetDevice(reference: { workspaceId: string; accountId: string; deviceId: string }): Promise<void> {
    this.clear(); await Promise.allSettled([...this.running]); await this.operations.forgetDevice(reference);
  }
  private check(epoch: number): void { if (epoch !== this.epoch) throw new PlanningClientError('CANCELLED'); }
  private run<T>(work: (signal: AbortSignal, epoch: number) => Promise<T>): Promise<T> {
    const request = new AbortController(), epoch = this.epoch; this.requests.add(request);
    const promise = work(request.signal, epoch).then((result) => { this.check(epoch); return result; }); this.running.add(promise);
    void promise.finally(() => { this.requests.delete(request); this.running.delete(promise); }).catch(() => {}); return promise;
  }
  private session() { const current = this.auth.current(); if (current?.localAccess !== 'unlocked' || !current.session.deviceId) throw new AuthClientError('AUTH_REQUIRED'); return current.session; }
  private async history(reference: Reference, signal: AbortSignal, epoch: number): Promise<SecurityHistoryInput> {
    const pin = await this.pins.pin(reference.workspaceId); this.check(epoch); if (!pin) throw new PlanningClientError('TRUST_REQUIRED');
    const response = await this.transport.history(reference, { signal }); this.check(epoch);
    if (!same(response.anchor, response.current)) throw new PlanningClientError('CONFLICT');
    const input: SecurityHistoryInput = { workspaceId: reference.workspaceId, origin: this.auth.origin, genesisFingerprint: pin.genesisFingerprint,
      genesis: response.genesis, transitions: response.transitions, expected: response.anchor, pin, trustedServiceKeys: this.options.trustedServiceKeys ?? {} };
    const state = await verifySecurityHistory(input); this.check(epoch); const session = this.session(), profile = state.profiles[session.accountId], device = state.devices[session.deviceId!];
    if (session.workspaceId !== state.workspaceId || !profile?.active || !device?.active || device.accountId !== session.accountId ||
      profile.credentialGeneration !== session.credentialGeneration || profile.sessionGeneration !== session.sessionGeneration || state.dataGeneration !== session.dataGeneration) throw new PlanningClientError('INVALID_PLANNING');
    return input;
  }
  private async current(reference: Reference, signal: AbortSignal, epoch: number) {
    const context = planningContext.parse(await this.transport.context(reference, { signal })); this.check(epoch);
    const session = this.session(); if (context.binding.workspaceId !== reference.workspaceId || context.binding.projectId !== reference.projectId ||
      context.binding.operationId !== reference.operationId || context.binding.accountId !== session.accountId || context.binding.deviceId !== session.deviceId) throw new PlanningClientError('INVALID_PLANNING');
    const history = await this.history(reference, signal, epoch), pin = await this.operations.pin(reference); this.check(epoch);
    const input = { context, history, accountId: session.accountId, deviceId: session.deviceId!, ...(pin ? { pin } : {}) },
      view = await this.auth.worker.readPlanning(input, { signal }); this.check(epoch);
    await this.operations.recordPin(view.pin); this.check(epoch); await this.pins.recordVerifiedHistory(history); this.check(epoch);
    return { context, history, input, view };
  }
  read(projectId: string): Promise<ReadablePlanning> { return this.run(async (signal, epoch) => {
    const session = this.session(), reference = { workspaceId: session.workspaceId, projectId: identifier.parse(projectId), operationId: crypto.randomUUID() };
    await this.access.refreshKeys(); this.check(epoch); return (await this.current(reference, signal, epoch)).view;
  }); }
  private async receipt(receiptValue: PlanningReceipt, record: StoredPlanningOperation, signal: AbortSignal, epoch: number): Promise<PlanningProgress> {
    const receipt = planningReceipt.parse(receiptValue), payload = record.payload, body = payload.mutation.body, b = body.binding;
    if (receipt.workspaceId !== b.workspaceId || receipt.projectId !== b.projectId || receipt.operationId !== b.operationId || receipt.dataGeneration !== b.dataGeneration ||
      receipt.requestHash !== await digestObject(payload) || receipt.planningVersion !== body.nextVersion || receipt.planningHead !== await digestObject(payload.mutation) ||
      receipt.graphDigest !== body.afterGraphDigest || !same(receipt.mutation, payload.mutation)) throw new PlanningClientError('INVALID_PLANNING'); this.check(epoch);
    const current = await this.current({ workspaceId: b.workspaceId, projectId: b.projectId, operationId: b.operationId }, signal, epoch);
    if (!current.context.history.some((mutation) => same(mutation, payload.mutation))) throw new PlanningClientError('INVALID_PLANNING');
    this.options.onWrite?.();
    return { state: 'completed', operationId: b.operationId, projectId: b.projectId, receipt };
  }
  private async finish(record: StoredPlanningOperation, signal: AbortSignal, epoch: number): Promise<PlanningProgress> {
    assertOnline();
    const b = record.payload.mutation.body.binding, session = this.session();
    if (record.workspaceId !== session.workspaceId || record.accountId !== session.accountId || record.deviceId !== session.deviceId || b.dataGeneration !== session.dataGeneration) throw new PlanningClientError('CONFLICT');
    const reference = { workspaceId: b.workspaceId, projectId: b.projectId, operationId: b.operationId }, requestHash = await digestObject(record.payload); this.check(epoch);
    const status = planningView.parse(await this.transport.status({ ...reference, dataGeneration: b.dataGeneration, requestHash }, { signal })); this.check(epoch);
    if (status.state === 'completed') { if (!status.receipt) throw new PlanningClientError('INVALID_PLANNING'); return this.receipt(status.receipt, record, signal, epoch); }
    if (status.receipt || Date.parse(b.expiresAt) <= Date.now()) throw new PlanningClientError('EXPIRED');
    const current = await this.current(reference, signal, epoch), security = await verifySecurityHistory(current.history); this.check(epoch);
    verifyPlanningBinding(b, security);
    if (b.beforeHead !== current.context.binding.beforeHead || b.beforeVersion !== current.context.binding.beforeVersion) throw new PlanningClientError('CONFLICT');
    await validatePlanningPayload(record.payload, b, current.context.graph, current.context.records); this.check(epoch);
    assertOnline();const receipt = await this.transport.save(record.payload, { signal }); this.check(epoch); return this.receipt(receipt, record, signal, epoch);
  }
  private change(value: ExecutePlanningInput | CreateTaskInput): Promise<PlanningProgress> {
    const input=structuredClone(value);
    return this.run(async (signal, epoch) => {
    assertOnline();
    const existingTarget='command' in input&&!['create_phase','create_milestone','create_task','create_blocker'].includes(input.command.action);
    if(existingTarget&&(!('reviewed' in input)||!input.reviewed))throw new WriteError('REVIEW_REQUIRED');
    const session = this.session(), reference = { workspaceId: session.workspaceId, projectId: identifier.parse(input.projectId), operationId: input.operationId ?? crypto.randomUUID() };
    if (await this.operations.get(reference.workspaceId, reference.operationId)) throw new PlanningClientError('CONFLICT'); this.check(epoch);
    await this.access.refreshKeys(); this.check(epoch);
    const current = await this.current(reference, signal, epoch);
    if(existingTarget&&'reviewed' in input&&!same(planningPin.parse(input.reviewed),current.view.pin))throw new WriteConflict(reference.operationId,current.view,input);
    const resolved: ExecutePlanningInput = 'command' in input ? input : { projectId: input.projectId,
      command: { action: 'create_task', task: { id: input.taskId!, phaseId: input.phaseId ?? null, milestoneId: input.milestoneId ?? null,
        teamId: input.teamId ?? null, leadProfileId: input.leadProfileId ?? null, reviewerProfileId: input.reviewerProfileId ?? null,
        assigneeIds: input.assigneeIds ?? (current.context.binding.permissions.includes('manage_tasks') ? [] : [current.context.binding.accountId]) } },
      content: taskPrivateData.parse({ title: input.title, ...(input.description === undefined ? {} : { description: input.description }),
        ...(input.startDate === undefined ? {} : { startDate: input.startDate }), ...(input.dueDate === undefined ? {} : { dueDate: input.dueDate }),
        ...(input.priority === undefined ? {} : { priority: input.priority }), ...(input.acceptanceCriteria === undefined ? {} : { acceptanceCriteria: input.acceptanceCriteria }) }) };
    const needsClosingSettings = ['complete_project', 'cancel_project', 'complete_phase', 'cancel_phase', 'accept_milestone', 'cancel_milestone'].includes(resolved.command.action);
    const closingSettings = needsClosingSettings ? await this.options.closingSettings?.() : undefined; this.check(epoch);
    if (needsClosingSettings && !closingSettings) throw new PlanningClientError('INVALID_PLANNING');
    const payload = await this.auth.worker.preparePlanning({ ...current.input, command: resolved.command, ...(closingSettings ? { closingSettings } : {}),
      ...(resolved.content === undefined ? {} : { content: resolved.content }), ...(resolved.outcome === undefined ? {} : { outcome: resolved.outcome }) }, { signal }); this.check(epoch);
    const record: StoredPlanningOperation = { version: 1, origin: this.auth.origin, workspaceId: reference.workspaceId, operationId: reference.operationId,
      accountId: session.accountId, deviceId: session.deviceId!, payload };
    await this.operations.put(record); this.check(epoch); const readback = await this.operations.get(reference.workspaceId, reference.operationId); this.check(epoch);
    if (!readback || !same(readback, record)) throw new PlanningClientError('STORAGE');
    await validatePlanningPayload(readback.payload, current.context.binding, current.context.graph, current.context.records); this.check(epoch);
    try{return await this.finish(readback, signal, epoch);}catch(error){
      if(isWriteConflict(error)){const fresh=await this.current(reference,signal,epoch);throw new WriteConflict(reference.operationId,fresh.view,input);}throw error;
    }
  }); }
  execute(input: ExecutePlanningInput): Promise<PlanningProgress> { return this.change(input); }
  createTask(input: CreateTaskInput): Promise<PlanningProgress & { taskId: string }> {
    const taskId = input.taskId ?? crypto.randomUUID(); return this.change({ ...input, taskId }).then((result) => ({ ...result, taskId }));
  }
  resume(operationId: string): Promise<PlanningProgress> { return this.run(async (signal, epoch) => {
    assertOnline();
    const session = this.session(), record = await this.operations.get(session.workspaceId, identifier.parse(operationId)); this.check(epoch);
    if (!record) throw new PlanningClientError('NOT_FOUND'); return this.finish(record, signal, epoch);
  }); }
  pending() { const session = this.session(); return this.operations.list({ workspaceId: session.workspaceId, accountId: session.accountId, deviceId: session.deviceId! }); }
}
