import { z } from 'zod';
import { assertOnline } from './write-state.js';
import { identifier } from '../shared/contracts.js';
import { canonicalJson, digestObject } from '../shared/crypto.js';
import { projectCreateContext, projectCreateRequest, projectCreateView, projectPrivateData, validateProjectCreatePayload, validateProjectCreateReceiptForPayload,
  type ProjectCreateRequest, type ProjectCreateContext, type ProjectCreateReference, type ProjectCreatePayload, type ProjectCreateView, type ProjectCreateReceipt } from '../shared/project-create.js';
import { deriveScopeProvisionPlan } from '../shared/scope-provision.js';
import { verifySecurityHistory, type SecurityHistoryInput } from '../shared/security-history.js';
import { AuthenticatedHttp, AuthClientError, type AuthController, type AuthRequestOptions } from './auth-controller.js';
import { IndexedPairingStore, readSecurityHistoryPages, historyResponse, type PairingHistoryResponse } from './pairing.js';
import { IndexedProjectCreateStore, type ProjectCreateRecord } from './project-create-store.js';
import { ProjectCreateClientError } from './project-create-crypto.js';
import type { AccessChangeController } from './access-change-controller.js';

const same = (a: unknown, b: unknown) => canonicalJson(a) === canonicalJson(b);
export interface ProjectCreateTransport {
  readonly origin: string;
  context(input: ProjectCreateRequest, options?: AuthRequestOptions): Promise<ProjectCreateContext>;
  stage(payload: ProjectCreatePayload, options?: AuthRequestOptions): Promise<ProjectCreateView>;
  finalize(input: ProjectCreateReference & { requestHash: string }, options?: AuthRequestOptions): Promise<ProjectCreateView>;
  status(input: ProjectCreateReference, options?: AuthRequestOptions): Promise<ProjectCreateView>;
  history(input: ProjectCreateReference, options?: AuthRequestOptions): Promise<PairingHistoryResponse>;
}
export class HttpProjectCreateTransport extends AuthenticatedHttp implements ProjectCreateTransport {
  constructor(origin: string, private readonly csrfToken: () => string | undefined, fetcher?: typeof fetch) { super(origin, fetcher); }
  private request<T>(path: string, body: unknown, schema: z.ZodType<T>, options?: AuthRequestOptions): Promise<T> {
    const csrfToken = this.csrfToken(); if (!csrfToken) throw new AuthClientError('AUTH_REQUIRED');
    return this.post(`/v1/work/projects/create/${path}`, body, schema, { ...options, csrfToken });
  }
  context(input: ProjectCreateRequest, options?: AuthRequestOptions) { return this.request('context', input, projectCreateContext, options); }
  stage(input: ProjectCreatePayload, options?: AuthRequestOptions) { return this.request('stage', input, projectCreateView, options); }
  finalize(input: ProjectCreateReference & { requestHash: string }, options?: AuthRequestOptions) { return this.request('finalize', input, projectCreateView, options); }
  status(input: ProjectCreateReference, options?: AuthRequestOptions) { return this.request('status', input, projectCreateView, options); }
  history(input: ProjectCreateReference, options?: AuthRequestOptions) {
    return readSecurityHistoryPages(input.operationId, 'current', (page) => { const { mode: _mode, ...cursor } = page;
      return this.request('history', { workspaceId: input.workspaceId, ...cursor }, historyResponse, options); });
  }
  protected override responseLimit(path: string): number { return path === '/v1/work/projects/create/history' ? 3 * 1024 * 1024 : super.responseLimit(path); }
}
export interface ProjectCreateProgress { operationId: string; projectId: string; state: 'completed' | 'finishing'; receipt: ProjectCreateReceipt }
export class ProjectCreateController {
  private epoch = 0;
  private readonly requests = new Set<AbortController>();
  private readonly running = new Set<Promise<unknown>>();
  constructor(private readonly auth: AuthController, private readonly transport: ProjectCreateTransport,
    private readonly operations: IndexedProjectCreateStore, private readonly pins: IndexedPairingStore,
    private readonly access: Pick<AccessChangeController, 'refreshKeys'>, private readonly options: { trustedServiceKeys?: Record<string, string> } = {}) {
    if (auth.origin !== transport.origin || auth.origin !== operations.origin || auth.origin !== pins.origin) throw new ProjectCreateClientError('CONFLICT');
  }
  clear(): void { this.epoch++; for (const request of this.requests) request.abort(); this.requests.clear(); }
  attachAuthLifecycle(): () => void { const clear = this.auth.onClear(() => this.clear()), forget = this.auth.onForget((ref) => this.forgetDevice(ref)); return () => { clear(); forget(); }; }
  async forgetDevice(reference: { workspaceId: string; accountId: string; deviceId: string }): Promise<void> {
    this.clear(); await Promise.allSettled([...this.running]); await this.operations.forgetDevice(reference);
  }
  private check(epoch: number): void { if (epoch !== this.epoch) throw new ProjectCreateClientError('CANCELLED'); }
  private run<T>(work: (signal: AbortSignal, epoch: number) => Promise<T>): Promise<T> {
    const request = new AbortController(), epoch = this.epoch; this.requests.add(request);
    const promise = work(request.signal, epoch).then((result) => { this.check(epoch); return result; }); this.running.add(promise);
    void promise.finally(() => { this.requests.delete(request); this.running.delete(promise); }).catch(() => {}); return promise;
  }
  private session() { const current = this.auth.current(); if (current?.localAccess !== 'unlocked' || !current.session.deviceId) throw new AuthClientError('AUTH_REQUIRED'); return current.session; }
  private async history(reference: ProjectCreateReference, signal: AbortSignal, epoch: number): Promise<SecurityHistoryInput> {
    const pin = await this.pins.pin(reference.workspaceId); this.check(epoch); if (!pin) throw new ProjectCreateClientError('TRUST_REQUIRED');
    const response = await this.transport.history(reference, { signal }); this.check(epoch);
    if (!same(response.anchor, response.current)) throw new ProjectCreateClientError('CONFLICT');
    const input: SecurityHistoryInput = { workspaceId: reference.workspaceId, origin: this.auth.origin, genesisFingerprint: pin.genesisFingerprint,
      genesis: response.genesis, transitions: response.transitions, expected: response.anchor, pin, trustedServiceKeys: this.options.trustedServiceKeys ?? {} };
    const state = await verifySecurityHistory(input); this.check(epoch); const session = this.session(), profile = state.profiles[session.accountId], device = state.devices[session.deviceId!];
    if (session.workspaceId !== state.workspaceId || !profile?.active || !profile.owner || !device?.active || device.accountId !== session.accountId ||
      profile.credentialGeneration !== session.credentialGeneration || profile.sessionGeneration !== session.sessionGeneration || state.dataGeneration !== session.dataGeneration) throw new ProjectCreateClientError('INVALID_PROJECT');
    return input;
  }
  private async finish(record: ProjectCreateRecord, signal: AbortSignal, epoch: number): Promise<ProjectCreateProgress> {
    assertOnline();
    const binding = record.payload.transition.body.binding, session = this.session(), reference = { workspaceId: record.workspaceId, operationId: record.operationId },
      requestHash = await digestObject(record.payload); this.check(epoch);
    if (record.workspaceId !== session.workspaceId || record.accountId !== session.accountId || record.deviceId !== session.deviceId) throw new ProjectCreateClientError('CONFLICT');
    let view = projectCreateView.parse(await this.transport.status(reference, { signal })); this.check(epoch);
    if (!view.receipt) {
      if (view.state === 'expired' || Date.parse(binding.expiresAt) <= Date.now()) throw new ProjectCreateClientError('EXPIRED');
      const history = await this.history(reference, signal, epoch), state = await verifySecurityHistory(history); this.check(epoch);
      await validateProjectCreatePayload(record.payload, binding, state); this.check(epoch);
      if (view.state === 'absent') { view = projectCreateView.parse(await this.transport.stage(record.payload, { signal })); this.check(epoch); }
      if (!view.receipt) {
        if (view.state !== 'staged' || view.requestHash !== requestHash) throw new ProjectCreateClientError('CONFLICT');
        view = projectCreateView.parse(await this.transport.finalize({ ...reference, requestHash }, { signal })); this.check(epoch);
      }
    }
    if (!view.receipt || !['completed', 'finishing'].includes(view.state) || view.requestHash !== requestHash) throw new ProjectCreateClientError('INVALID_PROJECT');
    const receipt = await validateProjectCreateReceiptForPayload(view.receipt, record.payload); this.check(epoch);
    const history = await this.history(reference, signal, epoch);
    if (!history.transitions.some((transition) => same(transition, receipt.transition))) throw new ProjectCreateClientError('INVALID_PROJECT');
    await this.pins.recordVerifiedHistory(history); this.check(epoch);
    await this.access.refreshKeys(); this.check(epoch);
    return { operationId: reference.operationId, projectId: binding.projectId, state: view.state as ProjectCreateProgress['state'], receipt };
  }
  create(input: { name: string; operationId?: string; projectId?: string }): Promise<ProjectCreateProgress> {
    return this.run(async (signal, epoch) => {
      assertOnline();
      const name = projectPrivateData.parse({ name: input.name }).name, session = this.session(), request = projectCreateRequest.parse({ workspaceId: session.workspaceId,
        operationId: input.operationId ?? crypto.randomUUID(), projectId: input.projectId ?? crypto.randomUUID() });
      if (await this.operations.get(request.workspaceId, request.operationId)) throw new ProjectCreateClientError('CONFLICT'); this.check(epoch);
      await this.access.refreshKeys(); this.check(epoch);
      const context = projectCreateContext.parse(await this.transport.context(request, { signal })); this.check(epoch);
      if (context.binding.authorizer.accountId !== session.accountId || context.binding.authorizer.device.id !== session.deviceId) throw new ProjectCreateClientError('INVALID_PROJECT');
      const history = await this.history(request, signal, epoch), state = await verifySecurityHistory(history); this.check(epoch);
      if (!same(deriveScopeProvisionPlan(context.binding, state), context.plan)) throw new ProjectCreateClientError('INVALID_PROJECT');
      const payload = await this.auth.worker.prepareProjectCreate({ request, context, history, name }, { signal }); this.check(epoch);
      const record: ProjectCreateRecord = { version: 1, origin: this.auth.origin, workspaceId: request.workspaceId, operationId: request.operationId,
        accountId: session.accountId, deviceId: session.deviceId!, payload };
      await this.operations.put(record); this.check(epoch);
      const readback = await this.operations.get(request.workspaceId, request.operationId); this.check(epoch);
      if (!readback || !same(readback, record)) throw new ProjectCreateClientError('STORAGE');
      await validateProjectCreatePayload(readback.payload, context.binding, state); this.check(epoch);
      return this.finish(readback, signal, epoch);
    });
  }
  resume(operationId: string): Promise<ProjectCreateProgress> { return this.run(async (signal, epoch) => {
    assertOnline();
    const session = this.session(), record = await this.operations.get(session.workspaceId, identifier.parse(operationId)); this.check(epoch);
    if (!record) throw new ProjectCreateClientError('NOT_FOUND'); return this.finish(record, signal, epoch);
  }); }
  pending() { const session = this.session(); return this.operations.list({ workspaceId: session.workspaceId, accountId: session.accountId, deviceId: session.deviceId! }); }
}
