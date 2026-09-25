import { z } from 'zod';
import { identifier } from '../shared/contracts.js';
import { base64urlEncode, canonicalJson, digestObject } from '../shared/crypto.js';
import { accessContext, accessDelivery, accessRequest, accessView, accessReceiptTokenHash, validateAccessPayload, validateAccessReceiptForPayload,
  verifyAccessBindingAgainstHistory, type AccessRequest, type AccessContext, type AccessReference, type AccessPayload,
  type AccessView, type AccessDelivery, type AccessReceipt } from '../shared/access-change.js';
import { verifySecurityHistory, type SecurityHistoryInput } from '../shared/security-history.js';
import { AuthenticatedHttp, AuthClientError, type AuthController, type AuthRequestOptions } from './auth-controller.js';
import { IndexedPairingStore, readSecurityHistoryPages, historyResponse, type PairingHistoryResponse } from './pairing.js';
import { IndexedAccessChangeStore, type AccessChangeRecord } from './access-change-store.js';
import { AccessChangeClientError, type RefreshedAccess } from './access-change-crypto.js';

const same = (a: unknown, b: unknown) => canonicalJson(a) === canonicalJson(b);
export interface AccessChangeTransport {
  readonly origin: string;
  context(input: AccessRequest, options?: AuthRequestOptions): Promise<AccessContext>;
  stage(payload: AccessPayload, options?: AuthRequestOptions): Promise<AccessView>;
  finalize(input: AccessReference & { requestHash: string; receiptToken: string }, options?: AuthRequestOptions): Promise<AccessView>;
  status(input: AccessReference & { receiptToken: string }, options?: AuthRequestOptions): Promise<AccessView>;
  history(input: AccessReference, options?: AuthRequestOptions): Promise<PairingHistoryResponse>;
  delivery(input: { workspaceId: string }, options?: AuthRequestOptions): Promise<AccessDelivery>;
  deliveryHistory(input: AccessReference, options?: AuthRequestOptions): Promise<PairingHistoryResponse>;
}
export class HttpAccessChangeTransport extends AuthenticatedHttp implements AccessChangeTransport {
  constructor(origin: string, private readonly csrfToken: () => string | undefined, fetcher?: typeof fetch) { super(origin, fetcher); }
  private request<T>(path: string, body: unknown, schema: z.ZodType<T>, options?: AuthRequestOptions, authenticated = true): Promise<T> {
    const csrfToken = this.csrfToken(); if (authenticated && !csrfToken) throw new AuthClientError('AUTH_REQUIRED');
    return this.post(`/v1/auth/access-change/${path}`, body, schema, { ...options, ...(csrfToken ? { csrfToken } : {}) });
  }
  context(input: AccessRequest, options?: AuthRequestOptions) { return this.request('context', input, accessContext, options); }
  stage(input: AccessPayload, options?: AuthRequestOptions) { return this.request('stage', input, accessView, options); }
  finalize(input: AccessReference & { requestHash: string; receiptToken: string }, options?: AuthRequestOptions) { return this.request('finalize', input, accessView, options, false); }
  status(input: AccessReference & { receiptToken: string }, options?: AuthRequestOptions) { return this.request('status', input, accessView, options, false); }
  history(input: AccessReference, options?: AuthRequestOptions) {
    return readSecurityHistoryPages(input.operationId, 'current', (page) => { const { mode: _mode, ...cursor } = page;
      return this.request('history', { workspaceId: input.workspaceId, ...cursor }, historyResponse, options); });
  }
  delivery(input: { workspaceId: string }, options?: AuthRequestOptions) { return this.request('delivery', input, accessDelivery, options); }
  deliveryHistory(input: AccessReference, options?: AuthRequestOptions) {
    return readSecurityHistoryPages(input.operationId, 'current', (page) => { const { mode: _mode, ...cursor } = page;
      return this.request('delivery/history', { workspaceId: input.workspaceId, ...cursor }, historyResponse, options); });
  }
  protected override responseLimit(path: string): number {
    return ['/v1/auth/access-change/history', '/v1/auth/access-change/delivery/history'].includes(path) ? 3 * 1024 * 1024 : super.responseLimit(path);
  }
}
export interface AccessChangeProgress { operationId: string; targetAccountId: string; state: 'completed' | 'finishing'; receipt: AccessReceipt;
  access: 'ready' | 'revoked' }
export class AccessChangeController {
  private epoch = 0;
  private readonly requests = new Set<AbortController>();
  private readonly running = new Set<Promise<unknown>>();
  constructor(private readonly auth: AuthController, private readonly transport: AccessChangeTransport,
    private readonly operations: IndexedAccessChangeStore, private readonly pins: IndexedPairingStore,
    private readonly options: { trustedServiceKeys?: Record<string, string> } = {}) {
    if (auth.origin !== transport.origin || auth.origin !== operations.origin || auth.origin !== pins.origin) throw new AccessChangeClientError('CONFLICT');
  }
  clear(): void { this.epoch++; for (const request of this.requests) request.abort(); this.requests.clear(); }
  attachAuthLifecycle(): () => void { const clear = this.auth.onClear(() => this.clear()), forget = this.auth.onForget((ref) => this.forgetDevice(ref)); return () => { clear(); forget(); }; }
  async forgetDevice(reference: { workspaceId: string; accountId: string; deviceId: string }): Promise<void> {
    this.clear(); await Promise.allSettled([...this.running]); await this.operations.forgetDevice(reference);
  }
  private check(epoch: number): void { if (epoch !== this.epoch) throw new AccessChangeClientError('CANCELLED'); }
  private run<T>(work: (signal: AbortSignal, epoch: number) => Promise<T>): Promise<T> {
    const request = new AbortController(), epoch = this.epoch; this.requests.add(request);
    const promise = work(request.signal, epoch).then((result) => { this.check(epoch); return result; }); this.running.add(promise);
    void promise.finally(() => { this.requests.delete(request); this.running.delete(promise); }).catch(() => {}); return promise;
  }
  private session() { const current = this.auth.current(); if (current?.localAccess !== 'unlocked' || !current.session.deviceId) throw new AuthClientError('AUTH_REQUIRED'); return current.session; }
  private async history(reference: AccessReference, signal: AbortSignal, epoch: number, ordinary = false): Promise<SecurityHistoryInput> {
    const pin = await this.pins.pin(reference.workspaceId); this.check(epoch); if (!pin) throw new AccessChangeClientError('TRUST_REQUIRED');
    const response = await (ordinary ? this.transport.deliveryHistory(reference, { signal }) : this.transport.history(reference, { signal })); this.check(epoch);
    if (!same(response.anchor, response.current)) throw new AccessChangeClientError('CONFLICT');
    const input: SecurityHistoryInput = { workspaceId: reference.workspaceId, origin: this.auth.origin, genesisFingerprint: pin.genesisFingerprint,
      genesis: response.genesis, transitions: response.transitions, expected: response.anchor, pin, trustedServiceKeys: this.options.trustedServiceKeys ?? {} };
    const state = await verifySecurityHistory(input); this.check(epoch); const session = this.session(), profile = state.profiles[session.accountId], device = state.devices[session.deviceId!];
    if (session.workspaceId !== state.workspaceId || !profile?.active || !device?.active || device.accountId !== session.accountId ||
      (!ordinary && !profile.owner) || profile.credentialGeneration !== session.credentialGeneration || profile.sessionGeneration !== session.sessionGeneration ||
      state.dataGeneration !== session.dataGeneration) throw new AccessChangeClientError('INVALID_CHANGE'); return input;
  }
  private async refreshed(signal: AbortSignal, epoch: number, history?: SecurityHistoryInput): Promise<RefreshedAccess> {
    const session = this.session(), delivery = accessDelivery.parse(await this.transport.delivery({ workspaceId: session.workspaceId }, { signal })); this.check(epoch);
    if (delivery.workspaceId !== session.workspaceId || delivery.accountId !== session.accountId || delivery.deviceId !== session.deviceId) throw new AccessChangeClientError('INVALID_CHANGE');
    const current = history ?? await this.history({ workspaceId: session.workspaceId, operationId: crypto.randomUUID() }, signal, epoch, true);
    const result = await this.auth.worker.refreshAccessKeys({ delivery, history: current }, { signal }); this.check(epoch);
    await this.pins.recordVerifiedHistory(current); this.check(epoch); return result;
  }
  refreshKeys(): Promise<RefreshedAccess> { return this.run((signal, epoch) => this.refreshed(signal, epoch)); }
  private async finish(record: AccessChangeRecord, signal: AbortSignal, epoch: number): Promise<AccessChangeProgress> {
    const binding = record.payload.transition.body.binding, reference = { workspaceId: record.workspaceId, operationId: record.operationId },
      requestHash = await digestObject(record.payload); this.check(epoch);
    if (await accessReceiptTokenHash(reference, record.receiptToken) !== binding.receiptTokenHash) throw new AccessChangeClientError('CONFLICT'); this.check(epoch);
    let view = accessView.parse(await this.transport.status({ ...reference, receiptToken: record.receiptToken }, { signal })); this.check(epoch);
    if (!view.receipt) {
      if (view.state === 'expired' || Date.parse(binding.expiresAt) <= Date.now()) throw new AccessChangeClientError('EXPIRED');
      const history = await this.history(reference, signal, epoch), state = await verifySecurityHistory(history); this.check(epoch);
      await validateAccessPayload(record.payload, binding, state); this.check(epoch);
      if (view.state === 'absent') { view = accessView.parse(await this.transport.stage(record.payload, { signal })); this.check(epoch); }
      if (!view.receipt) {
        if (view.state !== 'staged' || view.requestHash !== requestHash) throw new AccessChangeClientError('CONFLICT');
        view = accessView.parse(await this.transport.finalize({ ...reference, requestHash, receiptToken: record.receiptToken }, { signal })); this.check(epoch);
      }
    }
    if (!view.receipt || !['completed', 'finishing'].includes(view.state) || view.requestHash !== requestHash) throw new AccessChangeClientError('INVALID_CHANGE');
    const receipt = await validateAccessReceiptForPayload(view.receipt, record.payload); this.check(epoch);
    const selfChange = binding.targetAccountId === binding.authorizer.accountId;
    // Receipt capability proves only this saved operation's outcome. It never restores content or access.
    if (!selfChange) {
      const history = await this.history(reference, signal, epoch);
      if (!history.transitions.some((transition) => same(transition, receipt.transition))) throw new AccessChangeClientError('INVALID_CHANGE');
      await this.refreshed(signal, epoch, history);
    }
    return { operationId: reference.operationId, targetAccountId: binding.targetAccountId, state: view.state as AccessChangeProgress['state'], receipt,
      access: selfChange ? 'revoked' : 'ready' };
  }
  private async afterCommit(result: AccessChangeProgress): Promise<AccessChangeProgress> {
    const current = this.auth.current();
    if (result.access === 'revoked' && current?.session.workspaceId === result.receipt.workspaceId && current.session.accountId === result.targetAccountId) await this.auth.logout();
    return result;
  }
  private change(input: { action: AccessRequest['action']; accountId: string; desired: AccessRequest['desired']; operationId?: string }): Promise<AccessChangeProgress> {
    return this.run(async (signal, epoch) => {
      const session = this.session(), reference = { workspaceId: session.workspaceId, operationId: input.operationId ?? crypto.randomUUID() };
      if (await this.operations.get(reference.operationId)) throw new AccessChangeClientError('CONFLICT'); this.check(epoch);
      const receiptToken = base64urlEncode(crypto.getRandomValues(new Uint8Array(32))), request = accessRequest.parse({ ...reference,
        action: input.action, targetAccountId: input.accountId, desired: input.desired, receiptTokenHash: await accessReceiptTokenHash(reference, receiptToken) }); this.check(epoch);
      const context = accessContext.parse(await this.transport.context(request, { signal })); this.check(epoch);
      if (context.binding.authorizer.accountId !== session.accountId || context.binding.authorizer.device.id !== session.deviceId) throw new AccessChangeClientError('INVALID_CHANGE');
      const history = await this.history(reference, signal, epoch), state = await verifySecurityHistory(history); this.check(epoch);
      verifyAccessBindingAgainstHistory(context.binding, context.plan, state);
      const payload = await this.auth.worker.prepareAccessChange({ request, context, history }, { signal }); this.check(epoch);
      const record: AccessChangeRecord = { version: 1, origin: this.auth.origin, ...reference, accountId: session.accountId, deviceId: session.deviceId!, receiptToken, payload };
      await this.operations.put(record); this.check(epoch);
      const readback = await this.operations.get(reference.operationId); this.check(epoch);
      if (!readback || !same(readback, record)) throw new AccessChangeClientError('STORAGE');
      await validateAccessPayload(readback.payload, context.binding, state); this.check(epoch);
      return this.finish(readback, signal, epoch);
    }).then((result) => this.afterCommit(result));
  }
  setAccess(input: { accountId: string; roleId: string; projectIds: string[]; operationId?: string }) {
    return this.change({ action: 'set_access', accountId: input.accountId, desired: { roleId: input.roleId, projectIds: input.projectIds }, ...(input.operationId ? { operationId: input.operationId } : {}) });
  }
  demoteOwner(input: { accountId: string; roleId: string; projectIds: string[]; operationId?: string }) {
    return this.change({ action: 'demote_owner', accountId: input.accountId, desired: { roleId: input.roleId, projectIds: input.projectIds }, ...(input.operationId ? { operationId: input.operationId } : {}) });
  }
  reactivateMember(input: { accountId: string; roleId: string; projectIds: string[]; operationId?: string }) {
    return this.change({ action: 'reactivate_member', accountId: input.accountId, desired: { roleId: input.roleId, projectIds: input.projectIds }, ...(input.operationId ? { operationId: input.operationId } : {}) });
  }
  suspend(input: { accountId: string; operationId?: string }) { return this.change({ ...input, action: 'suspend', desired: null }); }
  remove(input: { accountId: string; operationId?: string }) { return this.change({ ...input, action: 'remove', desired: null }); }
  resume(operationId: string): Promise<AccessChangeProgress> { return this.run(async (signal, epoch) => {
    const record = await this.operations.get(identifier.parse(operationId)); this.check(epoch);
    if (!record) throw new AccessChangeClientError('NOT_FOUND'); return this.finish(record, signal, epoch);
  }).then((result) => this.afterCommit(result)); }
  pending() { return this.operations.list(); }
}
