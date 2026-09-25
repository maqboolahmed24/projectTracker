import { z } from 'zod';
import { binary, identifier } from '../shared/contracts.js';
import { base64urlDecode, canonicalJson, decryptContent, digestObject, encryptContent, signObject } from '../shared/crypto.js';
import { customRolePermissions } from '../shared/permissions.js';
import { roleContext, roleContextRequest, rolePayload, roleReceipt, roleView, roleList, roleListRequest, roleTransition,
  roleLabelHeader, validateRolePayload, validateRoleReceipt, type RoleBinding, type RoleContext, type RolePayload,
  type RoleReceipt, type RoleReference, type RoleView, type RoleList } from '../shared/roles.js';
import { verifyRoleBindingAgainstHistory, verifySecurityHistory, type SecurityHistoryInput, type SecurityHistoryState, type HistoryScope } from '../shared/security-history.js';
import type { PairingMaterial, PairingScope } from '../shared/pairing.js';
import { AuthenticatedHttp, AuthClientError, type AuthController, type AuthRequestOptions } from './auth-controller.js';
import type { DeviceBundle } from './device-store.js';
import { IndexedPairingStore, historyResponse, readSecurityHistoryPages, readDeviceScopeKeyMaterial, type PairingHistoryResponse } from './pairing.js';

export class RolesClientError extends Error {
  constructor(readonly code: 'INVALID_ROLE' | 'TRUST_REQUIRED' | 'INCOMPLETE_KEYS' | 'CONFLICT' | 'EXPIRED' | 'NOT_FOUND' | 'STORAGE' | 'CANCELLED') {
    super(`Role operation failed (${code})`); this.name = 'RolesClientError';
  }
}
const copy = <T>(value: T): T => JSON.parse(canonicalJson(value)) as T;
const same = (a: unknown, b: unknown) => canonicalJson(a) === canonicalJson(b);
const labelPlaintext = z.strictObject({ displayName: z.string().trim().min(1).max(200).refine((name) => !/[\uD800-\uDFFF]/u.test(name)) });
function invalid(): never { throw new RolesClientError('INVALID_ROLE'); }
function currentOwner(state: SecurityHistoryState, accountId: string, deviceId: string) {
  const profile = state.profiles[accountId], device = state.devices[deviceId];
  if (!profile?.active || !profile.owner || !device?.active || device.accountId !== accountId) invalid();
  const custody = (scope: HistoryScope) => scope.scope === 'workspace' && scope.scopeId === state.workspaceId &&
    scope.mode === 'custody' && scope.keyEpoch === state.custodyEpoch && scope.permissions.includes('read_project') &&
    (scope.expiresAt === null || Date.parse(scope.expiresAt) > Date.now());
  if (!profile.scopes.some(custody) || !device.scopes.some(custody)) invalid();
  return { profile, device, workspace: profile.scopes.find(custody)! };
}
/** Decoded keyrings never cross the Worker RPC or enter a persistent record. */
async function workspaceKeys(state: SecurityHistoryState, accountId: string, deviceId: string, materials: PairingMaterial[], bundle: DeviceBundle) {
  const { device, workspace } = currentOwner(state, accountId, deviceId);
  if (bundle.signingPublicKey !== device.signingPublicKey || bundle.recipientPublicKey !== device.recipientPublicKey) invalid();
  const scope: PairingScope = { scope: 'workspace', scopeId: state.workspaceId, mode: 'content', keyEpoch: state.workspaceKeyEpoch,
    permissions: [...workspace.permissions], expiresAt: workspace.expiresAt, sources: workspace.manifests
      .filter((manifest) => materials.some((material) => material.id === manifest.id && material.digest === manifest.digest))
      .map((manifest) => ({ grantId: deviceId, generation: '1', manifestId: manifest.id, manifestDigest: manifest.digest })) };
  if (!scope.sources.length) throw new RolesClientError('INCOMPLETE_KEYS');
  const values = await readDeviceScopeKeyMaterial({ history: state, materials, scopes: [scope], holder: { workspaceId: state.workspaceId,
    custodyEpoch: state.custodyEpoch, approverAccountId: accountId, approverDevice: { id: device.id, keyGeneration: device.keyGeneration,
      signingPublicKey: device.signingPublicKey, recipientPublicKey: device.recipientPublicKey } } }, bundle);
  return z.object({ mode: z.literal('content'), keys: z.array(z.object({ epoch: z.string(), key: binary(32) })) }).parse(values[0]).keys;
}
async function openRoleLabel(reference: NonNullable<SecurityHistoryState['roles'][string]['label']>, object: RolePayload['label'],
  history: SecurityHistoryInput, ring: { epoch: string; key: string }[]): Promise<string> {
  if (reference.id !== object.id || reference.digest !== await digestObject(object.envelope)) invalid();
  // Full replay already authenticated the historical signer, including a subsequently retired device.
  const transition = history.transitions.map((item) => roleTransition.safeParse(item)).find((item) => item.success &&
    same(item.data.body.role.label, reference));
  if (!transition?.success) invalid();
  const binding = transition.data.body.binding;
  await validateRolePayload({ transition: transition.data, label: object }, binding);
  const entry = ring.find((key) => key.epoch === object.envelope.header.keyEpoch); if (!entry) throw new RolesClientError('INCOMPLETE_KEYS');
  const key = base64urlDecode(entry.key, 32);
  try { return labelPlaintext.parse(await decryptContent(object.envelope, key,
    base64urlDecode(binding.authorizer.device.signingPublicKey, 32), roleLabelHeader(binding))).displayName; }
  finally { key.fill(0); }
}
export interface PrepareRoleChangeInput { request: z.infer<typeof roleContextRequest>; context: RoleContext; history: SecurityHistoryInput;
  displayName?: string; permissions?: z.infer<typeof customRolePermissions> }
/** Worker-only: authoritative history is verified before any label is decrypted, encrypted or signed. */
export async function prepareRoleChange(value: PrepareRoleChangeInput, bundle: DeviceBundle): Promise<RolePayload> {
  const input = copy(value), context = roleContext.parse(input.context), binding = context.binding,
    request = roleContextRequest.parse(input.request), state = await verifySecurityHistory(input.history);
  if (!same(request, { workspaceId: binding.workspaceId, operationId: binding.operationId, action: binding.action, roleId: binding.roleId }) ||
    !same(context.labelHeader, roleLabelHeader(binding)) || Date.parse(binding.expiresAt) <= Date.now() || Date.parse(binding.issuedAt) > Date.now() + 30_000) invalid();
  verifyRoleBindingAgainstHistory(binding, state);
  const ring = await workspaceKeys(state, binding.authorizer.accountId, binding.authorizer.device.id, context.materials, bundle);
  let displayName: string;
  if (binding.action === 'retire') {
    if (input.displayName !== undefined || input.permissions !== undefined || !binding.previous || !context.previousLabel) invalid();
    displayName = await openRoleLabel(binding.previous.label, context.previousLabel, input.history, ring);
  } else displayName = labelPlaintext.parse({ displayName: input.displayName }).displayName;
  const permissions = binding.action === 'retire' ? binding.previous!.permissions : customRolePermissions.parse(input.permissions);
  const entry = ring.find((key) => key.epoch === binding.workspaceKeyEpoch); if (!entry) throw new RolesClientError('INCOMPLETE_KEYS');
  const key = base64urlDecode(entry.key, 32), signing = base64urlDecode(bundle.signingPrivateKey, 64);
  try {
    const envelope = await encryptContent(context.labelHeader, { displayName }, key, signing);
    if (!same(await decryptContent(envelope, key, base64urlDecode(bundle.signingPublicKey, 32), context.labelHeader), { displayName })) invalid();
    const id = crypto.randomUUID(), role = { id: binding.roleId, template: 'custom' as const, revision: binding.nextRevision,
      state: binding.action === 'retire' ? 'retired' as const : 'active' as const, permissions,
      label: { id, revision: binding.nextRevision, digest: await digestObject(envelope) } };
    const transition = await signObject({ version: 1 as const, purpose: 'ukda.custom-role-definition.v1' as const, binding, role }, signing);
    return (await validateRolePayload({ transition, label: { id, envelope } }, binding)).payload;
  } finally { key.fill(0); signing.fill(0); }
}
export interface ReadRolesInput { request: z.infer<typeof roleListRequest>; page: RoleList; history: SecurityHistoryInput; accountId: string; deviceId: string }
export interface ReadableRole { id: string; template: RoleList['roles'][number]['template']; revision: string; state: 'active' | 'retired';
  permissions: z.infer<typeof customRolePermissions>; displayName: string }
export async function readRoleLabels(value: ReadRolesInput, bundle: DeviceBundle): Promise<{ roles: ReadableRole[]; nextRoleId: string | null }> {
  const input = copy(value), request = roleListRequest.parse(input.request), page = roleList.parse(input.page), state = await verifySecurityHistory(input.history);
  if (request.workspaceId !== state.workspaceId || page.workspaceId !== state.workspaceId ||
    !same(page.current, { securityHead: state.securityHead, securityVersion: state.securityVersion })) invalid();
  const expected = Object.values(state.roles).filter((role) => !request.afterRoleId || role.id > request.afterRoleId).sort((a, b) => a.id < b.id ? -1 : 1), selected = expected.slice(0, request.limit);
  if (!same(page.roles.map((role) => role.id), selected.map((role) => role.id)) ||
    page.nextRoleId !== (expected.length > selected.length ? selected.at(-1)!.id : null)) invalid();
  const ring = await workspaceKeys(state, input.accountId, input.deviceId, page.materials, bundle), roles: ReadableRole[] = [];
  for (const row of page.roles) {
    const trusted = state.roles[row.id]!;
    if (!same({ ...row, label: null }, { ...trusted, label: null }) || (row.template === 'custom') !== !!row.label) invalid();
    const displayName = row.template === 'custom' ? await openRoleLabel(trusted.label!, row.label!, input.history, ring) :
      ({ owner: 'Owner', manager: 'Manager', member: 'Member', viewer: 'Viewer' } as const)[row.template];
    roles.push({ ...row, displayName, label: undefined } as ReadableRole);
  }
  return { roles: roles.map(({ id, template, revision, state: status, permissions, displayName }) => ({ id, template, revision, state: status, permissions, displayName })), nextRoleId: page.nextRoleId };
}

const storedRole = z.strictObject({ version: z.literal(1), origin: z.string(), workspaceId: identifier, accountId: identifier,
  deviceId: identifier, operationId: identifier, payload: rolePayload });
export type StoredRoleOperation = z.infer<typeof storedRole>;
/** Immutable ciphertext only. Replaying an operation cannot silently reseal or replace its label. */
export class IndexedRolesStore {
  private constructor(readonly origin: string, private readonly database: IDBDatabase) { database.onversionchange = () => database.close(); }
  static async open(origin: string, name = 'ukda-roles-v1', factory: IDBFactory | undefined = globalThis.indexedDB): Promise<IndexedRolesStore> {
    const accepted = new AuthenticatedHttp(origin).origin; if (!factory) throw new RolesClientError('STORAGE');
    return new Promise((resolve, reject) => { let settled = false; const request = factory.open(name, 1);
      const fail = () => { settled = true; reject(new RolesClientError('STORAGE')); };
      request.onerror = request.onblocked = fail; request.onupgradeneeded = () => request.result.createObjectStore('operations');
      request.onsuccess = () => { if (settled) request.result.close(); else resolve(new IndexedRolesStore(accepted, request.result)); }; });
  }
  private transaction<T>(mode: IDBTransactionMode, work: (store: IDBObjectStore, done: (value: T) => void, fail: (error: unknown) => void) => void): Promise<T> {
    return new Promise((resolve, reject) => { let tx: IDBTransaction;
      try { tx = this.database.transaction('operations', mode, mode === 'readwrite' ? { durability: 'strict' } : {}); } catch { reject(new RolesClientError('STORAGE')); return; }
      let value: T, complete = false, error: unknown;
      const fail = (reason: unknown) => { error = reason; try { tx.abort(); } catch { reject(reason); } };
      tx.onabort = () => reject(error instanceof RolesClientError ? error : new RolesClientError('STORAGE'));
      tx.oncomplete = () => complete ? resolve(value) : reject(new RolesClientError('STORAGE'));
      try { work(tx.objectStore('operations'), (result) => { value = result; complete = true; }, fail); } catch (reason) { fail(reason); }
    });
  }
  private key(workspaceId: string, operationId: string) { return `${this.origin}:${identifier.parse(workspaceId)}:${identifier.parse(operationId)}`; }
  private parse(value: unknown): StoredRoleOperation {
    const record = storedRole.parse(copy(value)), binding = record.payload.transition.body.binding;
    if (record.origin !== this.origin || record.origin !== binding.origin || record.workspaceId !== binding.workspaceId ||
      record.accountId !== binding.authorizer.accountId || record.deviceId !== binding.authorizer.device.id || record.operationId !== binding.operationId) throw new RolesClientError('CONFLICT');
    return record;
  }
  get(workspaceId: string, operationId: string): Promise<StoredRoleOperation | undefined> {
    const key = this.key(workspaceId, operationId); return this.transaction('readonly', (store, done, fail) => {
      const request = store.get(key); request.onsuccess = () => { try { const record = request.result === undefined ? undefined : this.parse(request.result);
        if (record && (record.workspaceId !== workspaceId || record.operationId !== operationId)) throw new RolesClientError('CONFLICT'); done(record); } catch (error) { fail(error); } }; });
  }
  put(value: StoredRoleOperation): Promise<void> {
    const record = this.parse(value), key = this.key(record.workspaceId, record.operationId);
    return this.transaction('readwrite', (store, done, fail) => { const request = store.get(key); request.onsuccess = () => { try {
      if (request.result !== undefined && !same(this.parse(request.result), record)) throw new RolesClientError('CONFLICT'); store.put(record, key); done(undefined);
    } catch (error) { fail(error); } }; });
  }
  list(workspaceId: string): Promise<{ operationId: string; roleId: string; action: RoleBinding['action'] }[]> {
    identifier.parse(workspaceId); return this.transaction('readonly', (store, done, fail) => { const request = store.getAll(); request.onsuccess = () => { try {
      done(request.result.flatMap((value: unknown) => { const record = storedRole.safeParse(value); if (!record.success || record.data.origin !== this.origin || record.data.workspaceId !== workspaceId) return [];
        return [{ operationId: record.data.operationId, roleId: record.data.payload.transition.body.binding.roleId, action: record.data.payload.transition.body.binding.action }]; }));
    } catch (error) { fail(error); } }; });
  }
  forgetDevice(reference: { workspaceId: string; accountId: string; deviceId: string }): Promise<void> {
    return this.transaction('readwrite', (store, done, fail) => { const request = store.openCursor(); request.onsuccess = () => { try {
      const cursor = request.result; if (!cursor) { done(undefined); return; }
      const record = z.object({ origin: z.string(), workspaceId: identifier, accountId: identifier, deviceId: identifier }).safeParse(cursor.value);
      if (record.success && record.data.origin === this.origin && record.data.workspaceId === reference.workspaceId &&
        record.data.accountId === reference.accountId && record.data.deviceId === reference.deviceId) cursor.delete(); cursor.continue();
    } catch (error) { fail(error); } }; });
  }
  close(): void { this.database.close(); }
}
export interface RolesTransport {
  readonly origin: string;
  context(input: z.infer<typeof roleContextRequest>, options?: AuthRequestOptions): Promise<RoleContext>;
  stage(payload: RolePayload, options?: AuthRequestOptions): Promise<RoleView>;
  finalize(input: RoleReference & { requestHash: string }, options?: AuthRequestOptions): Promise<RoleView>;
  status(input: RoleReference, options?: AuthRequestOptions): Promise<RoleView>;
  history(input: RoleReference, options?: AuthRequestOptions): Promise<PairingHistoryResponse>;
  list(input: z.infer<typeof roleListRequest>, options?: AuthRequestOptions): Promise<RoleList>;
}
export class HttpRolesTransport extends AuthenticatedHttp implements RolesTransport {
  constructor(origin: string, private readonly csrfToken: () => string | undefined, fetcher?: typeof fetch) { super(origin, fetcher); }
  private request<T>(path: string, body: unknown, schema: z.ZodType<T>, options?: AuthRequestOptions): Promise<T> {
    const csrfToken = this.csrfToken(); if (!csrfToken) throw new AuthClientError('AUTH_REQUIRED');
    return this.post(`/v1/auth/roles/${path}`, body, schema, { ...options, csrfToken });
  }
  context(input: z.infer<typeof roleContextRequest>, options?: AuthRequestOptions) { return this.request('context', input, roleContext, options); }
  stage(payload: RolePayload, options?: AuthRequestOptions) { return this.request('stage', payload, roleView, options); }
  finalize(input: RoleReference & { requestHash: string }, options?: AuthRequestOptions) { return this.request('finalize', input, roleView, options); }
  status(input: RoleReference, options?: AuthRequestOptions) { return this.request('status', input, roleView, options); }
  history(input: RoleReference, options?: AuthRequestOptions) {
    return readSecurityHistoryPages(input.operationId, 'current', (page) => { const { mode: _mode, ...cursor } = page;
      return this.request('history', { workspaceId: input.workspaceId, ...cursor }, historyResponse, options); });
  }
  list(input: z.infer<typeof roleListRequest>, options?: AuthRequestOptions) { return this.request('list', input, roleList, options); }
  protected override responseLimit(path: string): number { return path === '/v1/auth/roles/history' ? 3 * 1024 * 1024 : super.responseLimit(path); }
}
export interface RoleProgress { operationId: string; roleId: string; state: 'completed' | 'finishing'; receipt: RoleReceipt }
export class RolesController {
  private epoch = 0;
  private readonly requests = new Set<AbortController>();
  private readonly running = new Set<Promise<unknown>>();
  constructor(private readonly auth: AuthController, private readonly transport: RolesTransport, private readonly operations: IndexedRolesStore,
    private readonly pins: IndexedPairingStore, private readonly options: { trustedServiceKeys?: Record<string, string> } = {}) {
    if (auth.origin !== transport.origin || auth.origin !== operations.origin || auth.origin !== pins.origin) throw new RolesClientError('CONFLICT');
  }
  clear(): void { this.epoch++; for (const request of this.requests) request.abort(); this.requests.clear(); }
  attachAuthLifecycle(): () => void { const clear = this.auth.onClear(() => this.clear()), forget = this.auth.onForget((ref) => this.forgetDevice(ref)); return () => { clear(); forget(); }; }
  async forgetDevice(reference: { workspaceId: string; accountId: string; deviceId: string }): Promise<void> {
    this.clear(); await Promise.allSettled([...this.running]); await this.operations.forgetDevice(reference);
  }
  private check(epoch: number): void { if (epoch !== this.epoch) throw new RolesClientError('CANCELLED'); }
  private run<T>(work: (signal: AbortSignal, epoch: number) => Promise<T>): Promise<T> {
    const request = new AbortController(), epoch = this.epoch; this.requests.add(request);
    const promise = work(request.signal, epoch).then((value) => { this.check(epoch); return value; }); this.running.add(promise);
    void promise.finally(() => { this.running.delete(promise); this.requests.delete(request); }).catch(() => {}); return promise;
  }
  private session() { const current = this.auth.current(); if (current?.localAccess !== 'unlocked' || !current.session.deviceId) throw new AuthClientError('AUTH_REQUIRED'); return current.session; }
  private async history(reference: RoleReference, signal: AbortSignal, epoch: number): Promise<SecurityHistoryInput> {
    const pin = await this.pins.pin(reference.workspaceId); this.check(epoch); if (!pin) throw new RolesClientError('TRUST_REQUIRED');
    const response = await this.transport.history(reference, { signal }); this.check(epoch);
    if (!same(response.anchor, response.current)) throw new RolesClientError('CONFLICT');
    const history: SecurityHistoryInput = { workspaceId: reference.workspaceId, origin: this.auth.origin, genesisFingerprint: pin.genesisFingerprint,
      genesis: response.genesis, transitions: response.transitions, expected: response.anchor, pin, trustedServiceKeys: this.options.trustedServiceKeys ?? {} };
    const state = await verifySecurityHistory(history); this.check(epoch); const session = this.session();
    const { profile } = currentOwner(state, session.accountId, session.deviceId!);
    if (session.workspaceId !== state.workspaceId || session.credentialGeneration !== profile.credentialGeneration ||
      session.sessionGeneration !== profile.sessionGeneration || session.dataGeneration !== state.dataGeneration) invalid(); return history;
  }
  private async finish(record: StoredRoleOperation, signal: AbortSignal, epoch: number): Promise<RoleProgress> {
    const binding = record.payload.transition.body.binding, reference = { workspaceId: record.workspaceId, operationId: record.operationId };
    const checked = await validateRolePayload(record.payload, binding); this.check(epoch);
    let view = roleView.parse(await this.transport.status(reference, { signal })); this.check(epoch);
    if (!view.receipt) {
      if (view.state === 'expired') throw new RolesClientError('EXPIRED');
      if (Date.parse(binding.expiresAt) <= Date.now()) throw new RolesClientError('EXPIRED');
      const history = await this.history(reference, signal, epoch); verifyRoleBindingAgainstHistory(binding, await verifySecurityHistory(history)); this.check(epoch);
      if (view.state === 'absent') { view = roleView.parse(await this.transport.stage(record.payload, { signal })); this.check(epoch); }
      if (!view.receipt) {
        if (view.state !== 'staged' || view.requestHash !== checked.requestHash) throw new RolesClientError('CONFLICT');
        view = roleView.parse(await this.transport.finalize({ ...reference, requestHash: checked.requestHash }, { signal })); this.check(epoch);
      }
    }
    if (!view.receipt || !['completed', 'finishing'].includes(view.state) || view.requestHash !== checked.requestHash) invalid();
    const receipt = await validateRoleReceipt(view.receipt, binding); this.check(epoch);
    if (receipt.requestHash !== checked.requestHash || !same(receipt.transition, record.payload.transition)) invalid();
    const history = await this.history(reference, signal, epoch);
    if (!history.transitions.some((transition) => same(transition, receipt.transition))) invalid();
    await this.pins.recordVerifiedHistory(history); this.check(epoch);
    return { operationId: record.operationId, roleId: binding.roleId, state: view.state as RoleProgress['state'], receipt };
  }
  private change(input: { action: RoleBinding['action']; roleId?: string; operationId?: string; displayName?: string; permissions?: z.infer<typeof customRolePermissions> }): Promise<RoleProgress> {
    return this.run(async (signal, epoch) => {
      const session = this.session(), request = roleContextRequest.parse({ workspaceId: session.workspaceId, operationId: input.operationId ?? crypto.randomUUID(), action: input.action, roleId: input.roleId ?? crypto.randomUUID() });
      // Reusing an operation id is explicit resume only; altered human intent must never replay an older change.
      if (await this.operations.get(request.workspaceId, request.operationId)) throw new RolesClientError('CONFLICT'); this.check(epoch);
      const context = roleContext.parse(await this.transport.context(request, { signal })); this.check(epoch);
      if (context.binding.authorizer.accountId !== session.accountId || context.binding.authorizer.device.id !== session.deviceId) invalid();
      const history = await this.history(request, signal, epoch);
      const payload = await this.auth.worker.prepareRoleChange({ request, context, history,
        ...(input.displayName === undefined ? {} : { displayName: input.displayName }), ...(input.permissions === undefined ? {} : { permissions: input.permissions }) }, { signal }); this.check(epoch);
      const record = storedRole.parse({ version: 1, origin: this.auth.origin, workspaceId: session.workspaceId, accountId: session.accountId, deviceId: session.deviceId, operationId: request.operationId, payload });
      await this.operations.put(record); this.check(epoch);
      const readback = await this.operations.get(record.workspaceId, record.operationId); this.check(epoch);
      if (!readback || !same(readback, record)) throw new RolesClientError('STORAGE');
      await validateRolePayload(readback.payload, context.binding); this.check(epoch);
      return this.finish(readback, signal, epoch);
    });
  }
  create(input: { displayName: string; permissions: z.infer<typeof customRolePermissions>; roleId?: string; operationId?: string }) { return this.change({ ...input, action: 'create' }); }
  update(input: { roleId: string; displayName: string; permissions: z.infer<typeof customRolePermissions>; operationId?: string }) { return this.change({ ...input, action: 'update' }); }
  retire(input: { roleId: string; operationId?: string }) { return this.change({ ...input, action: 'retire' }); }
  resume(operationId: string): Promise<RoleProgress> { return this.run(async (signal, epoch) => {
    const session = this.session(), record = await this.operations.get(session.workspaceId, operationId); this.check(epoch);
    if (!record) throw new RolesClientError('NOT_FOUND'); return this.finish(record, signal, epoch);
  }); }
  pending() { return this.operations.list(this.session().workspaceId); }
  list(input: { afterRoleId?: string; limit?: number } = {}): Promise<{ roles: ReadableRole[]; nextRoleId: string | null }> {
    return this.run(async (signal, epoch) => {
      const session = this.session(), request = roleListRequest.parse({ workspaceId: session.workspaceId, ...input }), page = await this.transport.list(request, { signal }); this.check(epoch);
      const history = await this.history({ workspaceId: session.workspaceId, operationId: crypto.randomUUID() }, signal, epoch);
      const result = await this.auth.worker.readRoleLabels({ request, page, history, accountId: session.accountId, deviceId: session.deviceId! }, { signal }); this.check(epoch);
      await this.pins.recordVerifiedHistory(history); this.check(epoch); return result;
    });
  }
}
