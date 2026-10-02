import { z } from 'zod';
import { identifier } from '../shared/contracts.js';
import { canonicalJson, digestObject } from '../shared/crypto.js';
import { TEAM_HISTORY_MAX_BYTES, teamContent, teamContext, teamContextRequest, teamHistoryPage, teamHistoryRequest, teamListRequest, teamReceipt, teamReference, validateTeamPayload,
  type TeamContext, type TeamHistoryPage, type TeamPayload, type TeamReceipt } from '../shared/teams.js';
import { accessDelivery } from '../shared/access-change.js';
import { verifySecurityHistory, type SecurityHistoryInput } from '../shared/security-history.js';
import { AuthenticatedHttp, AuthClientError, type AuthController, type AuthRequestOptions } from './auth-controller.js';
import { IndexedPairingStore } from './pairing.js';
import { type AccessChangeController, type AccessChangeTransport } from './access-change-controller.js';
import { IndexedTeamsStore, type TeamsRecord } from './teams-store.js';
import { encryptedTeamsPage, TEAM_HISTORY_MAX_REVISIONS, TeamsClientError, type EncryptedTeamsPage, type ReadableTeamHistory, type TeamsPage } from './teams-crypto.js';
import { assertOnline, isWriteConflict, WriteConflict, WriteError } from './write-state.js';

const same = (a: unknown, b: unknown) => canonicalJson(a) === canonicalJson(b);
export interface TeamsTransport {
  readonly origin: string;
  context(input: z.infer<typeof teamContextRequest>, options?: AuthRequestOptions): Promise<TeamContext>;
  save(payload: TeamPayload, options?: AuthRequestOptions): Promise<TeamReceipt>;
  status(input: z.infer<typeof teamReference>, options?: AuthRequestOptions): Promise<{ receipt: TeamReceipt | null }>;
  list(input: z.input<typeof teamListRequest>, options?: AuthRequestOptions): Promise<EncryptedTeamsPage>;
  history(input: z.input<typeof teamHistoryRequest>, options?: AuthRequestOptions): Promise<TeamHistoryPage>;
}
export class HttpTeamsTransport extends AuthenticatedHttp implements TeamsTransport {
  constructor(origin: string, private readonly csrfToken: () => string | undefined, fetcher?: typeof fetch) { super(origin, fetcher); }
  private request<T>(path: string, body: unknown, schema: z.ZodType<T>, options?: AuthRequestOptions): Promise<T> {
    const csrfToken = this.csrfToken(); if (!csrfToken) throw new AuthClientError('AUTH_REQUIRED');
    return this.post(`/v1/work/teams/${path}`, body, schema, { ...options, csrfToken });
  }
  context(input: z.infer<typeof teamContextRequest>, options?: AuthRequestOptions) { return this.request('context', input, teamContext, options); }
  save(input: TeamPayload, options?: AuthRequestOptions) { return this.request('save', input, teamReceipt, options); }
  status(input: z.infer<typeof teamReference>, options?: AuthRequestOptions) { return this.request('status', input, z.strictObject({ receipt: teamReceipt.nullable() }), options); }
  list(input: z.input<typeof teamListRequest>, options?: AuthRequestOptions) { return this.request('list', teamListRequest.parse(input), encryptedTeamsPage, options); }
  history(input: z.input<typeof teamHistoryRequest>, options?: AuthRequestOptions) { return this.request('history', teamHistoryRequest.parse(input), teamHistoryPage, options); }
  protected override responseLimit(path: string): number { return path === '/v1/work/teams/list' ? 16 * 1024 * 1024 :
    path === '/v1/work/teams/history' ? TEAM_HISTORY_MAX_BYTES : super.responseLimit(path); }
}
export interface TeamProgress { operationId: string; teamId: string; state: 'completed'; receipt: TeamReceipt }
export class TeamsController {
  private epoch = 0;
  private readonly requests = new Set<AbortController>();
  private readonly running = new Set<Promise<unknown>>();
  constructor(private readonly auth: AuthController, private readonly transport: TeamsTransport,
    private readonly operations: IndexedTeamsStore, private readonly pins: IndexedPairingStore,
    private readonly access: Pick<AccessChangeController, 'refreshKeys'>,
    private readonly security: Pick<AccessChangeTransport, 'delivery' | 'deliveryHistory'>,
    private readonly options: { trustedServiceKeys?: Record<string, string> } = {}) {
    if (auth.origin !== transport.origin || auth.origin !== operations.origin || auth.origin !== pins.origin) throw new TeamsClientError('CONFLICT');
  }
  clear(): void { this.epoch++; for (const request of this.requests) request.abort(); this.requests.clear(); }
  attachAuthLifecycle(): () => void { const clear = this.auth.onClear(() => this.clear()), forget = this.auth.onForget((ref) => this.forgetDevice(ref)); return () => { clear(); forget(); }; }
  async forgetDevice(reference: { workspaceId: string; accountId: string; deviceId: string }): Promise<void> {
    this.clear(); await Promise.allSettled([...this.running]); await this.operations.forgetDevice(reference);
  }
  private check(epoch: number): void { if (epoch !== this.epoch) throw new TeamsClientError('CANCELLED'); }
  private run<T>(work: (signal: AbortSignal, epoch: number) => Promise<T>): Promise<T> {
    const request = new AbortController(), epoch = this.epoch; this.requests.add(request);
    const promise = work(request.signal, epoch).then((result) => { this.check(epoch); return result; }); this.running.add(promise);
    void promise.finally(() => { this.requests.delete(request); this.running.delete(promise); }).catch(() => {}); return promise;
  }
  private session() { const current = this.auth.current(); if (current?.localAccess !== 'unlocked' || !current.session.deviceId) throw new AuthClientError('AUTH_REQUIRED'); return current.session; }
  private async keys(signal: AbortSignal, epoch: number) {
    const session = this.session(), pin = await this.pins.pin(session.workspaceId); this.check(epoch); if (!pin) throw new TeamsClientError('TRUST_REQUIRED');
    await this.access.refreshKeys(); this.check(epoch);
    const delivery = accessDelivery.parse(await this.security.delivery({ workspaceId: session.workspaceId }, { signal })); this.check(epoch);
    const response = await this.security.deliveryHistory({ workspaceId: session.workspaceId, operationId: crypto.randomUUID() }, { signal }); this.check(epoch);
    if (!same(response.anchor, response.current) || !same(delivery.current, response.current) || delivery.workspaceId !== session.workspaceId ||
      delivery.accountId !== session.accountId || delivery.deviceId !== session.deviceId) throw new TeamsClientError('CONFLICT');
    const history: SecurityHistoryInput = { workspaceId: session.workspaceId, origin: this.auth.origin, genesisFingerprint: pin.genesisFingerprint,
      genesis: response.genesis, transitions: response.transitions, expected: response.anchor, pin, trustedServiceKeys: this.options.trustedServiceKeys ?? {} };
    const state = await verifySecurityHistory(history); this.check(epoch);
    const profile = state.profiles[session.accountId], device = state.devices[session.deviceId!];
    if (!profile?.active || !device?.active || device.accountId !== session.accountId || profile.credentialGeneration !== session.credentialGeneration ||
      profile.sessionGeneration !== session.sessionGeneration || state.dataGeneration !== session.dataGeneration) throw new TeamsClientError('CONFLICT');
    await this.pins.recordVerifiedHistory(history); this.check(epoch);
    return { history, materials: delivery.materials, accountId: session.accountId, deviceId: session.deviceId!, state };
  }
  private async finish(record: TeamsRecord, signal: AbortSignal, epoch: number): Promise<TeamProgress> {
    assertOnline();
    const session = this.session(), b = record.payload.mutation.body.binding;
    if (record.workspaceId !== session.workspaceId || record.accountId !== session.accountId || record.deviceId !== session.deviceId ||
      record.credentialGeneration !== session.credentialGeneration || record.sessionGeneration !== session.sessionGeneration || record.dataGeneration !== session.dataGeneration) throw new TeamsClientError('CONFLICT');
    const keys = await this.keys(signal, epoch); this.check(epoch);
    await this.auth.worker.readTeams({ ...keys, page: { records: [{ id: b.teamId, revision: record.payload.envelope.header.revision,
      key_epoch: b.keyEpoch, encrypted_envelope: record.payload.envelope, memberIds: record.payload.mutation.body.memberIds, signedChange: record.payload }],
      nextCursor: null, securityHead: keys.state.securityHead, securityVersion: keys.state.securityVersion, dataGeneration: keys.state.dataGeneration } }, { signal }); this.check(epoch);
    const reference = { workspaceId: b.workspaceId, teamId: b.teamId, operationId: b.operationId }, status = await this.transport.status(reference, { signal }); this.check(epoch);
    let receipt = status.receipt;
    if (!receipt) {
      if (!keys.state.profiles[record.accountId]?.owner || b.securityHead !== keys.state.securityHead || b.securityVersion !== keys.state.securityVersion) throw new TeamsClientError('CONFLICT');
      receipt = await this.transport.save(record.payload, { signal }); this.check(epoch);
    }
    const verified = teamReceipt.parse(receipt);
    if (verified.workspaceId !== b.workspaceId || verified.operationId !== b.operationId || verified.teamId !== b.teamId ||
      verified.actorId !== record.accountId || verified.dataGeneration !== record.dataGeneration || verified.revision !== record.payload.envelope.header.revision ||
      verified.requestHash !== await digestObject(record.payload)) throw new TeamsClientError('INVALID_TEAM');
    this.check(epoch); return { operationId: b.operationId, teamId: b.teamId, state: 'completed', receipt: verified };
  }
  private change(action: 'create' | 'update', value: { name: string; description?: string; memberIds?: string[]; operationId?: string; teamId?: string; expectedRevision?: string }): Promise<TeamProgress> {
    const input=structuredClone(value);
    return this.run(async (signal, epoch) => {
      assertOnline();if(action==='update'&&!input.expectedRevision)throw new WriteError('REVIEW_REQUIRED');
      const content = teamContent.parse({ name: input.name, description: input.description ?? '' }), session = this.session(), request = teamContextRequest.parse({
        action, workspaceId: session.workspaceId, teamId: input.teamId ?? crypto.randomUUID(), operationId: input.operationId ?? crypto.randomUUID() });
      if (await this.operations.get(request.workspaceId, request.operationId)) throw new TeamsClientError('CONFLICT'); this.check(epoch);
      const context = teamContext.parse(await this.transport.context(request, { signal })); this.check(epoch);
      const keys = await this.keys(signal, epoch); this.check(epoch);
      if(action==='update'&&context.binding.expectedRevision!==input.expectedRevision)throw new WriteConflict(request.operationId,await this.history(request.teamId),input);
      const payload = await this.auth.worker.prepareTeamChange({ ...keys, request, context, ...content,
        memberIds: input.memberIds ?? context.binding.previousMemberIds }, { signal }); this.check(epoch);
      const record: TeamsRecord = { version: 1, origin: this.auth.origin, workspaceId: request.workspaceId, operationId: request.operationId,
        accountId: session.accountId, deviceId: session.deviceId!, credentialGeneration: session.credentialGeneration,
        sessionGeneration: session.sessionGeneration, dataGeneration: session.dataGeneration, payload };
      await this.operations.put(record); this.check(epoch);
      const readback = await this.operations.get(request.workspaceId, request.operationId); this.check(epoch);
      if (!readback || !same(record, readback)) throw new TeamsClientError('STORAGE'); await validateTeamPayload(readback.payload); this.check(epoch);
      try{return await this.finish(readback, signal, epoch);}catch(error){if(isWriteConflict(error))throw new WriteConflict(request.operationId,await this.history(request.teamId),input);throw error;}
    });
  }
  create(input: { name: string; description?: string; memberIds?: string[]; operationId?: string; teamId?: string }) { return this.change('create', input); }
  edit(input: { teamId: string; expectedRevision: string; name: string; description?: string; memberIds?: string[]; operationId?: string }) { return this.change('update', input); }
  resume(operationId: string): Promise<TeamProgress> { return this.run(async (signal, epoch) => {
    assertOnline();
    const session = this.session(), record = await this.operations.get(session.workspaceId, identifier.parse(operationId)); this.check(epoch);
    if (!record) throw new TeamsClientError('NOT_FOUND'); return this.finish(record, signal, epoch);
  }); }
  pending() { const session = this.session(); return this.operations.list({ workspaceId: session.workspaceId, accountId: session.accountId, deviceId: session.deviceId! }); }
  history(teamId: string): Promise<ReadableTeamHistory> { return this.run(async (signal, epoch) => {
    const workspaceId = this.session().workspaceId, id = identifier.parse(teamId), keys = await this.keys(signal, epoch); this.check(epoch);
    const pages: TeamHistoryPage[] = []; let afterRevision = '0', anchor: TeamHistoryPage['anchor'] | undefined, count = 0, bytes = 2;
    while (count < TEAM_HISTORY_MAX_REVISIONS) {
      const request = teamHistoryRequest.parse({ workspaceId, teamId: id, afterRevision, ...(anchor ? { anchor } : {}), limit: 100 });
      const page = teamHistoryPage.parse(await this.transport.history(request, { signal })); this.check(epoch);
      bytes += new TextEncoder().encode(canonicalJson(page)).byteLength + (pages.length ? 1 : 0); count += page.records.length;
      if (bytes > TEAM_HISTORY_MAX_BYTES || count > TEAM_HISTORY_MAX_REVISIONS || BigInt(page.anchor.revision) > BigInt(TEAM_HISTORY_MAX_REVISIONS) ||
        page.workspaceId !== workspaceId || page.teamId !== id || anchor && !same(anchor, page.anchor) ||
        page.securityHead !== keys.state.securityHead || page.securityVersion !== keys.state.securityVersion || page.dataGeneration !== keys.state.dataGeneration ||
        page.records[0]!.payload.envelope.header.revision !== String(BigInt(afterRevision) + 1n) ||
        page.complete !== (page.nextRevision === null) || !page.complete &&
          (page.nextRevision !== page.records.at(-1)!.payload.envelope.header.revision || BigInt(page.nextRevision!) <= BigInt(afterRevision))) throw new TeamsClientError('INVALID_TEAM');
      pages.push(page); anchor = page.anchor;
      if (page.complete) { const result = await this.auth.worker.readTeamHistory({ ...keys, pages }, { signal }); this.check(epoch); return result; }
      afterRevision = page.nextRevision!;
    }
    throw new TeamsClientError('INVALID_TEAM');
  }); }
  list(input: { after?: string; limit?: number } = {}): Promise<TeamsPage> { return this.run(async (signal, epoch) => {
    const request = teamListRequest.parse({ ...input, workspaceId: this.session().workspaceId }), page = encryptedTeamsPage.parse(await this.transport.list(request, { signal })); this.check(epoch);
    if (page.records.some((row, index) => (request.after && row.id <= request.after) || index > 0 && row.id <= page.records[index - 1]!.id) ||
      page.nextCursor !== null && page.nextCursor !== page.records.at(-1)?.id) throw new TeamsClientError('INVALID_TEAM');
    const keys = await this.keys(signal, epoch); this.check(epoch);
    const result = await this.auth.worker.readTeams({ ...keys, page }, { signal }); this.check(epoch); return result;
  }); }
}
