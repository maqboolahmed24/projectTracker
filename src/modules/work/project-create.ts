import { randomUUID } from 'node:crypto';
import type pg from 'pg';
import { z } from 'zod';
import { transaction, type Databases } from '../../db.js';
import { AppError } from '../../errors.js';
import { identifier } from '../../shared/contracts.js';
import { projectCreateRequest, projectCreatePayload, projectCreateTransition, projectCreateReceipt, projectCreateFinalize, projectCreateReference,
  createProjectBinding, validateProjectCreatePayload, type ProjectCreateRequest, type ProjectCreatePayload, type ProjectCreateReceipt, type ProjectCreateContext, type ProjectCreateView } from '../../shared/project-create.js';
import { deriveScopeProvisionPlan, type ScopeProvisionBinding, type ScopeProvisionPlan } from '../../shared/scope-provision.js';
import { base64urlEncode, canonicalJson, digestObject } from '../../shared/crypto.js';
import { verifySecurityHistory, type SecurityHistoryState } from '../../shared/security-history.js';
import type { PairingMaterial } from '../../shared/pairing.js';
import { EntitlementOperations } from '../identity/entitlements.js';
import { projectAuthoritativeWorkspace, withSecurityFence } from '../identity/projection.js';
import type { ServiceSecrets } from '../identity/secrets.js';
import { SessionService, type SessionPrincipal } from '../identity/sessions.js';
export interface ProjectCreateAuth { cookieValue: string; csrfToken: string }
interface Options { databases: Databases; sessions: SessionService; secrets: ServiceSecrets; origin: string; now?: () => Date;
  requestBudget?: (scope: { workspaceId: string; accountId: string; history: boolean }) => Promise<void>;
  hooks?: { beforeControlCommit?: () => Promise<void>; afterControlCommit?: () => Promise<void>; beforeProjection?: () => Promise<void> } }
interface Authority { lifecycle: string; licence_state: string; security_head: string; security_version: string; data_generation: string;
  write_schema:number; ownership_version: string; custody_epoch: string; genesis_object_id: string; current_custody_manifest_object_id: string; content_maintenance: boolean; restore_quarantine: boolean }
interface Stored { object_id: string; object_hash: string; object_kind: string; versioned_object: unknown; staged_operation_id: string; state: string; expires_at: Date | null }
const changed = () => new AppError('PROJECT_CHANGED', 'Project creation authority changed; prepare a current signed draft', 409);
const invalid = () => new AppError('PROJECT_INVALID', 'Invalid encrypted project creation', 400);
const forbidden = () => new AppError('PROJECT_FORBIDDEN', 'A current approved Owner is required', 403);
const unavailable = () => new AppError('PROJECT_UNAVAILABLE', 'Project creation is temporarily unavailable; retain the local draft', 503);
const equal = (a: unknown, b: unknown) => canonicalJson(a) === canonicalJson(b);
function parse<T>(schema: z.ZodType<T>, input: unknown): T { const result = schema.safeParse(input); if (!result.success) throw invalid(); return result.data; }
/** Create one encrypted Planned project only after every active Owner has durable current custody access. */
export class ProjectCreateService {
  readonly #o: Options; readonly #now: () => Date; readonly #trustedKeys: Promise<Record<string, string>>;
  constructor(options: Options) {
    if (new URL(options.origin).origin !== options.origin) throw new Error('Project creation requires an exact origin');
    this.#o = options; this.#now = options.now ?? (() => new Date());
    this.#trustedKeys = new EntitlementOperations(options.databases, options.secrets).publicSigningKey().then((key) => ({ [options.secrets.keyId]: key }));
  }
  async #tx<T>(workspaceId: string, auth: ProjectCreateAuth,
    action: (c: pg.PoolClient, w: Authority, principal: SessionPrincipal, now: Date) => Promise<T>, options: { history?: boolean; ordinary?: boolean } = {}): Promise<T> {
    if (!identifier.safeParse(workspaceId).success) throw invalid();
    try { return await transaction(this.#o.databases.control, async (c) => {
      await c.query("SET LOCAL synchronous_commit='on'"); await c.query("SELECT set_config('ukda.workspace_id',$1,true)", [workspaceId]);
      const w = (await c.query<Authority>('SELECT * FROM security.workspaces WHERE workspace_id=$1 FOR UPDATE', [workspaceId])).rows[0];
      if (!w || !['active', 'pending_deletion'].includes(w.lifecycle) || w.security_version === '0') throw forbidden();
      const now = this.#now(), p = await this.#o.sessions.resolveCurrent(c, auth.cookieValue, { csrfToken: auth.csrfToken, approved: true, recent: !options.history }, now);
      if (p.workspaceId !== workspaceId || !p.deviceId) throw forbidden();
      if (!options.ordinary && !(await c.query("SELECT 1 FROM security.profiles WHERE workspace_id=$1 AND profile_id=$2 AND state='active' AND is_owner", [workspaceId, p.accountId])).rowCount) throw forbidden();
      await this.#o.requestBudget?.({ workspaceId, accountId: p.accountId, history: options.history ?? false });
      return action(c, w, p, now);
    }); } catch (error) { if (error instanceof AppError) throw error; throw unavailable(); }
  }
  async #object(c: pg.PoolClient, workspaceId: string, objectId: string, committed = true): Promise<Stored> {
    const row = (await c.query<Stored>('SELECT * FROM security.staged_objects WHERE workspace_id=$1 AND object_id=$2', [workspaceId, objectId])).rows[0];
    if (!row || committed && row.state !== 'committed' || await digestObject(row.versioned_object) !== row.object_hash) throw changed(); return row;
  }
  async #history(c: pg.PoolClient, workspaceId: string, w: Authority, addition?: ProjectCreatePayload['transition']): Promise<SecurityHistoryState> {
    const genesis = await this.#object(c, workspaceId, w.genesis_object_id);
    const transitions = (await c.query<{ sequence: string; signed_transition: unknown }>('SELECT sequence,signed_transition FROM security.security_transitions WHERE workspace_id=$1 AND sequence>1 ORDER BY sequence', [workspaceId])).rows;
    if (BigInt(transitions.length) + 1n !== BigInt(w.security_version)) throw changed();
    let state: SecurityHistoryState;
    try { state = await verifySecurityHistory({ workspaceId, origin: this.#o.origin, genesisFingerprint: genesis.object_hash,
      genesis: genesis.versioned_object as Parameters<typeof verifySecurityHistory>[0]['genesis'], transitions: [...transitions.map((row) => row.signed_transition), ...(addition ? [addition] : [])],
      expected: addition ? { securityHead: await digestObject(addition), securityVersion: addition.body.binding.nextSecurityVersion } : { securityHead: w.security_head, securityVersion: w.security_version }, trustedServiceKeys: await this.#trustedKeys });
    } catch { throw changed(); }
    if (!addition && (state.dataGeneration !== w.data_generation || state.ownershipVersion !== w.ownership_version || state.custodyEpoch !== w.custody_epoch || state.licenceState !== w.licence_state || state.custodyManifest.id !== w.current_custody_manifest_object_id)) throw changed();
    return state;
  }
  async #live(c: pg.PoolClient, workspaceId: string, state: SecurityHistoryState): Promise<void> {
    const heads = (await c.query<{ scope_kind: string; scope_id: string; key_epoch: string; recovery_manifest_object_id: string }>('SELECT * FROM security.scope_heads WHERE workspace_id=$1 ORDER BY scope_kind,scope_id', [workspaceId])).rows;
    if (heads.length !== Object.keys(state.scopeHeads).length || heads.some((h) => state.scopeHeads[`${h.scope_kind}:${h.scope_id}`]?.keyEpoch !== h.key_epoch || h.recovery_manifest_object_id !== state.custodyManifest.id)) throw changed();
    const custody = await this.#object(c, workspaceId, state.custodyManifest.id); if (custody.object_hash !== state.custodyManifest.digest) throw changed();
    const profiles = (await c.query<{ profile_id: string; state: string; is_owner: boolean; credential_generation: string; session_generation: string; recovery_generation: string;
      profile_object_id: string; role_id: string | null; role_revision: string | null }>('SELECT * FROM security.profiles WHERE workspace_id=$1 ORDER BY profile_id', [workspaceId])).rows;
    for (const known of Object.values(state.profiles)) {
      const row = profiles.find((p) => p.profile_id === known.accountId);
      if (!row || row.state !== known.state || (row.state === 'active') !== known.active || row.is_owner !== known.owner || row.credential_generation !== known.credentialGeneration ||
        row.session_generation !== known.sessionGeneration || row.recovery_generation !== known.recoveryGeneration || row.profile_object_id !== known.profile.objectId ||
        row.role_id !== known.role.id || row.role_revision !== known.role.revision) throw changed();
    }
    if (profiles.some((p) => p.state === 'active' && !state.profiles[p.profile_id])) throw changed();
    const devices = (await c.query<{ device_id: string; profile_id: string; state: string; key_generation: string; signing_public_key: Buffer; recipient_public_key: Buffer }>('SELECT * FROM security.devices WHERE workspace_id=$1 ORDER BY device_id', [workspaceId])).rows;
    for (const known of Object.values(state.devices)) {
      const row = devices.find((d) => d.device_id === known.id);
      if (!row || row.profile_id !== known.accountId || (row.state === 'active') !== known.active || row.key_generation !== known.keyGeneration ||
        base64urlEncode(row.signing_public_key) !== known.signingPublicKey || base64urlEncode(row.recipient_public_key) !== known.recipientPublicKey) throw changed();
    }
    if (devices.some((d) => d.state === 'active' && !state.devices[d.device_id])) throw changed();
    const recovery = (await c.query<{ profile_id: string; generation: string; state: string; proof_public_key: Buffer; recipient_public_key: Buffer; custody_epoch: string; custody_envelope_object_id: string }>('SELECT * FROM security.recovery_authorities WHERE workspace_id=$1 ORDER BY profile_id,generation', [workspaceId])).rows;
    for (const known of Object.values(state.recoveryAuthorities)) {
      const row = recovery.find((r) => r.profile_id === known.accountId && r.generation === known.generation);
      if (!row || (row.state === 'active') !== known.active || base64urlEncode(row.proof_public_key) !== known.signingPublicKey ||
        base64urlEncode(row.recipient_public_key) !== known.recipientPublicKey || row.custody_epoch !== known.custodyEpoch || row.custody_envelope_object_id !== known.custodyEnvelope.id) throw changed();
    }
    if (recovery.some((r) => r.state === 'active' && !state.recoveryAuthorities[`${r.profile_id}:${r.generation}`])) throw changed();
    const roles = (await c.query<{ role_id: string; template: string; revision: string; state: string; permissions: string[]; encrypted_role_object_id: string | null }>('SELECT * FROM security.roles WHERE workspace_id=$1 ORDER BY role_id', [workspaceId])).rows;
    if (roles.length !== Object.keys(state.roles).length) throw changed();
    for (const row of roles) { const known = state.roles[row.role_id];
      if (!known || known.template !== row.template || known.revision !== row.revision || known.state !== row.state || !equal(known.permissions, row.permissions) || (known.label?.id ?? null) !== row.encrypted_role_object_id) throw changed(); }
  }
  async #liveGrants(c: pg.PoolClient, state: SecurityHistoryState, now: Date): Promise<void> {
    type Grant = { profile_id: string; device_id: string | null; grant_kind: string; scope_kind: 'workspace' | 'project'; scope_id: string | null;
      generation: string; permissions: string[]; key_epoch: string; expires_at: Date | null; revoked_at: Date | null;
      role_id: string | null; role_revision: string | null; security_version: string; signed_grant_object_id: string; key_manifest_object_id: string | null };
    const rows = (await c.query<Grant>("SELECT * FROM security.grants WHERE workspace_id=$1 AND state='active' ORDER BY profile_id,device_id,scope_kind,scope_id,grant_id", [state.workspaceId])).rows;
    const groups = new Map<string, Grant[]>(), objects = new Map<string, Stored>();
    const object = async (id: string) => { const cached = objects.get(id); if (cached) return cached; const value = await this.#object(c, state.workspaceId, id); objects.set(id, value); return value; };
    const groupKey = (account: string, device: string | null, scope: string, scopeId: string) => `${account}:${device ?? 'person'}:${scope}:${scopeId}`;
    for (const row of rows) {
      const profile = state.profiles[row.profile_id], device = row.device_id ? state.devices[row.device_id] : undefined;
      const scopeId = row.scope_id ?? state.workspaceId, scopes = device ? device.scopes : profile?.scopes;
      const expected = scopes?.find((s) => s.scope === row.scope_kind && s.scopeId === scopeId);
      if (!profile?.active || row.revoked_at || (row.device_id && (!device?.active || device.accountId !== profile.accountId || row.generation !== device.keyGeneration)) ||
        !expected || row.key_epoch !== expected.keyEpoch || BigInt(row.security_version) > BigInt(state.securityVersion) ||
        row.grant_kind !== (row.scope_kind === 'project' ? 'project' : device ? 'device' : profile.owner ? 'owner' : 'membership')) throw changed();
      const role = row.scope_kind === 'project' && !device ? profile.projectRoles[scopeId] : undefined;
      if ((row.role_id ?? null) !== (role?.id ?? null) || (row.role_revision ?? null) !== (role?.revision ?? null)) throw changed();
      const definition = await object(row.signed_grant_object_id); if (!['signed_grant', 'genesis'].includes(definition.object_kind) || !row.key_manifest_object_id) throw changed();
      const manifest = await object(row.key_manifest_object_id);
      // A personal source may remain an older same-account delivery after device loss;
      // its signed hash proves bytes only and never revives that device's authority.
      const sources = device ? expected.manifests : [...expected.manifests, { id: state.custodyManifest.id, digest: state.custodyManifest.digest },
        ...Object.values(state.devices).filter((d) => d.accountId === profile.accountId).flatMap((d) => d.scopes.filter((s) =>
          s.scope === expected.scope && s.scopeId === expected.scopeId && s.mode === expected.mode && s.keyEpoch === expected.keyEpoch).flatMap((s) => s.manifests))];
      if (!sources.some((m) => m.id === manifest.object_id && m.digest === manifest.object_hash)) throw changed();
      const key = groupKey(profile.accountId, row.device_id, row.scope_kind, scopeId), group = groups.get(key) ?? []; group.push(row); groups.set(key, group);
    }
    for (const profile of Object.values(state.profiles).filter((p) => p.active)) {
      const holders = [{ id: null, scopes: profile.scopes }, ...Object.values(state.devices).filter((d) => d.active && d.accountId === profile.accountId).map((d) => ({ id: d.id as string | null, scopes: d.scopes }))];
      for (const holder of holders) for (const expected of holder.scopes) {
        const rows = groups.get(groupKey(profile.accountId, holder.id, expected.scope, expected.scopeId));
        if (!rows?.length) { if (expected.expiresAt !== null && Date.parse(expected.expiresAt) <= now.getTime()) continue; throw changed(); }
        const permissions = [...new Set(rows.flatMap((r) => r.permissions))].sort();
        const expires = rows.reduce<Date | null>((value, row) => row.expires_at && (!value || row.expires_at < value) ? row.expires_at : value, null)?.toISOString() ?? null;
        if (!equal(permissions, [...expected.permissions].sort()) || expires !== expected.expiresAt) throw changed();
      }
    }
  }
  async #materials(c: pg.PoolClient, workspaceId: string, ids: readonly string[]): Promise<PairingMaterial[]> {
    const unique = [...new Set(ids)].sort(), result: PairingMaterial[] = [];
    for (const id of unique) { const object = await this.#object(c, workspaceId, id);
      result.push({ id, digest: object.object_hash, kind: object.object_kind, value: object.versioned_object }); }
    return result;
  }
  async withAuthorizedHistory<T>(workspaceId: string, auth: ProjectCreateAuth,
    action: (c: pg.PoolClient, context: { workspaceId: string; current: { securityHead: string; securityVersion: string } }) => Promise<T>): Promise<T> {
    return this.#tx(workspaceId, auth, (c, w) => action(c, { workspaceId, current: { securityHead: w.security_head, securityVersion: w.security_version } }), { history: true });
  }
  #actor(state: SecurityHistoryState, p: SessionPrincipal): ScopeProvisionBinding['authorizer'] {
    const d = state.devices[p.deviceId!]; if (!d || !d.active || d.accountId !== p.accountId) throw forbidden();
    return { accountId: p.accountId, credentialGeneration: p.credentialGeneration, sessionGeneration: p.sessionGeneration,
      device: { id: d.id, keyGeneration: d.keyGeneration, signingPublicKey: d.signingPublicKey, recipientPublicKey: d.recipientPublicKey } };
  }
  async #binding(c: pg.PoolClient, w: Authority, p: SessionPrincipal, now: Date, request: ProjectCreateRequest,
    times?: { issuedAt: string; expiresAt: string }): Promise<{ binding: ScopeProvisionBinding; plan: ScopeProvisionPlan; state: SecurityHistoryState }> {
    if(![1,2].includes(w.write_schema))throw new AppError('UPDATE_REQUIRED','Update the client before writing this workspace',409);
    if (w.lifecycle !== 'active' || w.licence_state !== 'active' || w.content_maintenance || w.restore_quarantine)
      throw new AppError('WORKSPACE_RESTRICTED', 'Project creation is unavailable while the workspace is restricted', 423);
    const state = await this.#history(c, request.workspaceId, w); await this.#live(c, request.workspaceId, state); await this.#liveGrants(c, state, now);
    let binding: ScopeProvisionBinding;
    try { binding = createProjectBinding(request, state, this.#actor(state, p), times ?? { issuedAt: now.toISOString(), expiresAt: new Date(now.getTime() + 600000).toISOString() }); }
    catch { throw changed(); }
    return { binding, plan: deriveScopeProvisionPlan(binding, state), state };
  }
  async #check(c: pg.PoolClient, w: Authority, p: SessionPrincipal, now: Date, binding: ScopeProvisionBinding) {
    if (Date.parse(binding.expiresAt) <= now.getTime() || Date.parse(binding.issuedAt) > now.getTime() + 30000) throw changed();
    const { workspaceId, operationId, projectId } = binding;
    const result = await this.#binding(c, w, p, now, { workspaceId, operationId, projectId }, binding);
    if (!equal(result.binding, binding)) throw changed();
    for (const recipient of result.plan.recipients) if (recipient.scope.expiresAt !== null && Date.parse(recipient.scope.expiresAt) <= now.getTime()) throw changed();
    return result;
  }
  async #ownerMaterials(c: pg.PoolClient, w: Authority, state: SecurityHistoryState, p: SessionPrincipal): Promise<PairingMaterial[]> {
    const genesis = await this.#object(c, state.workspaceId, w.genesis_object_id);
    const body = (genesis.versioned_object as { body: { device: { id: string }; deviceEnvelopeId: string; custodyId: string } }).body;
    const ids = [w.current_custody_manifest_object_id, ...state.devices[p.deviceId!]!.scopes.flatMap((s) => s.manifests.map((m) => m.id))];
    if (body.device.id === p.deviceId && state.devices[p.deviceId!]!.scopes.some((s) => s.manifests.some((m) => m.id === body.custodyId))) ids.push(body.deviceEnvelopeId);
    // Custody manifests preserve every retained historical ordinary-content key; no removed custodian is needed.
    return this.#materials(c, state.workspaceId, ids);
  }
  async context(cookie: string, csrf: string, input: unknown): Promise<ProjectCreateContext> {
    const request = parse(projectCreateRequest, input);
    return this.#tx(request.workspaceId, { cookieValue: cookie, csrfToken: csrf }, async (c, w, p, now) => {
      const prepared = await this.#binding(c, w, p, now, request);
      return { binding: prepared.binding, plan: prepared.plan, materials: await this.#ownerMaterials(c, w, prepared.state, p) };
    });
  }
  #objects(payload: ProjectCreatePayload) { const b = payload.transition.body.binding;
    return [{ id: b.operationId, kind: 'signed_grant', value: payload.transition }, { id: payload.custody.id, kind: 'custody_manifest', value: payload.custody.envelope },
      { id: payload.project.id, kind: 'encrypted_project', value: payload.project.envelope }, ...payload.deliveries.map((d) => ({ id: d.id, kind: 'key_envelope', value: d.envelope }))];
  }
  async #receipt(c: pg.PoolClient, workspaceId: string, operationId: string): Promise<ProjectCreateReceipt | null> {
    const row = (await c.query<{ operation_kind: string; request_hash: string; outcome: unknown }>('SELECT operation_kind,request_hash,outcome FROM security.operation_receipts WHERE workspace_id=$1 AND operation_id=$2', [workspaceId, operationId])).rows[0];
    if (!row) return null; if (row.operation_kind !== 'project.create') throw changed();
    const receipt = parse(projectCreateReceipt, row.outcome); if (receipt.requestHash !== row.request_hash) throw changed(); return receipt;
  }
  async #read(c: pg.PoolClient, workspaceId: string, operationId: string): Promise<ProjectCreatePayload | null> {
    const row = (await c.query<Stored>('SELECT * FROM security.staged_objects WHERE workspace_id=$1 AND object_id=$2', [workspaceId, operationId])).rows[0]; if (!row) return null;
    if (row.object_kind !== 'signed_grant' || row.staged_operation_id !== operationId || await digestObject(row.versioned_object) !== row.object_hash) throw changed();
    const transition = parse(projectCreateTransition, row.versioned_object), body = transition.body;
    const read = async (descriptor: { id: string; digest: string }, kind: string) => { const object = await this.#object(c, workspaceId, descriptor.id, false);
      if (object.object_kind !== kind || object.staged_operation_id !== operationId || object.state !== row.state || object.object_hash !== descriptor.digest) throw changed();
      return { id: object.object_id, envelope: object.versioned_object }; };
    return parse(projectCreatePayload, { transition, custody: await read(body.custody, 'custody_manifest'),
      project: body.project ? await read(body.project, 'encrypted_project') : null,
      deliveries: await Promise.all(body.deliveries.map((d) => read(d, 'key_envelope'))) });
  }
  async #project(workspaceId: string, receipt: ProjectCreateReceipt, application?: pg.PoolClient): Promise<ProjectCreateView> {
    try { await this.#o.hooks?.beforeProjection?.(); const result = await projectAuthoritativeWorkspace(this.#o.databases, workspaceId, application);
      return { state: result.state === 'ready' ? 'completed' : 'finishing', requestHash: receipt.requestHash, receipt };
    } catch { return { state: 'finishing', requestHash: receipt.requestHash, receipt }; }
  }
  async stage(cookie: string, csrf: string, input: unknown): Promise<ProjectCreateView> {
    const payload = parse(projectCreatePayload, input), b = payload.transition.body.binding;
    const view = await this.#tx(b.workspaceId, { cookieValue: cookie, csrfToken: csrf }, async (c, w, p, now): Promise<ProjectCreateView> => {
      const requestHash = await digestObject(payload), receipt = await this.#receipt(c, b.workspaceId, b.operationId);
      if (receipt) { if (receipt.requestHash !== requestHash) throw changed(); return { state: 'completed', requestHash, receipt }; }
      const { state } = await this.#check(c, w, p, now, b);
      try { await validateProjectCreatePayload(payload, b, state); } catch { throw invalid(); }
      for (const o of this.#objects(payload)) {
        const hash = await digestObject(o.value), prior = (await c.query<Stored>('SELECT * FROM security.staged_objects WHERE workspace_id=$1 AND object_id=$2', [b.workspaceId, o.id])).rows[0];
        if (prior && (prior.state !== 'staged' || prior.staged_operation_id !== b.operationId || prior.object_kind !== o.kind || prior.object_hash !== hash)) throw changed();
        if (!prior) await c.query('INSERT INTO security.staged_objects(workspace_id,object_id,object_kind,object_hash,versioned_object,staged_operation_id,created_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)', [b.workspaceId, o.id, o.kind, hash, o.value, b.operationId, now, b.expiresAt]);
      }
      const readback = await this.#read(c, b.workspaceId, b.operationId); if (!readback || await digestObject(readback) !== requestHash) throw changed();
      return { state: 'staged', requestHash, receipt: null };
    });
    return view.receipt ? this.#project(b.workspaceId, view.receipt) : view;
  }
  async #persist(c: pg.PoolClient, payload: ProjectCreatePayload, state: SecurityHistoryState, now: Date): Promise<void> {
    const b = payload.transition.body.binding;
    await c.query(`INSERT INTO security.project_creations(workspace_id,project_id,operation_id,project_object_id,security_version,created_at)
      VALUES($1,$2,$3,$2,$4,$5)`, [b.workspaceId,b.projectId,b.operationId,b.nextSecurityVersion,now]);
    for (const authority of Object.values(state.recoveryAuthorities)) await c.query(`UPDATE security.recovery_authorities SET state=$4,
      revoked_at=CASE WHEN $4='revoked' THEN coalesce(revoked_at,$7) ELSE NULL END,custody_epoch=$5,custody_envelope_object_id=$6
      WHERE workspace_id=$1 AND profile_id=$2 AND generation=$3`, [b.workspaceId, authority.accountId, authority.generation,
      authority.active ? 'active' : 'revoked', authority.custodyEpoch, authority.custodyEnvelope.id, now]);
    const generations = (await c.query<{ profile_id: string; scope_kind: string; scope_id: string | null; generation: string }>(`SELECT profile_id,scope_kind,scope_id,max(generation)::text AS generation FROM security.grants
      WHERE workspace_id=$1 AND device_id IS NULL GROUP BY profile_id,scope_kind,scope_id`, [b.workspaceId])).rows;
    await c.query("UPDATE security.grants SET state='revoked',revoked_at=$2 WHERE workspace_id=$1 AND state<>'revoked'", [b.workspaceId, now]);
    for (const profile of Object.values(state.profiles).filter((p) => p.active)) for (const scope of profile.scopes) {
      if (scope.expiresAt !== null && Date.parse(scope.expiresAt) <= now.getTime()) continue;
      const previous = generations.find((g) => g.profile_id === profile.accountId && g.scope_kind === scope.scope && (g.scope_id ?? b.workspaceId) === scope.scopeId);
      const role = scope.scope === 'project' ? profile.projectRoles[scope.scopeId] : null; if (scope.scope === 'project' && !role) throw changed();
      await c.query(`INSERT INTO security.grants(workspace_id,grant_id,profile_id,grant_kind,scope_kind,scope_id,generation,permissions,state,
        signed_grant_object_id,key_manifest_object_id,key_epoch,role_id,role_revision,security_version,created_at,activated_at,expires_at)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,'active',$9,$10,$11,$12,$13,$14,$15,$15,$16)`, [b.workspaceId, randomUUID(), profile.accountId,
        scope.scope === 'project' ? 'project' : profile.owner ? 'owner' : 'membership', scope.scope, scope.scope === 'workspace' ? null : scope.scopeId,
        String(BigInt(previous?.generation ?? '0') + 1n), scope.permissions, b.operationId, state.custodyManifest.id, scope.keyEpoch,
        role?.id ?? null, role?.revision ?? null, b.nextSecurityVersion, now, scope.expiresAt]);
    }
    for (const device of Object.values(state.devices).filter((d) => d.active)) for (const scope of device.scopes) {
      if (scope.expiresAt !== null && Date.parse(scope.expiresAt) <= now.getTime()) continue;
      const source = scope.manifests[0]; if (!source) throw changed(); const object = await this.#object(c, b.workspaceId, source.id);
      if (object.object_hash !== source.digest) throw changed();
      await c.query(`INSERT INTO security.grants(workspace_id,grant_id,profile_id,device_id,grant_kind,scope_kind,scope_id,generation,permissions,state,
        signed_grant_object_id,key_manifest_object_id,key_epoch,security_version,created_at,activated_at,expires_at)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'active',$10,$11,$12,$13,$14,$14,$15)`, [b.workspaceId, randomUUID(), device.accountId, device.id,
        scope.scope === 'workspace' ? 'device' : 'project', scope.scope, scope.scope === 'workspace' ? null : scope.scopeId, device.keyGeneration,
        scope.permissions, b.operationId, source.id, scope.keyEpoch, b.nextSecurityVersion, now, scope.expiresAt]);
    }
    for (const scope of Object.values(state.scopeHeads)) await c.query(`INSERT INTO security.scope_heads(workspace_id,scope_kind,scope_id,key_epoch,recovery_manifest_object_id,security_version) VALUES($1,$2,$3,$4,$5,$6)
      ON CONFLICT(workspace_id,scope_kind,scope_id) DO UPDATE SET key_epoch=EXCLUDED.key_epoch,recovery_manifest_object_id=EXCLUDED.recovery_manifest_object_id,security_version=EXCLUDED.security_version`, [b.workspaceId, scope.scope, scope.scopeId, scope.keyEpoch, state.custodyManifest.id, b.nextSecurityVersion]);
    await c.query(`UPDATE security.workspaces SET security_head=$2,security_version=$3,ownership_version=$4,custody_epoch=$5,
      current_custody_manifest_object_id=$6,updated_at=$7 WHERE workspace_id=$1`, [b.workspaceId, state.securityHead, state.securityVersion,
      state.ownershipVersion, state.custodyEpoch, state.custodyManifest.id, now]);
  }
  async finalize(cookie: string, csrf: string, input: unknown): Promise<ProjectCreateView> {
    const request = parse(projectCreateFinalize, input);
    if (!cookie || !csrf) throw forbidden(); const auth = { cookieValue: cookie, csrfToken: csrf };
    const preflight = await this.#tx(request.workspaceId, auth, async (c, w, p, now) => {
      const receipt = await this.#receipt(c, request.workspaceId, request.operationId);
      if (receipt) { if (receipt.requestHash !== request.requestHash) throw changed(); return receipt; }
      const payload = await this.#read(c, request.workspaceId, request.operationId);
      if (!payload || await digestObject(payload) !== request.requestHash) throw changed(); await this.#check(c, w, p, now, payload.transition.body.binding); return null;
    });
    if (preflight) return this.#project(request.workspaceId, preflight);
    try {
      const result = await withSecurityFence(this.#o.databases, request.workspaceId, async (application) => {
        let receipt: ProjectCreateReceipt;
        try { receipt = await this.#tx(request.workspaceId, auth, async (c, w, p, now) => {
          const previous = await this.#receipt(c, request.workspaceId, request.operationId);
          if (previous) { if (previous.requestHash !== request.requestHash) throw changed(); return previous; }
          const payload = await this.#read(c, request.workspaceId, request.operationId); if (!payload || await digestObject(payload) !== request.requestHash) throw changed();
          const b = payload.transition.body.binding, before = await this.#check(c, w, p, now, b);
          let checked: Awaited<ReturnType<typeof validateProjectCreatePayload>>;
          try { checked = await validateProjectCreatePayload(payload, b, before.state); } catch { throw changed(); }
          const after = await this.#history(c, b.workspaceId, w, payload.transition);
          await c.query(`INSERT INTO security.security_transitions(workspace_id,sequence,operation_id,previous_head,head,action,actor_kind,actor_profile_id,actor_device_id,signed_transition,created_at)
            VALUES($1,$2,$3,$4,$5,$6,'device',$7,$8,$9,$10)`, [b.workspaceId, b.nextSecurityVersion, b.operationId, b.securityHead, checked.securityHead,
            'project.create', b.authorizer.accountId, b.authorizer.device.id, payload.transition, now]);
          const objects = this.#objects(payload), committed = await c.query("UPDATE security.staged_objects SET state='committed',committed_security_version=$3 WHERE workspace_id=$1 AND staged_operation_id=$2 AND state='staged' AND object_id=ANY($4::uuid[])", [b.workspaceId, b.operationId, b.nextSecurityVersion, objects.map((o) => o.id)]);
          if (committed.rowCount !== objects.length) throw changed(); await this.#persist(c, payload, after, now);
          const outcome = parse(projectCreateReceipt, { version: 1, workspaceId: b.workspaceId, operationId: b.operationId, projectId: b.projectId,
            securityVersion: b.nextSecurityVersion, securityHead: checked.securityHead, requestHash: checked.requestHash, committedAt: now.toISOString(), transition: payload.transition });
          const durable = (await c.query<{ outcome: ProjectCreateReceipt }>(`INSERT INTO security.operation_receipts(workspace_id,operation_id,request_hash,operation_kind,security_version,outcome,created_at)
            VALUES($1,$2,$3,'project.create',$4,$5,$6) RETURNING outcome`, [b.workspaceId, b.operationId, checked.requestHash, b.nextSecurityVersion, outcome, now])).rows[0]!.outcome;
          await this.#o.hooks?.beforeControlCommit?.(); return durable;
        }); } catch (error) { await projectAuthoritativeWorkspace(this.#o.databases, request.workspaceId, application); return { error }; }
        await this.#o.hooks?.afterControlCommit?.(); return { view: await this.#project(request.workspaceId, receipt, application) };
      }, { enqueueActivationProjection: true });
      if ('error' in result) throw result.error; return result.view;
    } catch (error) { if (error instanceof AppError) throw error; throw unavailable(); }
  }
  async status(cookie: string, csrf: string, input: unknown): Promise<ProjectCreateView> {
    const request = parse(projectCreateReference, input);
    const view = await this.#tx(request.workspaceId, { cookieValue: cookie, csrfToken: csrf }, async (c, _w, _p, now): Promise<ProjectCreateView> => {
      const receipt = await this.#receipt(c, request.workspaceId, request.operationId); if (receipt) return { state: 'completed', requestHash: receipt.requestHash, receipt };
      const payload = await this.#read(c, request.workspaceId, request.operationId); if (!payload) return { state: 'absent', requestHash: null, receipt: null };
      return { state: Date.parse(payload.transition.body.binding.expiresAt) <= now.getTime() ? 'expired' : 'staged', requestHash: await digestObject(payload), receipt: null };
    }, { history: true });
    return view.receipt ? this.#project(request.workspaceId, view.receipt) : view;
  }
}
