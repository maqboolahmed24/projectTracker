import type pg from 'pg';
import { z } from 'zod';
import { transaction, type Databases } from '../../db.js';
import { AppError } from '../../errors.js';
import { contentEnvelope, identifier } from '../../shared/contracts.js';
import { base64urlEncode, canonicalJson, digestObject } from '../../shared/crypto.js';
import { roleBinding, roleContextRequest, roleFinalize, roleLabelHeader, rolePayload, roleReceipt, roleReference, roleListRequest,
  validateRolePayload, type RoleBinding, type RoleDefinition, type RolePayload, type RoleReceipt, type RoleContext, type RoleView } from '../../shared/roles.js';
import type { PairingMaterial } from '../../shared/pairing.js';
import { assertEntitlementAllows } from './entitlements.js';
import { readPersonalScopes } from './personal-scopes.js';
import { projectAuthoritativeWorkspace, withSecurityFence } from './projection.js';
import { SessionService, type SessionPrincipal } from './sessions.js';
export interface RoleAuth { cookieValue: string; csrfToken: string }
interface Options { databases: Databases; sessions: SessionService; origin: string; now?: () => Date;
  requestBudget?: (scope: { workspaceId: string; accountId: string; history: boolean }) => Promise<void>;
  hooks?: { beforeControlCommit?: () => Promise<void>; afterControlCommit?: () => Promise<void>; beforeProjection?: () => Promise<void> } }
interface Authority { lifecycle: string; licence_state: string; security_head: string; security_version: string; data_generation: string;
  ownership_version: string; custody_epoch: string; genesis_object_id: string; content_maintenance: boolean; restore_quarantine: boolean }
interface Stored { object_id: string; object_hash: string; object_kind: string; versioned_object: unknown; staged_operation_id: string; state: string; expires_at: Date | null }
interface RoleRow { role_id: string; template: 'owner' | 'manager' | 'member' | 'viewer' | 'custom'; revision: string; state: 'active' | 'retired';
  permissions: RoleDefinition['permissions']; definition_object_id: string; encrypted_role_object_id: string | null; security_version: string }
const changed = () => new AppError('ROLE_CHANGED', 'Role authority changed; prepare a current signed definition', 409);
const invalid = () => new AppError('ROLE_INVALID', 'Invalid role definition operation', 400);
const forbidden = () => new AppError('ROLE_FORBIDDEN', 'A current approved Owner is required', 403);
const unavailable = () => new AppError('ROLE_UNAVAILABLE', 'Role operation is temporarily unavailable; retain the local draft', 503);
const equal = (a: unknown, b: unknown) => canonicalJson(a) === canonicalJson(b);
const next = (value: string) => String(BigInt(value) + 1n);
function parse<T>(schema: z.ZodType<T>, input: unknown): T { const p = schema.safeParse(input); if (!p.success) throw invalid(); return p.data; }
/** Definition edits never rewrite existing personal/project permission snapshots. */
export class RoleService {
  readonly #o: Options; readonly #now: () => Date;
  constructor(options: Options) { if (new URL(options.origin).origin !== options.origin) throw new Error('Role operations require an exact origin'); this.#o = options; this.#now = options.now ?? (() => new Date()); }
  async #tx<T>(workspaceId: string, auth: RoleAuth, action: (c: pg.PoolClient, w: Authority, p: SessionPrincipal, now: Date) => Promise<T>, history = false): Promise<T> {
    if (!identifier.safeParse(workspaceId).success) throw invalid();
    try { return await transaction(this.#o.databases.control, async (c) => {
      await c.query("SET LOCAL synchronous_commit='on'"); await c.query("SELECT set_config('ukda.workspace_id',$1,true)", [workspaceId]);
      const w = (await c.query<Authority>('SELECT * FROM security.workspaces WHERE workspace_id=$1 FOR UPDATE', [workspaceId])).rows[0];
      if (!w || !['active', 'pending_deletion'].includes(w.lifecycle) || w.security_version === '0') throw forbidden();
      const p = await this.#o.sessions.resolveCurrent(c, auth.cookieValue, { csrfToken: auth.csrfToken, approved: true, recent: !history }, this.#now());
      if (p.workspaceId !== workspaceId || !p.deviceId || !(await c.query("SELECT 1 FROM security.profiles WHERE workspace_id=$1 AND profile_id=$2 AND state='active' AND is_owner", [workspaceId, p.accountId])).rowCount) throw forbidden();
      await this.#o.requestBudget?.({ workspaceId, accountId: p.accountId, history }); return action(c, w, p, this.#now());
    }); } catch (error) { if (error instanceof AppError) throw error; throw unavailable(); }
  }
  #writable(w: Authority) { assertEntitlementAllows(w.licence_state, 'expand_access'); if (w.lifecycle !== 'active' || w.content_maintenance || w.restore_quarantine) throw new AppError('WORKSPACE_RESTRICTED', 'Role definitions cannot change while workspace writes are restricted', 423); }
  async #object(c: pg.PoolClient, workspaceId: string, objectId: string, kind?: string, committed = true): Promise<Stored> {
    const o = (await c.query<Stored>('SELECT * FROM security.staged_objects WHERE workspace_id=$1 AND object_id=$2', [workspaceId, objectId])).rows[0];
    if (!o || (committed && o.state !== 'committed') || (kind && o.object_kind !== kind) || await digestObject(o.versioned_object) !== o.object_hash) throw changed(); return o;
  }
  async #definition(c: pg.PoolClient, workspaceId: string, roleId: string): Promise<{ row: RoleRow; definition: RoleDefinition; label: RolePayload['label'] } | null> {
    const row = (await c.query<RoleRow>('SELECT * FROM security.roles WHERE workspace_id=$1 AND role_id=$2', [workspaceId, roleId])).rows[0]; if (!row) return null;
    if (row.template !== 'custom') throw new AppError('BUILTIN_ROLE_IMMUTABLE', 'Built-in role definitions cannot be changed', 409);
    await this.#object(c, workspaceId, row.definition_object_id, 'signed_grant'); if (!row.encrypted_role_object_id) throw changed();
    const o = await this.#object(c, workspaceId, row.encrypted_role_object_id, 'encrypted_role'), envelope = contentEnvelope.parse(o.versioned_object);
    if (envelope.header.recordId !== roleId || envelope.header.recordType !== 'role' || envelope.header.workspaceId !== workspaceId || envelope.header.revision !== row.revision) throw changed();
    return { row, definition: { id: roleId, template: 'custom', revision: row.revision, state: row.state, permissions: row.permissions,
      label: { id: o.object_id, revision: row.revision, digest: o.object_hash } }, label: { id: o.object_id, envelope } };
  }
  async #unused(c: pg.PoolClient, workspaceId: string, roleId: string, now: Date) {
    const used = await c.query(`SELECT 1 FROM security.profiles WHERE workspace_id=$1 AND state='active' AND role_id=$2
      UNION ALL SELECT 1 FROM security.grants g LEFT JOIN security.profiles p ON p.workspace_id=g.workspace_id AND p.profile_id=g.profile_id
      LEFT JOIN security.staged_objects o ON o.workspace_id=g.workspace_id AND o.object_id=g.signed_grant_object_id AND o.state='committed'
      WHERE g.workspace_id=$1 AND g.device_id IS NULL AND g.state IN ('pending','active') AND g.revoked_at IS NULL
        AND (g.role_id=$2 OR (p.state='active' AND p.role_id IS NULL AND g.grant_kind='membership' AND o.versioned_object->'body'->'transcript'->'binding'->'role'->>'id'=$2::text))
      UNION ALL SELECT 1 FROM security.ceremonies WHERE workspace_id=$1 AND kind='invitation' AND state IN ('issued','waiting_approval') AND expires_at>$3 AND public_state->>'roleId'=$2::text LIMIT 1`, [workspaceId, roleId, now]);
    if (used.rowCount) throw new AppError('ROLE_IN_USE', 'Reassign people and invitations before retiring this role', 409);
  }
  async #binding(c: pg.PoolClient, w: Authority, p: SessionPrincipal, now: Date, request: z.infer<typeof roleContextRequest>, times?: { issuedAt: string; expiresAt: string }): Promise<RoleBinding> {
    const previous = await this.#definition(c, request.workspaceId, request.roleId);
    if (request.action === 'create' ? previous !== null : previous === null || previous.row.state !== 'active') throw changed();
    if (request.action === 'retire') await this.#unused(c, request.workspaceId, request.roleId, now);
    const d = (await c.query<{ key_generation: string; signing_public_key: Buffer; recipient_public_key: Buffer }>('SELECT key_generation,signing_public_key,recipient_public_key FROM security.devices WHERE workspace_id=$1 AND profile_id=$2 AND device_id=$3', [request.workspaceId, p.accountId, p.deviceId])).rows[0]; if (!d) throw forbidden();
    const epoch = (await c.query<{ key_epoch: string }>("SELECT key_epoch FROM security.scope_heads WHERE workspace_id=$1 AND scope_kind='workspace' AND scope_id=$1", [request.workspaceId])).rows[0]?.key_epoch;
    const genesis = await this.#object(c, request.workspaceId, w.genesis_object_id, 'genesis'); if (!epoch) throw changed();
    return roleBinding.parse({ version: 1, origin: this.#o.origin, ...request, previous: previous?.definition ?? null, nextRevision: previous ? next(previous.row.revision) : '1',
      authorizer: { accountId: p.accountId, device: { id: p.deviceId!, keyGeneration: d.key_generation, signingPublicKey: base64urlEncode(d.signing_public_key), recipientPublicKey: base64urlEncode(d.recipient_public_key) }, credentialGeneration: p.credentialGeneration, sessionGeneration: p.sessionGeneration },
      securityVersion: w.security_version, nextSecurityVersion: next(w.security_version), securityHead: w.security_head, dataGeneration: w.data_generation,
      ownershipVersion: w.ownership_version, custodyEpoch: w.custody_epoch, workspaceKeyEpoch: epoch, genesisFingerprint: genesis.object_hash,
      issuedAt: times?.issuedAt ?? now.toISOString(), expiresAt: times?.expiresAt ?? new Date(now.getTime() + 600_000).toISOString() });
  }
  async #check(c: pg.PoolClient, w: Authority, p: SessionPrincipal, now: Date, b: RoleBinding) {
    this.#writable(w); if (Date.parse(b.expiresAt) <= now.getTime() || Date.parse(b.issuedAt) > now.getTime() + 30_000) throw changed();
    const expected = await this.#binding(c, w, p, now, { workspaceId: b.workspaceId, operationId: b.operationId, action: b.action, roleId: b.roleId }, b);
    if (!equal(expected, b)) throw changed();
  }
  async #materials(c: pg.PoolClient, workspaceId: string, p: SessionPrincipal, w: Authority, now: Date): Promise<PairingMaterial[]> {
    const personal = await readPersonalScopes(c, workspaceId, p.accountId, true, now), workspace = personal.find((s) => s.scope === 'workspace')!;
    const ids = workspace.sources.map((s) => s.manifestId), rows = (await c.query<Stored>(`SELECT * FROM security.staged_objects WHERE workspace_id=$1 AND state='committed' AND
      (object_id=ANY($2::uuid[]) OR (object_kind='key_envelope' AND versioned_object->'header'->>'recipientId'=$3 AND versioned_object->'header'->>'recipientKind'='device') OR
      (object_kind='custody_manifest' AND versioned_object->'header'->>'scope'='workspace' AND versioned_object->'header'->>'scopeId'=$1::text AND versioned_object->'header'->>'keyEpoch'=$4)) ORDER BY object_id`, [workspaceId, ids, p.deviceId, w.custody_epoch])).rows;
    const materials: PairingMaterial[] = [];
    for (const o of rows) { const header = (o.versioned_object as { header?: { scope?: string; scopeId?: string } }).header;
      if (!ids.includes(o.object_id) && (header?.scope !== 'workspace' || header.scopeId !== workspaceId)) continue;
      if (await digestObject(o.versioned_object) !== o.object_hash) throw changed(); materials.push({ id: o.object_id, kind: o.object_kind, digest: o.object_hash, value: o.versioned_object }); }
    if (ids.some((id) => !materials.some((m) => m.id === id))) throw changed(); return materials;
  }
  async context(cookie: string, csrf: string, input: unknown): Promise<RoleContext> { const request = parse(roleContextRequest, input); return this.#tx(request.workspaceId, { cookieValue: cookie, csrfToken: csrf }, async (c, w, p, now) => {
    this.#writable(w); const binding = await this.#binding(c, w, p, now, request), prior = binding.previous ? await this.#definition(c, request.workspaceId, request.roleId) : null;
    return { binding, labelHeader: roleLabelHeader(binding), previousLabel: prior?.label ?? null, materials: await this.#materials(c, request.workspaceId, p, w, now) };
  }); }
  async #receipt(c: pg.PoolClient, workspaceId: string, operationId: string): Promise<RoleReceipt | null> {
    const row = (await c.query<{ outcome: unknown; operation_kind: string; request_hash: string }>('SELECT outcome,operation_kind,request_hash FROM security.operation_receipts WHERE workspace_id=$1 AND operation_id=$2', [workspaceId, operationId])).rows[0];
    if (!row) return null; if (row.operation_kind !== 'role.define') throw changed(); const receipt = roleReceipt.parse(row.outcome); if (receipt.requestHash !== row.request_hash) throw changed(); return receipt;
  }
  async #read(c: pg.PoolClient, workspaceId: string, operationId: string): Promise<{ payload: RolePayload; requestHash: string; securityHead: string } | null> {
    const found = (await c.query<Stored>('SELECT * FROM security.staged_objects WHERE workspace_id=$1 AND object_id=$2', [workspaceId, operationId])).rows[0]; if (!found) return null;
    if (found.object_kind !== 'signed_grant' || found.staged_operation_id !== operationId || await digestObject(found.versioned_object) !== found.object_hash) throw changed();
    const transition = rolePayload.shape.transition.parse(found.versioned_object), descriptor = transition.body.role.label;
    const label = await this.#object(c, workspaceId, descriptor.id, 'encrypted_role', false);
    if (label.staged_operation_id !== operationId || label.state !== found.state || label.object_hash !== descriptor.digest) throw changed();
    let checked: Awaited<ReturnType<typeof validateRolePayload>>;
    try { checked = await validateRolePayload({ transition, label: { id: label.object_id, envelope: label.versioned_object } }, transition.body.binding); } catch { throw changed(); }
    return { payload: checked.payload, requestHash: checked.requestHash, securityHead: checked.securityHead };
  }
  async stage(cookie: string, csrf: string, input: unknown): Promise<RoleView> { const payload = parse(rolePayload, input), b = payload.transition.body.binding;
    const view: RoleView = await this.#tx(b.workspaceId, { cookieValue: cookie, csrfToken: csrf }, async (c, w, p, now): Promise<RoleView> => {
      let checked: Awaited<ReturnType<typeof validateRolePayload>>; try { checked = await validateRolePayload(payload, b); } catch { throw invalid(); }
      const receipt = await this.#receipt(c, b.workspaceId, b.operationId); if (receipt) { if (receipt.requestHash !== checked.requestHash) throw changed(); return { state: 'completed', requestHash: receipt.requestHash, receipt }; }
      await this.#check(c, w, p, now, b);
      if ((await c.query('SELECT 1 FROM security.security_transitions WHERE workspace_id=$1 AND operation_id=$2', [b.workspaceId, b.operationId])).rowCount) throw changed();
      for (const o of [{ id: b.operationId, kind: 'signed_grant', value: payload.transition }, { id: payload.label.id, kind: 'encrypted_role', value: payload.label.envelope }]) {
        const hash = await digestObject(o.value), prior = (await c.query<Stored>('SELECT * FROM security.staged_objects WHERE workspace_id=$1 AND object_id=$2', [b.workspaceId, o.id])).rows[0];
        if (prior && (prior.state !== 'staged' || prior.staged_operation_id !== b.operationId || prior.object_hash !== hash || prior.object_kind !== o.kind)) throw changed();
        if (!prior) await c.query('INSERT INTO security.staged_objects(workspace_id,object_id,object_kind,object_hash,versioned_object,staged_operation_id,created_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)', [b.workspaceId, o.id, o.kind, hash, o.value, b.operationId, now, b.expiresAt]);
      }
      const readback = await this.#read(c, b.workspaceId, b.operationId); if (!readback || readback.requestHash !== checked.requestHash) throw changed();
      return { state: 'staged', requestHash: checked.requestHash, receipt: null };
    });
    return view.receipt ? this.#project(b.workspaceId, view.receipt) : view;
  }
  async #project(workspaceId: string, receipt: RoleReceipt, application?: pg.PoolClient): Promise<RoleView> {
    try { await this.#o.hooks?.beforeProjection?.(); const result = await projectAuthoritativeWorkspace(this.#o.databases, workspaceId, application);
      return { state: result.state === 'ready' ? 'completed' : 'finishing', requestHash: receipt.requestHash, receipt };
    } catch { return { state: 'finishing', requestHash: receipt.requestHash, receipt }; }
  }
  async finalize(cookie: string, csrf: string, input: unknown): Promise<RoleView> {
    const request = parse(roleFinalize, input), auth = { cookieValue: cookie, csrfToken: csrf };
    const preflight = await this.#tx(request.workspaceId, auth, async (c, w, p, now) => {
      const receipt = await this.#receipt(c, request.workspaceId, request.operationId);
      if (receipt) { if (receipt.requestHash !== request.requestHash) throw changed(); return receipt; }
      const staged = await this.#read(c, request.workspaceId, request.operationId);
      if (!staged || staged.requestHash !== request.requestHash) throw changed(); await this.#check(c, w, p, now, staged.payload.transition.body.binding); return null;
    });
    if (preflight) return this.#project(request.workspaceId, preflight);
    try {
      const result = await withSecurityFence(this.#o.databases, request.workspaceId, async (application) => {
        let receipt: RoleReceipt;
        try { receipt = await this.#tx(request.workspaceId, auth, async (c, w, p, now) => {
          const prior = await this.#receipt(c, request.workspaceId, request.operationId);
          if (prior) { if (prior.requestHash !== request.requestHash) throw changed(); return prior; }
          const staged = await this.#read(c, request.workspaceId, request.operationId);
          if (!staged || staged.requestHash !== request.requestHash) throw changed();
          const payload = staged.payload, b = payload.transition.body.binding, role = payload.transition.body.role;
          await this.#check(c, w, p, now, b);
          await c.query(`INSERT INTO security.security_transitions(workspace_id,sequence,operation_id,previous_head,head,action,actor_kind,actor_profile_id,actor_device_id,signed_transition,created_at)
            VALUES($1,$2,$3,$4,$5,$6,'device',$7,$8,$9,$10)`, [b.workspaceId, b.nextSecurityVersion, b.operationId, b.securityHead, staged.securityHead, `role.${b.action}`, b.authorizer.accountId, b.authorizer.device.id, payload.transition, now]);
          const committed = await c.query("UPDATE security.staged_objects SET state='committed',committed_security_version=$3 WHERE workspace_id=$1 AND staged_operation_id=$2 AND state='staged' AND object_id=ANY($4::uuid[])", [b.workspaceId, b.operationId, b.nextSecurityVersion, [b.operationId, payload.label.id]]);
          if (committed.rowCount !== 2) throw changed();
          if (b.action === 'create') await c.query(`INSERT INTO security.roles(workspace_id,role_id,template,revision,state,permissions,definition_object_id,encrypted_role_object_id,security_version)
            VALUES($1,$2,'custom',$3,$4,$5,$6,$7,$8)`, [b.workspaceId, b.roleId, role.revision, role.state, role.permissions, b.operationId, payload.label.id, b.nextSecurityVersion]);
          else await c.query(`UPDATE security.roles SET revision=$3,state=$4,permissions=$5,definition_object_id=$6,encrypted_role_object_id=$7,security_version=$8
            WHERE workspace_id=$1 AND role_id=$2`, [b.workspaceId, b.roleId, role.revision, role.state, role.permissions, b.operationId, payload.label.id, b.nextSecurityVersion]);
          await c.query('UPDATE security.workspaces SET security_head=$2,security_version=$3,updated_at=$4 WHERE workspace_id=$1', [b.workspaceId, staged.securityHead, b.nextSecurityVersion, now]);
          const outcome = roleReceipt.parse({ version: 1, workspaceId: b.workspaceId, operationId: b.operationId, roleId: b.roleId, roleRevision: role.revision,
            securityVersion: b.nextSecurityVersion, securityHead: staged.securityHead, requestHash: request.requestHash, committedAt: now.toISOString(), transition: payload.transition });
          const durable = (await c.query<{ outcome: RoleReceipt }>(`INSERT INTO security.operation_receipts(workspace_id,operation_id,request_hash,operation_kind,security_version,outcome,created_at)
            VALUES($1,$2,$3,'role.define',$4,$5,$6) RETURNING outcome`, [b.workspaceId, b.operationId, request.requestHash, b.nextSecurityVersion, outcome, now])).rows[0]!.outcome;
          await this.#o.hooks?.beforeControlCommit?.(); return durable;
        }); } catch (error) {
          // A rolled-back authority write must not strand otherwise current content behind its preparation fence.
          await projectAuthoritativeWorkspace(this.#o.databases, request.workspaceId, application); return { error };
        }
        await this.#o.hooks?.afterControlCommit?.(); return { view: await this.#project(request.workspaceId, receipt, application) };
      }, { enqueueActivationProjection: true });
      if ('error' in result) throw result.error; return result.view;
    } catch (error) { if (error instanceof AppError) throw error; throw unavailable(); }
  }
  async status(cookie: string, csrf: string, input: unknown): Promise<RoleView> {
    const request = parse(roleReference, input), view = await this.#tx(request.workspaceId, { cookieValue: cookie, csrfToken: csrf }, async (c, _w, _p, now): Promise<RoleView> => {
      const receipt = await this.#receipt(c, request.workspaceId, request.operationId); if (receipt) return { state: 'completed', requestHash: receipt.requestHash, receipt };
      const staged = await this.#read(c, request.workspaceId, request.operationId); if (!staged) return { state: 'absent', requestHash: null, receipt: null };
      return { state: Date.parse(staged.payload.transition.body.binding.expiresAt) <= now.getTime() ? 'expired' : 'staged', requestHash: staged.requestHash, receipt: null };
    }, true);
    return view.receipt ? this.#project(request.workspaceId, view.receipt) : view;
  }
  async list(cookie: string, csrf: string, input: unknown): Promise<import('../../shared/roles.js').RoleList> {
    const request = parse(roleListRequest, input); return this.#tx(request.workspaceId, { cookieValue: cookie, csrfToken: csrf }, async (c, w, p, now) => {
      const rows = (await c.query<RoleRow>('SELECT * FROM security.roles WHERE workspace_id=$1 AND ($2::uuid IS NULL OR role_id>$2) ORDER BY role_id LIMIT $3', [request.workspaceId, request.afterRoleId ?? null, request.limit + 1])).rows;
      const page = rows.slice(0, request.limit), roles = [];
      for (const row of page) {
        const label = row.template === 'custom' ? (await this.#definition(c, request.workspaceId, row.role_id))!.label : null;
        if (!label) await this.#object(c, request.workspaceId, row.definition_object_id);
        roles.push({ id: row.role_id, template: row.template, revision: row.revision, state: row.state, permissions: row.permissions, label });
      }
      return { workspaceId: request.workspaceId, roles, nextRoleId: rows.length > request.limit ? page.at(-1)!.role_id : null,
        current: { securityHead: w.security_head, securityVersion: w.security_version }, materials: await this.#materials(c, request.workspaceId, p, w, now) };
    }, true);
  }
  async withAuthorizedHistory<T>(workspaceId: string, auth: RoleAuth,
    action: (c: pg.PoolClient, context: { workspaceId: string; current: { securityHead: string; securityVersion: string } }) => Promise<T>): Promise<T> {
    return this.#tx(workspaceId, auth, (c, w) => action(c, { workspaceId, current: { securityHead: w.security_head, securityVersion: w.security_version } }), true);
  }
}
