import { randomUUID } from 'node:crypto';
import type pg from 'pg';
import { z } from 'zod';
import type { Databases } from '../../db.js';
import { AppError } from '../../errors.js';
import { assertAuthoritativeContentWrite, dataTransaction, tenantTransaction } from '../../persistence.js';
import { base64urlEncode, canonicalJson, digestObject } from '../../shared/crypto.js';
import { teamBinding, teamContextRequest, teamHeader, teamListRequest, teamReceipt, teamReference, teamHistoryRequest, teamHistoryPage, TEAM_HISTORY_MAX_BYTES,
  validateTeamPayload, type TeamContext, type TeamPayload, type TeamReceipt, type TeamHistoryPage } from '../../shared/teams.js';
import { assertCurrentUpgradeBatch, recordUpgradeBatch } from '../upgrades/ledger.js';
import { SessionService, type SessionPrincipal } from '../identity/sessions.js';

interface Options { databases: Databases; sessions: SessionService;
  requestBudget?: (scope: { workspaceId: string; accountId: string }) => Promise<void>;
  beforeCommit?: () => Promise<void> }
interface TeamRow { id: string; revision: string; key_epoch: string; encrypted_envelope: TeamPayload['envelope'] }
interface WorkspaceWriteState { lifecycle: string; licence_state: string; content_maintenance: boolean }
export interface TeamAuth { cookieValue: string; csrfToken: string }
const invalid = () => new AppError('INVALID_REQUEST', 'Invalid team request', 400);
const forbidden = () => new AppError('FORBIDDEN', 'An active Owner is required to manage teams', 403);
const conflict = () => new AppError('REVISION_CONFLICT', 'Team or security state changed; refresh before saving', 409);
function parse<T>(schema: z.ZodType<T>, value: unknown): T { const r = schema.safeParse(value); if (!r.success) throw invalid(); return r.data; }

/** Teams are ordinary workspace records; their members never become security grants. */
export class TeamService {
  constructor(readonly options: Options) {}
  async #tx<T>(auth: TeamAuth, workspaceId: string, owner: boolean, write: boolean,
    action: (c: pg.PoolClient, p: SessionPrincipal, state: WorkspaceWriteState) => Promise<T>): Promise<T> {
    const p = await this.options.sessions.authenticate(auth.cookieValue, { csrfToken: auth.csrfToken, approved: true, recent: owner && write });
    if (p.workspaceId !== workspaceId) throw new AppError('NOT_FOUND', 'Workspace not available', 404);
    await this.options.requestBudget?.({ workspaceId, accountId: p.accountId });
    return dataTransaction(this.options.databases, p, async (c, state) => {
      // Recheck after acquiring the workspace's shared fence, including a concurrent logout.
      const current = await this.options.sessions.authenticate(auth.cookieValue, { csrfToken: auth.csrfToken, approved: true, recent: owner && write });
      if (current.securityHead !== p.securityHead || current.dataGeneration !== p.dataGeneration) throw conflict();
      if (owner && !(await c.query('SELECT 1 FROM app.profiles WHERE workspace_id=$1 AND id=$2 AND state=\'active\' AND is_owner', [workspaceId, p.accountId])).rowCount) throw forbidden();
      return action(c, current, state);
    }, { write });
  }
  async #binding(c: pg.PoolClient, p: SessionPrincipal, request: z.infer<typeof teamContextRequest>): Promise<TeamContext> {
    const row = (await c.query<TeamRow>('SELECT id,revision,key_epoch,encrypted_envelope FROM app.teams WHERE workspace_id=$1 AND id=$2', [p.workspaceId, request.teamId])).rows[0];
    if (request.action === 'create' ? !!row : !row) throw conflict();
    const memberIds = row ? (await c.query<{ profile_id: string }>('SELECT profile_id FROM app.team_members WHERE workspace_id=$1 AND team_id=$2 ORDER BY profile_id', [p.workspaceId, request.teamId])).rows.map((r) => r.profile_id) : [];
    const previousSignedChange = row ? (await c.query<{ encrypted_envelope: TeamPayload }>(`SELECT encrypted_envelope FROM app.record_versions
      WHERE workspace_id=$1 AND record_type='team' AND record_id=$2 AND record_revision=$3`, [p.workspaceId, request.teamId, row.revision])).rows[0]?.encrypted_envelope : null;
    if (row && (!previousSignedChange || canonicalJson(previousSignedChange.envelope) !== canonicalJson(row.encrypted_envelope) ||
      canonicalJson([...previousSignedChange.mutation.body.memberIds].sort()) !== canonicalJson(memberIds))) throw conflict();
    const authority = await tenantTransaction(this.options.databases.control, p.workspaceId, undefined, async (control) => {
      const device = (await control.query<{ key_generation: string; signing_public_key: Buffer }>("SELECT key_generation,signing_public_key FROM security.devices WHERE workspace_id=$1 AND device_id=$2 AND profile_id=$3 AND state='active'", [p.workspaceId, p.deviceId, p.accountId])).rows[0];
      const scope = (await control.query<{ key_epoch: string }>("SELECT key_epoch FROM security.scope_heads WHERE workspace_id=$1 AND scope_kind='workspace' AND scope_id=$1", [p.workspaceId])).rows[0];
      if (!device || !scope || !p.deviceId) throw forbidden();
      const workspace = (await control.query('SELECT write_schema,active_upgrade_id FROM security.workspaces WHERE workspace_id=$1',[p.workspaceId])).rows[0];
      return { version: workspace.write_schema===2 || workspace.active_upgrade_id ? 3 : 2, ...(workspace.write_schema===2 || workspace.active_upgrade_id ? {writeSchema:workspace.write_schema} : {}), keyEpoch: scope.key_epoch, authorizer: { accountId: p.accountId, deviceId: p.deviceId,
        keyGeneration: device.key_generation, signingPublicKey: base64urlEncode(device.signing_public_key) } };
    });
    const now = new Date();
    return { binding: teamBinding.parse({ ...request, issuedAt: now.toISOString(), expiresAt: new Date(now.getTime() + 600_000).toISOString(), expectedRevision: row?.revision ?? '0', previousDigest: row ? await digestObject(row.encrypted_envelope) : null,
      previousMemberIds: memberIds, securityHead: p.securityHead, securityVersion: p.securityVersion, dataGeneration: p.dataGeneration, ...authority }),
      previous: row?.encrypted_envelope ?? null, previousSignedChange: previousSignedChange ?? null };
  }
  async context(auth: TeamAuth, value: unknown): Promise<TeamContext> {
    const request = parse(teamContextRequest, value);
    return this.#tx(auth, request.workspaceId, true, request.action!=='upgrade_content', (c, p) => this.#binding(c, p, request));
  }
  async #receipt(c: pg.PoolClient, p: SessionPrincipal, operationId: string): Promise<{ receipt: TeamReceipt; requestHash: string } | null> {
    const row = (await c.query<{ action: string; request_digest: string; encrypted_envelope: { receipt?: unknown } }>(
      'SELECT action,request_digest,encrypted_envelope FROM app.operation_receipts WHERE workspace_id=$1 AND data_generation=$2 AND operation_id=$3',
      [p.workspaceId, p.dataGeneration, operationId])).rows[0];
    if (!row) return null;
    if (!['teams.create', 'teams.update', 'teams.upgrade_content'].includes(row.action)) throw conflict();
    const receipt = teamReceipt.parse(row.encrypted_envelope.receipt);
    if (receipt.workspaceId !== p.workspaceId || receipt.actorId !== p.accountId || receipt.operationId !== operationId ||
      receipt.dataGeneration !== p.dataGeneration || receipt.requestHash !== row.request_digest) throw conflict();
    return { receipt, requestHash: row.request_digest };
  }
  async save(auth: TeamAuth, value: unknown): Promise<TeamReceipt> {
    let payload: TeamPayload;
    try { payload = await validateTeamPayload(value); } catch { throw invalid(); }
    const b = payload.mutation.body.binding, requestHash = await digestObject(payload);
    return this.#tx(auth, b.workspaceId, true, false, async (c, p, workspace) => {
      await c.query("SELECT pg_advisory_xact_lock(hashtextextended('ukda.team.operation:' || $1 || ':' || $2,0))", [b.workspaceId, b.operationId]);
      const prior = await this.#receipt(c, p, b.operationId);
      if (prior) { if (prior.requestHash !== requestHash) throw conflict(); return prior.receipt; }
      // A completed receipt is readable in restricted mode; a new mutation is not.
      const upgrade = b.action==='upgrade_content' && payload.mutation.body.version===3 && payload.mutation.body.upgrade
        ? await assertCurrentUpgradeBatch(this.options.databases,c,p,payload.mutation.body.upgrade,payload.upgradeItems,new Date()) : null;
      if (!upgrade) await tenantTransaction(this.options.databases.control,b.workspaceId,undefined,control=>assertAuthoritativeContentWrite(control,b.workspaceId,[payload.envelope.header.schema]));
      await this.options.sessions.authenticate(auth.cookieValue, { csrfToken: auth.csrfToken, approved: true, recent: true });
      await c.query("SELECT pg_advisory_xact_lock(hashtextextended('ukda.team:' || $1 || ':' || $2,0))", [b.workspaceId, b.teamId]);
      const current = await this.#binding(c, p, { workspaceId: b.workspaceId, teamId: b.teamId, operationId: b.operationId, action: b.action });
      // Exact old v1 receipts remain retryable, but fresh writes must sign their time.
      const now = new Date();
      if (!('version' in b) || Date.parse(b.issuedAt) > now.getTime() + 30_000 || Date.parse(b.expiresAt) <= now.getTime() ||
        canonicalJson({ ...current.binding, issuedAt: b.issuedAt, expiresAt: b.expiresAt }) !== canonicalJson(b)) throw conflict();
      const priorBinding = current.previousSignedChange?.mutation.body.binding;
      if (priorBinding && 'version' in priorBinding && Date.parse(priorBinding.issuedAt) > Date.parse(b.issuedAt)) throw conflict();
      const ids = payload.mutation.body.memberIds;
      const eligible = !upgrade ? await c.query("SELECT id FROM app.profiles WHERE workspace_id=$1 AND id=ANY($2::uuid[]) AND state='active'", [b.workspaceId, ids]) : null;
      if (eligible && eligible.rowCount !== ids.length) throw new AppError('MEMBER_INELIGIBLE', 'Select active workspace profiles', 409);
      const header = teamHeader(b), revision = header.revision;
      if (b.action === 'create') await c.query('INSERT INTO app.teams(workspace_id,id,revision,schema_version,key_epoch,encrypted_envelope) VALUES($1,$2,$3,$6,$4,$5)', [b.workspaceId, b.teamId, revision, b.keyEpoch, payload.envelope,header.schema]);
      else await c.query('UPDATE app.teams SET revision=$3,key_epoch=$4,encrypted_envelope=$5,schema_version=$6,updated_at=clock_timestamp() WHERE workspace_id=$1 AND id=$2', [b.workspaceId, b.teamId, revision, b.keyEpoch, payload.envelope,header.schema]);
      if (!upgrade) { await c.query('DELETE FROM app.team_members WHERE workspace_id=$1 AND team_id=$2', [b.workspaceId, b.teamId]);
      for (const id of ids) await c.query('INSERT INTO app.team_members(workspace_id,team_id,profile_id,revision) VALUES($1,$2,$3,$4)', [b.workspaceId, b.teamId, id, revision]); }
      await c.query(`INSERT INTO app.record_versions(workspace_id,id,record_type,record_id,record_revision,actor_profile_id,operation_id,key_epoch,encrypted_envelope,schema_version)
        VALUES($1,$2,'team',$3,$4,$5,$6,$7,$8,$9)`, [b.workspaceId, randomUUID(), b.teamId, revision, p.accountId, b.operationId, b.keyEpoch, payload,header.schema]);
      await c.query(`INSERT INTO app.audit_events(workspace_id,id,actor_profile_id,operation_id,action,record_type,record_id,key_epoch,encrypted_envelope,schema_version)
        VALUES($1,$2,$3,$4,$5,'team',$6,$7,$8,$9)`, [b.workspaceId, randomUUID(), p.accountId, b.operationId, header.action, b.teamId, b.keyEpoch, { mutation: payload.mutation, before: current.previous, after: payload.envelope },header.schema]);
      const receipt: TeamReceipt = { version: 1, workspaceId: b.workspaceId, teamId: b.teamId, operationId: b.operationId,
        actorId: p.accountId, revision, dataGeneration: p.dataGeneration, requestHash };
      await c.query(`INSERT INTO app.operation_receipts(workspace_id,id,data_generation,operation_id,actor_profile_id,action,request_digest,encrypted_envelope)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, [b.workspaceId, randomUUID(), p.dataGeneration, b.operationId, p.accountId, header.action, requestHash, { receipt }]);
      await c.query(`INSERT INTO app.outbox(workspace_id,id,data_generation,operation_id,event_type,deduplication_key,encrypted_envelope)
        VALUES($1,$2,$3,$4,'teams.changed',$5,$6)`, [b.workspaceId, randomUUID(), p.dataGeneration, b.operationId, `teams:${b.operationId}`, { teamId: b.teamId, revision, actorId: p.accountId }]);
      if(upgrade) await recordUpgradeBatch(c,p,b.operationId,payload,upgrade.proof,upgrade.items,now);
      await this.options.beforeCommit?.();
      return receipt;
    });
  }
  async status(auth: TeamAuth, value: unknown): Promise<{ receipt: TeamReceipt | null }> {
    const ref = parse(teamReference, value);
    return this.#tx(auth, ref.workspaceId, false, false, async (c, p) => {
      const found = await this.#receipt(c, p, ref.operationId);
      if (found && found.receipt.teamId !== ref.teamId) throw conflict();
      return { receipt: found?.receipt ?? null };
    });
  }
  async history(auth: TeamAuth, value: unknown): Promise<TeamHistoryPage> {
    const ref = parse(teamHistoryRequest, value);
    return this.#tx(auth, ref.workspaceId, false, false, async (c, p) => {
      const row = (await c.query<TeamRow>('SELECT id,revision,key_epoch,encrypted_envelope FROM app.teams WHERE workspace_id=$1 AND id=$2', [ref.workspaceId, ref.teamId])).rows[0];
      if (!row) throw new AppError('NOT_FOUND', 'Team not available', 404);
      const anchor = { revision: row.revision, digest: await digestObject(row.encrypted_envelope) };
      if (ref.anchor && canonicalJson(ref.anchor) !== canonicalJson(anchor) || BigInt(ref.afterRevision) >= BigInt(row.revision)) throw conflict();
      const rows = (await c.query<{ record_revision: string; encrypted_envelope: TeamPayload; created_at: Date }>(
        `SELECT record_revision,encrypted_envelope,created_at FROM app.record_versions WHERE workspace_id=$1 AND record_type='team'
          AND record_id=$2 AND record_revision>$3 AND record_revision<=$4 ORDER BY record_revision LIMIT $5`,
        [ref.workspaceId, ref.teamId, ref.afterRevision, row.revision, ref.limit])).rows;
      if (!rows.length) throw conflict();
      const records: TeamHistoryPage['records'] = [];
      let expected = BigInt(ref.afterRevision) + 1n;
      for (const record of rows) {
        const payload = await validateTeamPayload(record.encrypted_envelope), header = payload.envelope.header;
        if (record.record_revision !== String(expected++) || header.workspaceId !== ref.workspaceId || header.recordId !== ref.teamId ||
          header.revision !== record.record_revision) throw conflict();
        records.push({ payload, recordedAt: record.created_at.toISOString() });
      }
      const last = records.at(-1)!.payload.envelope, complete = last.header.revision === anchor.revision;
      if (complete && await digestObject(last) !== anchor.digest || !complete && records.length !== ref.limit) throw conflict();
      const page = teamHistoryPage.parse({ workspaceId: ref.workspaceId, teamId: ref.teamId, securityHead: p.securityHead,
        securityVersion: p.securityVersion, dataGeneration: p.dataGeneration, anchor, records,
        nextRevision: complete ? null : last.header.revision, complete });
      if (Buffer.byteLength(canonicalJson(page)) > TEAM_HISTORY_MAX_BYTES) throw new AppError('HISTORY_TOO_LARGE', 'Request a smaller team history page', 413);
      return page;
    });
  }
  async list(auth: TeamAuth, value: unknown) {
    const ref = parse(teamListRequest, value);
    return this.#tx(auth, ref.workspaceId, false, false, async (c, p) => {
      const rows = (await c.query<TeamRow>('SELECT id,revision,key_epoch,encrypted_envelope FROM app.teams WHERE workspace_id=$1 AND ($2::uuid IS NULL OR id>$2) ORDER BY id LIMIT $3', [ref.workspaceId, ref.after ?? null, ref.limit + 1])).rows;
      const visible = rows.slice(0, ref.limit), ids = visible.map((r) => r.id);
      const members = (await c.query<{ team_id: string; profile_id: string }>('SELECT team_id,profile_id FROM app.team_members WHERE workspace_id=$1 AND team_id=ANY($2::uuid[]) ORDER BY team_id,profile_id', [ref.workspaceId, ids])).rows;
      const versions = (await c.query<{ record_id: string; encrypted_envelope: TeamPayload }>(`SELECT v.record_id,v.encrypted_envelope FROM app.record_versions v
        JOIN app.teams t ON t.workspace_id=v.workspace_id AND t.id=v.record_id AND t.revision=v.record_revision
        WHERE v.workspace_id=$1 AND v.record_type='team' AND v.record_id=ANY($2::uuid[])`, [ref.workspaceId, ids])).rows;
      return { records: visible.map((row) => ({ ...row, memberIds: members.filter((m) => m.team_id === row.id).map((m) => m.profile_id),
        signedChange: versions.find((v) => v.record_id === row.id)?.encrypted_envelope ?? null })),
        nextCursor: rows.length > ref.limit ? visible.at(-1)!.id : null, securityHead: p.securityHead, securityVersion: p.securityVersion, dataGeneration: p.dataGeneration };
    });
  }
}
