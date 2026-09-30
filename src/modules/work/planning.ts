import { randomUUID } from 'node:crypto';
import type pg from 'pg';
import { z } from 'zod';
import { transaction, type Databases } from '../../db.js';
import { AppError } from '../../errors.js';
import { assertAuthoritativeContentWrite,dataTransaction } from '../../persistence.js';
import { contentEnvelope, type ContentEnvelope } from '../../shared/contracts.js';
import { base64urlEncode, canonicalJson, digestObject } from '../../shared/crypto.js';
import { planningBinding, planningContext, planningGraph, planningGraphDigest, planningPayload, planningReceipt, planningReference, planningStatusRequest,
  canonicalPlanningGraph, planningEligibleAssignees, planningEligibleReviewers, validatePlanningPayload, verifyPlanningContext, PLANNING_MAX_BYTES, PLANNING_MAX_RECORDS, PLANNING_HISTORY_MAX_OPERATIONS, PLANNING_HISTORY_MAX_BYTES, PLANNING_HISTORY_PAGE_SIZE, planningFrame, planningAnchorFor, planningOperationsRequest, planningOperationsPage,
  type PlanningBinding, type PlanningContext, type PlanningPayload, type PlanningReceipt, type PlanningRecord, type PlanningSecurityResolver, type PlanningView, type PlanningOperationsPage } from '../../shared/planning-api.js';
import { PlanningError, planningRevisionSnapshot, type PlanningState } from '../../shared/planning.js';
import { projectCreateTransition } from '../../shared/project-create.js';
import { verifySecurityHistory, type SecurityHistoryState } from '../../shared/security-history.js';
import { readPersonalScopes, intersectDeviceScopes, PersonalScopeError } from '../identity/personal-scopes.js';
import type { PairingMaterial, PairingScope } from '../../shared/pairing.js';
import { SessionService, type SessionPrincipal } from '../identity/sessions.js';
import type { ServiceSecrets } from '../identity/secrets.js';
import { EntitlementOperations } from '../identity/entitlements.js';
import { enqueueNotificationJob, planningNotificationEvents } from '../notifications/delivery.js';
import { readReportingSettings } from './reporting.js';
import { assertCurrentUpgradeBatch,recordUpgradeBatch } from '../upgrades/ledger.js';
import type { UpgradeItem } from '../../shared/encrypted-upgrades.js';
import { assertPlanningFileEvidence } from '../files/evidence-service.js';
const invalid = () => new AppError('PLANNING_INVALID', 'Invalid encrypted planning operation', 400);
const changed = () => new AppError('PLANNING_CHANGED', 'Project state changed; reload before preparing this operation', 409);
const forbidden = () => new AppError('PLANNING_FORBIDDEN', 'Current project access and device keys are required', 403);
const oversized = () => new AppError('PLANNING_CONTEXT_TOO_LARGE', 'The complete project exceeds the current planning context limit', 413);
const unavailable = () => new AppError('PLANNING_UNAVAILABLE', 'Planning is temporarily unavailable; retain the encrypted draft', 503);
const same = (a: unknown, b: unknown) => canonicalJson(a) === canonicalJson(b);
function parse<T>(schema: z.ZodType<T>, value: unknown): T { const parsed = schema.safeParse(value); if (!parsed.success) throw invalid(); return parsed.data; }
interface Options { databases: Databases; sessions: SessionService; secrets: ServiceSecrets; origin: string; now?: () => Date;
  requestBudget?: (scope: { workspaceId: string; accountId: string }) => Promise<void>;
  hooks?: { beforeCommit?: () => Promise<void>; afterCommit?: () => Promise<void> } }
interface Profile { is_owner: boolean; role_id: string; credential_generation: string; session_generation: string }
interface Device { key_generation: string; signing_public_key: Buffer }
interface Operation { signed_mutation: PlanningContext['history'][number]; closing_snapshot: PlanningState['snapshots'][number] | null;
  movements: PlanningState['movements']; receipt: PlanningReceipt; request_digest: string; data_generation: string; project_id: string; planning_version: string;
  operation_id:string;upgrade_items:UpgradeItem[]|null }
interface Authority { principal: SessionPrincipal; profile: Profile; device: Device; scopes: PairingScope[] }

/** Caller must hold the shared application security fence until its read/write finishes. */
export async function readCurrentDeviceProjectScopes(control: pg.PoolClient, principal: SessionPrincipal, now = new Date()): Promise<PairingScope[]> {
  if (!principal.deviceId || principal.accessLevel !== 'device_approved') throw forbidden();
  await control.query("SELECT set_config('ukda.workspace_id',$1,true)", [principal.workspaceId]);
  const row = (await control.query<Profile>(`SELECT p.* FROM security.profiles p JOIN security.workspaces w USING(workspace_id)
    JOIN security.sessions s ON s.workspace_id=p.workspace_id AND s.profile_id=p.profile_id
    JOIN security.devices d ON d.workspace_id=p.workspace_id AND d.profile_id=p.profile_id AND d.device_id=s.device_id
    WHERE p.workspace_id=$1 AND p.profile_id=$2 AND s.session_id=$3 AND d.device_id=$4 AND p.state='active' AND d.state='active' AND d.revoked_at IS NULL
      AND s.revoked_at IS NULL AND s.idle_expires_at>$5 AND s.absolute_expires_at>$5 AND s.access_level='device_approved'
      AND s.credential_generation=p.credential_generation AND s.session_generation=p.session_generation AND s.data_generation=w.data_generation
      AND w.data_generation=$6 AND w.security_version=$7 AND w.security_head=$8`,
  [principal.workspaceId, principal.accountId, principal.sessionId, principal.deviceId, now, principal.dataGeneration, principal.securityVersion, principal.securityHead])).rows[0];
  if (!row || row.credential_generation !== principal.credentialGeneration || row.session_generation !== principal.sessionGeneration) throw forbidden();
  try { return await intersectDeviceScopes(control, principal.workspaceId, principal.accountId, principal.deviceId,
    await readPersonalScopes(control, principal.workspaceId, principal.accountId, row.is_owner, now), now); }
  catch (error) { if (error instanceof PersonalScopeError) throw forbidden(); throw error; }
}

export class PlanningService {
  readonly #o: Options; readonly #now: () => Date; readonly #trusted: Promise<Record<string, string>>;
  constructor(options: Options) {
    if (new URL(options.origin).origin !== options.origin) throw new Error('Planning requires an exact origin');
    this.#o = options; this.#now = options.now ?? (() => new Date());
    this.#trusted = new EntitlementOperations(options.databases, options.secrets).publicSigningKey().then((key) => ({ [options.secrets.keyId]: key }));
  }
  async #with<T>(ref: z.infer<typeof planningReference>, cookie: string, csrf: string,
    action: (application: pg.PoolClient, control: pg.PoolClient, authority: Authority, now: Date) => Promise<T>, write = false, applyAccountBudget = true): Promise<T> {
    try {
      const initial = await this.#o.sessions.authenticate(cookie, { csrfToken: csrf, approved: true });
      if (initial.workspaceId !== ref.workspaceId) throw forbidden();
      return await dataTransaction(this.#o.databases, initial, async (application) => {
        // Settings changes lock this exclusively; closure stamps and reporting
        // vector reads use a consistent settings-before-project lock order.
        await application.query("SELECT pg_advisory_xact_lock_shared(hashtextextended('ukda.reporting:' || $1,0))", [ref.workspaceId]);
        await application.query("SELECT pg_advisory_xact_lock(hashtextextended('ukda.project:' || $1 || ':' || $2,0))", [ref.workspaceId, ref.projectId]);
        return transaction(this.#o.databases.control, async (control) => {
          const now = this.#now(), principal = await this.#o.sessions.resolveCurrent(control, cookie, { csrfToken: csrf, approved: true }, now);
          if (principal.workspaceId !== initial.workspaceId || principal.securityHead !== initial.securityHead || principal.securityVersion !== initial.securityVersion || principal.dataGeneration !== initial.dataGeneration) throw changed();
          const scopes = await readCurrentDeviceProjectScopes(control, principal, now);
          if (!scopes.some((scope) => scope.scope === 'project' && scope.scopeId === ref.projectId)) throw forbidden();
          const profile = (await control.query<Profile>("SELECT * FROM security.profiles WHERE workspace_id=$1 AND profile_id=$2 AND state='active'", [ref.workspaceId, principal.accountId])).rows[0];
          const device = (await control.query<Device>("SELECT * FROM security.devices WHERE workspace_id=$1 AND device_id=$2 AND state='active'", [ref.workspaceId, principal.deviceId])).rows[0];
          if (!profile || !device || !(await application.query('SELECT 1 FROM app.projects WHERE workspace_id=$1 AND id=$2', [ref.workspaceId, ref.projectId])).rowCount) throw forbidden();
          if(applyAccountBudget)await this.#o.requestBudget?.({ workspaceId: ref.workspaceId, accountId: principal.accountId });
          return action(application, control, { principal, profile, device, scopes }, now);
        });
      }, { write });
    } catch (error) {
      if (error instanceof AppError) throw error;
      if (error instanceof PlanningError) throw new AppError(`PLANNING_${error.code.toUpperCase()}`, error.message, error.code === 'permission_denied' ? 403 : 409);
      throw unavailable();
    }
  }
  async #security(control: pg.PoolClient, principal: SessionPrincipal): Promise<PlanningSecurityResolver> {
    const genesis = (await control.query<{ versioned_object: unknown; object_hash: string }>(`SELECT o.versioned_object,o.object_hash FROM security.workspaces w
      JOIN security.staged_objects o ON o.workspace_id=w.workspace_id AND o.object_id=w.genesis_object_id AND o.state='committed' WHERE w.workspace_id=$1`, [principal.workspaceId])).rows[0];
    if (!genesis || genesis.object_hash !== await digestObject(genesis.versioned_object)) throw changed();
    const transitions = (await control.query<{ sequence: string; head: string; signed_transition: unknown }>('SELECT sequence,head,signed_transition FROM security.security_transitions WHERE workspace_id=$1 AND sequence>1 ORDER BY sequence', [principal.workspaceId])).rows;
    if (BigInt(transitions.length) + 1n !== BigInt(principal.securityVersion)) throw changed();
    const cache = new Map<string, SecurityHistoryState>();
    return async (version, suppliedHead) => {
      if (BigInt(version) < 1n || BigInt(version) > BigInt(principal.securityVersion)) throw changed();
      const head = version === '1' ? genesis.object_hash : transitions[Number(BigInt(version) - 2n)]?.head;
      if (!head || suppliedHead && suppliedHead !== head) throw changed();
      const cached = cache.get(version); if (cached) return cached;
      const state = await verifySecurityHistory({ workspaceId: principal.workspaceId, origin: this.#o.origin, genesisFingerprint: genesis.object_hash,
        genesis: genesis.versioned_object as Parameters<typeof verifySecurityHistory>[0]['genesis'], transitions: transitions.slice(0, Number(BigInt(version) - 1n)).map((row) => row.signed_transition),
        expected: { securityVersion: version, securityHead: head }, trustedServiceKeys: await this.#trusted });
      cache.set(version, state); return state;
    };
  }
  async #load(application: pg.PoolClient, control: pg.PoolClient, ref: z.infer<typeof planningReference>) {
    const creationRow = (await control.query<{ versioned_object: unknown }>(`SELECT o.versioned_object FROM security.project_creations p JOIN security.staged_objects o
      ON o.workspace_id=p.workspace_id AND o.object_id=p.operation_id AND o.state='committed' WHERE p.workspace_id=$1 AND p.project_id=$2`, [ref.workspaceId, ref.projectId])).rows[0];
    if (!creationRow) throw changed(); const creation = parse(projectCreateTransition, creationRow.versioned_object);
    const project = (await application.query('SELECT * FROM app.projects WHERE workspace_id=$1 AND id=$2', [ref.workspaceId, ref.projectId])).rows[0]; if (!project) throw forbidden();
    const rows: Record<'phase' | 'milestone' | 'task' | 'blocker', pg.QueryResultRow[]> = { phase: [], milestone: [], task: [], blocker: [] };
    for (const [kind, table] of [['phase', 'project_phases'], ['milestone', 'milestones'], ['task', 'tasks'], ['blocker', 'blockers']] as const) {
      const result = await application.query(`SELECT * FROM app.${table} WHERE workspace_id=$1 AND project_id=$2 ORDER BY id LIMIT $3`, [ref.workspaceId, ref.projectId, PLANNING_MAX_RECORDS + 1]);
      if (result.rows.length > PLANNING_MAX_RECORDS) throw oversized(); rows[kind] = result.rows;
    }
    if (rows.phase.length + rows.milestone.length + rows.task.length + rows.blocker.length + 1 > PLANNING_MAX_RECORDS) throw oversized();
    const assignments = (await application.query<{ task_id: string; member_id: string }>('SELECT task_id,member_id FROM app.task_assignments WHERE workspace_id=$1 AND project_id=$2 ORDER BY task_id,member_id', [ref.workspaceId, ref.projectId])).rows;
    const operations:Operation[]=[];let operationVersion='0',historyBytes=0;
    for(let page=0;page<=Math.ceil(PLANNING_HISTORY_MAX_OPERATIONS/PLANNING_HISTORY_PAGE_SIZE);page++) {
      const rows=(await application.query<Operation>('SELECT * FROM app.planning_operations WHERE workspace_id=$1 AND project_id=$2 AND planning_version>$3 ORDER BY planning_version LIMIT $4',
        [ref.workspaceId,ref.projectId,operationVersion,PLANNING_HISTORY_PAGE_SIZE])).rows;
      if(!rows.length)break;
      for(const row of rows) {historyBytes+=Buffer.byteLength(canonicalJson({mutation:row.signed_mutation,upgrades:row.upgrade_items}));
        if(historyBytes>PLANNING_HISTORY_MAX_BYTES||operations.length>=PLANNING_HISTORY_MAX_OPERATIONS)throw oversized();
        operations.push(row);operationVersion=row.planning_version;}
    }
    const history = operations.map((row) => row.signed_mutation);
    const auditIds = history.map((m) => m.body.audit.id), outcomeIds = history.flatMap((m) => m.body.outcome ? [m.body.outcome.id] : []);
    const audits = (await application.query<{ id: string; encrypted_envelope: ContentEnvelope }>('SELECT id,encrypted_envelope FROM app.audit_events WHERE workspace_id=$1 AND project_id=$2 AND id=ANY($3::uuid[]) ORDER BY id', [ref.workspaceId, ref.projectId, auditIds])).rows.map((row) => ({ id: row.id, envelope: row.encrypted_envelope }));
    const outcomes = (await application.query<{ id: string; encrypted_envelope: ContentEnvelope }>("SELECT record_id AS id,encrypted_envelope FROM app.record_versions WHERE workspace_id=$1 AND project_id=$2 AND record_type='update' AND record_revision=1 AND record_id=ANY($3::uuid[]) ORDER BY record_id", [ref.workspaceId, ref.projectId, outcomeIds])).rows.map((row) => ({ id: row.id, envelope: row.encrypted_envelope }));
    const core = (row: pg.QueryResultRow) => ({ workspaceId: row.workspace_id as string, id: row.id as string, revision: row.revision as string });
    const child = (row: pg.QueryResultRow) => ({ ...core(row), projectId: row.project_id as string });
    const graph = parse(planningGraph, { version: 2,
      project: { ...core(project), state: project.state, archived: project.archived, phaseLabel: project.phase_label, managerProfileId: project.manager_profile_id, teamId: project.team_id,
        reviewEnabled: project.review_enabled, reviewPolicyRevision: project.review_policy_revision },
      phases: rows.phase.map((row) => ({ ...child(row), state: row.state, archived: row.archived, displayOrder: row.display_order, leadProfileId: row.lead_profile_id })),
      milestones: rows.milestone.map((row) => ({ ...child(row), state: row.state, phaseId: row.phase_id, ownerProfileId: row.owner_profile_id })),
      tasks: rows.task.map((row) => ({ ...child(row), state: row.state, phaseId: row.phase_id, milestoneId: row.milestone_id, leadProfileId: row.lead_profile_id,
        assigneeIds: assignments.filter((a) => a.task_id === row.id).map((a) => a.member_id), teamId: row.team_id, contentRevision: row.content_revision,
        reviewerProfileId: row.reviewer_profile_id, submittedRevision: row.submitted_revision, submittedPolicyRevision: row.submitted_policy_revision,
        approvalOperationId: row.approval_operation_id })),
      blockers: rows.blocker.map((row) => ({ ...child(row), taskId: row.task_id, state: row.state, contentRevision: row.content_revision,
        responsibleProfileId: row.responsible_profile_id, createdBy: row.created_by, createdAt: (row.created_at as Date).toISOString(),
        resolvedBy: row.resolved_by, resolvedAt: row.resolved_at ? (row.resolved_at as Date).toISOString() : null })),
      snapshots: operations.flatMap((row) => row.closing_snapshot ? [row.closing_snapshot] : []), movements: operations.flatMap((row) => row.movements) });
    const records: PlanningRecord[] = [{ kind: 'project', id: project.id, envelope: parse(contentEnvelope, project.encrypted_envelope) },
      ...(['phase', 'milestone', 'task', 'blocker'] as const).flatMap((kind) => rows[kind].map((row) => ({ kind, id: row.id as string, envelope: parse(contentEnvelope, row.encrypted_envelope) })))];
    const head = (await application.query<{ planning_version: string; planning_head: string; graph_digest: string }>('SELECT * FROM app.project_planning_heads WHERE workspace_id=$1 AND project_id=$2', [ref.workspaceId, ref.projectId])).rows[0];
    if (head ? head.planning_version !== String(operations.length) || head.planning_head !== await digestObject(history.at(-1)) : operations.length !== 0) throw changed();
    const beforeVersion = head?.planning_version ?? '0', beforeHead = head?.planning_head ?? await digestObject(creation);
    const upgrades=operations.flatMap(row=>row.upgrade_items?[{operationId:row.operation_id,items:row.upgrade_items}]:[]);
    const loaded = { creation, graph, records, history, audits, outcomes, beforeVersion, beforeHead,upgrades };
    if (Buffer.byteLength(canonicalJson(loaded)) > PLANNING_HISTORY_MAX_BYTES) throw oversized();
    return loaded;
  }
  async #materials(control: pg.PoolClient, authority: Authority, security: SecurityHistoryState, projectId: string): Promise<PairingMaterial[]> {
    const device = security.devices[authority.principal.deviceId!], allowed = authority.scopes.filter((s) => s.scope === 'project' && s.scopeId === projectId || authority.profile.is_owner && s.scope === 'workspace' && s.mode === 'custody');
    if (!device) throw forbidden();
    const ids = new Set(device.scopes.filter((scope) => allowed.some((a) => a.scope === scope.scope && a.scopeId === scope.scopeId && a.keyEpoch === scope.keyEpoch)).flatMap((s) => s.manifests.map((m) => m.id)));
    if (authority.profile.is_owner && allowed.some((scope) => scope.mode === 'custody')) {
      ids.add(security.custodyManifest.id);
      const genesis = (await control.query<{ versioned_object: { body: { device: { id: string }; deviceEnvelopeId: string; custodyId: string } } }>(`SELECT o.versioned_object FROM security.workspaces w JOIN security.staged_objects o
        ON o.workspace_id=w.workspace_id AND o.object_id=w.genesis_object_id WHERE w.workspace_id=$1`, [security.workspaceId])).rows[0]?.versioned_object.body;
      if (genesis?.device.id === device.id && ids.has(genesis.custodyId)) ids.add(genesis.deviceEnvelopeId);
    }
    const rows = (await control.query<{ object_id: string; object_hash: string; object_kind: string; versioned_object: unknown }>('SELECT * FROM security.staged_objects WHERE workspace_id=$1 AND object_id=ANY($2::uuid[]) AND state=\'committed\' ORDER BY object_id', [security.workspaceId, [...ids]])).rows;
    if (rows.length !== ids.size) throw changed();
    return rows.filter((row) => authority.profile.is_owner || row.object_kind === 'key_envelope' &&
      (row.versioned_object as { header?: { recipientKind?: string; recipientId?: string } }).header?.recipientKind === 'device' &&
      (row.versioned_object as { header: { recipientId: string } }).header.recipientId === device.id)
      .map((row) => ({ id: row.object_id, digest: row.object_hash, kind: row.object_kind, value: row.versioned_object }));
  }
  async #context(application: pg.PoolClient, control: pg.PoolClient, authority: Authority, now: Date, ref: z.infer<typeof planningReference>, times?: Pick<PlanningBinding, 'issuedAt' | 'expiresAt'>): Promise<PlanningContext> {
    const loaded = await this.#load(application, control, ref), principal = authority.principal;
    const scope = authority.scopes.find((s) => s.scope === 'project' && s.scopeId === ref.projectId)!;
    const securityAt = await this.#security(control, principal), security = await securityAt(principal.securityVersion, principal.securityHead);
    const profile = security.profiles[principal.accountId], role = profile && security.roles[profile.projectRoles[ref.projectId]?.id ?? profile.role.id]; if (!role) throw forbidden();
    const workspace=(await control.query('SELECT write_schema,active_upgrade_id FROM security.workspaces WHERE workspace_id=$1',[ref.workspaceId])).rows[0];
    const modern=workspace?.write_schema===2||!!workspace?.active_upgrade_id;
    const binding = parse(planningBinding, { ...ref, version: modern?3:2,...(modern?{writeSchema:2}:{}), origin: this.#o.origin, accountId: principal.accountId, deviceId: principal.deviceId,
      credentialGeneration: principal.credentialGeneration, sessionGeneration: principal.sessionGeneration, keyGeneration: authority.device.key_generation,
      signingPublicKey: base64urlEncode(authority.device.signing_public_key), eligibleAssigneeIds: planningEligibleAssignees(security, ref.projectId, times?.issuedAt ?? now.toISOString()),
      eligibleReviewerIds: planningEligibleReviewers(security, ref.projectId, times?.issuedAt ?? now.toISOString()), permissionVersion: role.revision, permissions: scope.permissions, isOwner: authority.profile.is_owner,
      keyEpoch: scope.keyEpoch, securityVersion: principal.securityVersion, securityHead: principal.securityHead, dataGeneration: principal.dataGeneration,
      beforeVersion: loaded.beforeVersion, beforeHead: loaded.beforeHead, beforeGraphDigest: await planningGraphDigest(loaded.graph), before: planningRevisionSnapshot(loaded.graph),
      issuedAt: times?.issuedAt ?? now.toISOString(), expiresAt: times?.expiresAt ?? new Date(now.getTime() + 600000).toISOString() });
    const context = parse(planningContext, { binding, graph: loaded.graph, records: loaded.records, creation: loaded.creation, history: loaded.history,
      audits: loaded.audits, outcomes: loaded.outcomes,...(loaded.upgrades.length?{upgrades:loaded.upgrades}:{}), materials: await this.#materials(control, authority, security, ref.projectId) });
    if (Buffer.byteLength(canonicalJson(planningFrame(context))) > PLANNING_MAX_BYTES || Buffer.byteLength(canonicalJson(context)) > PLANNING_HISTORY_MAX_BYTES) throw oversized();
    try { return await verifyPlanningContext(context, securityAt); } catch { throw changed(); }
  }
  async context(cookie: string, csrf: string, input: unknown): Promise<PlanningContext> {
    const ref = parse(planningReference, input); return this.#with(ref, cookie, csrf, (a, c, authority, now) => this.#context(a, c, authority, now, ref));
  }
  async snapshot(cookie: string, csrf: string, input: unknown): Promise<PlanningContext> { return this.context(cookie, csrf, input); }
  async pagedContext(cookie:string,csrf:string,input:unknown) {return planningFrame(await this.context(cookie,csrf,input));}
  async operationsPage(cookie:string,csrf:string,input:unknown):Promise<PlanningOperationsPage> {
    const request=parse(planningOperationsRequest,input);
    return this.#with(request,cookie,csrf,async(application,control,authority)=>{
      const head=(await application.query<{planning_version:string;planning_head:string}>('SELECT planning_version,planning_head FROM app.project_planning_heads WHERE workspace_id=$1 AND project_id=$2',[request.workspaceId,request.projectId])).rows[0];
      const p=authority.principal,a=request.anchor;
      if(a.dataGeneration!==p.dataGeneration||a.securityVersion!==p.securityVersion||a.securityHead!==p.securityHead||
        a.version!==(head?.planning_version??'0')||head&&a.head!==head.planning_head||BigInt(request.afterVersion)>BigInt(a.version)||BigInt(a.version)>BigInt(PLANNING_HISTORY_MAX_OPERATIONS))throw changed();
      let previousHead:string;
      if(request.afterVersion==='0') {
        const creation=(await control.query<{versioned_object:unknown}>(`SELECT o.versioned_object FROM security.project_creations p JOIN security.staged_objects o
          ON o.workspace_id=p.workspace_id AND o.object_id=p.operation_id AND o.state='committed' WHERE p.workspace_id=$1 AND p.project_id=$2`,[request.workspaceId,request.projectId])).rows[0];
        if(!creation)throw changed();previousHead=await digestObject(creation.versioned_object);
      } else {
        const previous=(await application.query<Operation>('SELECT * FROM app.planning_operations WHERE workspace_id=$1 AND project_id=$2 AND planning_version=$3',[request.workspaceId,request.projectId,request.afterVersion])).rows[0];
        if(!previous)throw changed();previousHead=await digestObject(previous.signed_mutation);
      }
      if(!head&&a.head!==previousHead)throw changed();
      const rows=(await application.query<Operation>('SELECT * FROM app.planning_operations WHERE workspace_id=$1 AND project_id=$2 AND planning_version>$3 AND planning_version<=$4 ORDER BY planning_version LIMIT $5',
        [request.workspaceId,request.projectId,request.afterVersion,a.version,PLANNING_HISTORY_PAGE_SIZE])).rows;
      const result:PlanningOperationsPage={protocol:1,anchor:a,afterVersion:request.afterVersion,previousHead,nextVersion:request.afterVersion,nextHead:previousHead,complete:false,history:[],audits:[],outcomes:[],upgrades:[]};
      for(const row of rows) {
        const mutation=row.signed_mutation,audit=(await application.query<{id:string;encrypted_envelope:ContentEnvelope}>('SELECT id,encrypted_envelope FROM app.audit_events WHERE workspace_id=$1 AND project_id=$2 AND id=$3',[request.workspaceId,request.projectId,mutation.body.audit.id])).rows[0];
        const outcome=mutation.body.outcome?(await application.query<{id:string;encrypted_envelope:ContentEnvelope}>("SELECT record_id AS id,encrypted_envelope FROM app.record_versions WHERE workspace_id=$1 AND project_id=$2 AND record_type='update' AND record_revision=1 AND record_id=$3",[request.workspaceId,request.projectId,mutation.body.outcome.id])).rows[0]:null;
        if(!audit||mutation.body.outcome&&!outcome)throw changed();
        const candidate={...result,history:[...result.history,mutation],audits:[...result.audits,{id:audit.id,envelope:audit.encrypted_envelope}],
          outcomes:[...result.outcomes,...(outcome?[{id:outcome.id,envelope:outcome.encrypted_envelope}]:[])],upgrades:[...result.upgrades,...(row.upgrade_items?[{operationId:row.operation_id,items:row.upgrade_items}]:[])],
          nextVersion:row.planning_version,nextHead:await digestObject(mutation)};
        if(Buffer.byteLength(canonicalJson(candidate))>PLANNING_MAX_BYTES) {if(!result.history.length)throw oversized();break;}
        Object.assign(result,candidate);
      }
      result.complete=result.nextVersion===a.version;
      if(!result.complete&&!result.history.length)throw changed();
      return parse(planningOperationsPage,result);
    });
  }

  /** Collaboration reuses the same locked authority/graph without nesting pool locks. */
  async withCurrentContext<T>(cookie: string, csrf: string, input: unknown,
    action: (application: pg.PoolClient, context: PlanningContext, principal: SessionPrincipal, now: Date, securityAt: PlanningSecurityResolver) => Promise<T>, options: { write?:boolean;applyAccountBudget?:boolean } = {}): Promise<T> {
    const ref = parse(planningReference, input);
    return this.#with(ref, cookie, csrf, async (application, control, authority, now) =>
      action(application, await this.#context(application, control, authority, now, ref), authority.principal, now,
        await this.#security(control, authority.principal)),options.write??false,options.applyAccountBudget??false);
  }
  async #receipt(application: pg.PoolClient, ref: z.infer<typeof planningReference>, principal: SessionPrincipal, requestHash: string): Promise<PlanningReceipt | null> {
    const row = (await application.query<Operation>('SELECT * FROM app.planning_operations WHERE workspace_id=$1 AND operation_id=$2', [ref.workspaceId, ref.operationId])).rows[0];
    if (!row) return null;
    const receipt = parse(planningReceipt, row.receipt);
    if (row.project_id !== ref.projectId || row.data_generation !== principal.dataGeneration || row.request_digest !== requestHash ||
      receipt.requestHash !== requestHash || receipt.mutation.body.binding.accountId !== principal.accountId) throw changed();
    return receipt;
  }
  async status(cookie: string, csrf: string, input: unknown): Promise<PlanningView> {
    const request = parse(planningStatusRequest, input);
    return this.#with(request, cookie, csrf, async (a, _c, authority) => {
      if (request.dataGeneration !== authority.principal.dataGeneration) throw changed();
      const receipt = await this.#receipt(a, request, authority.principal, request.requestHash); return { state: receipt ? 'completed' : 'absent', receipt };
    });
  }
  async withAuthorizedHistory<T>(cookie: string, csrf: string, input: unknown, action: (c: pg.PoolClient, principal: SessionPrincipal) => Promise<T>): Promise<T> {
    const ref = parse(planningReference, input); return this.#with(ref, cookie, csrf, (_a, c, authority) => action(c, authority.principal));
  }
  async #designations(application: pg.PoolClient, context: PlanningContext, result: Awaited<ReturnType<typeof validatePlanningPayload>>['result'], now: Date): Promise<void> {
    const graph = result.state, ids = [ ...(result.changed.project && graph.project.managerProfileId && graph.project.managerProfileId !== context.graph.project.managerProfileId ? [graph.project.managerProfileId] : []),
      ...graph.phases.filter((r) => result.changed.phaseIds.includes(r.id)).flatMap((r) => r.leadProfileId && r.leadProfileId !== context.graph.phases.find((old) => old.id === r.id)?.leadProfileId ? [r.leadProfileId] : []),
      ...graph.milestones.filter((r) => result.changed.milestoneIds.includes(r.id)).flatMap((r) => r.ownerProfileId && r.ownerProfileId !== context.graph.milestones.find((old) => old.id === r.id)?.ownerProfileId ? [r.ownerProfileId] : []),
      ...graph.tasks.filter((r) => result.changed.taskIds.includes(r.id)).flatMap((r) => [...r.assigneeIds]),
      ...(graph.blockers ?? []).filter((r) => result.changed.blockerIds?.includes(r.id)).flatMap((r) => r.responsibleProfileId ? [r.responsibleProfileId] : []) ];
    if (ids.length) {
      const eligible = (await application.query<{ profile_id: string }>(`SELECT a.profile_id FROM app.project_access a JOIN app.profiles p ON p.workspace_id=a.workspace_id AND p.id=a.profile_id
        JOIN app.roles r ON r.workspace_id=a.workspace_id AND r.id=a.role_id WHERE a.workspace_id=$1 AND a.project_id=$2 AND a.profile_id=ANY($3::uuid[]) AND p.state='active' AND a.state='active'
        AND r.state='active' AND 'read_project'=ANY(a.permissions) AND (a.expires_at IS NULL OR a.expires_at>$4)`, [context.binding.workspaceId, context.binding.projectId, ids, now])).rows.map((r) => r.profile_id);
      if (ids.some((id) => !eligible.includes(id))) throw forbidden();
    }
    const reviewers = graph.tasks.filter((r) => result.changed.taskIds.includes(r.id) && r.reviewerProfileId &&
      r.reviewerProfileId !== context.graph.tasks.find((old) => old.id === r.id)?.reviewerProfileId).map((r) => r.reviewerProfileId!);
    if (reviewers.length) {
      const eligible = (await application.query<{ profile_id: string }>(`SELECT a.profile_id FROM app.project_access a JOIN app.profiles p ON p.workspace_id=a.workspace_id AND p.id=a.profile_id
        JOIN app.roles r ON r.workspace_id=a.workspace_id AND r.id=a.role_id WHERE a.workspace_id=$1 AND a.project_id=$2 AND a.profile_id=ANY($3::uuid[])
        AND p.state='active' AND a.state='active' AND r.state='active' AND 'read_project'=ANY(a.permissions)
        AND (p.is_owner OR 'approve_tasks'=ANY(a.permissions)) AND (a.expires_at IS NULL OR a.expires_at>$4)`,
      [context.binding.workspaceId, context.binding.projectId, reviewers, now])).rows.map((r) => r.profile_id);
      if (reviewers.some((id) => !eligible.includes(id))) throw forbidden();
    }
    const teamIds = [...new Set([...(result.changed.project && graph.project.teamId ? [graph.project.teamId] : []),
      ...graph.tasks.filter((r) => result.changed.taskIds.includes(r.id)).flatMap((r) => r.teamId ? [r.teamId] : [])])];
    if (teamIds.length && (await application.query('SELECT id FROM app.teams WHERE workspace_id=$1 AND id=ANY($2::uuid[])', [context.binding.workspaceId, teamIds])).rowCount !== teamIds.length) throw invalid();
  }
  async #version(application: pg.PoolClient, record: { kind: ContentEnvelope['header']['recordType']; id: string; envelope: ContentEnvelope }, workspaceId: string, projectId: string, prior = false,
    metadata?: { revision: string; actorId: string; operationId: string }): Promise<void> {
    const h = record.envelope.header;
    await application.query(`INSERT INTO app.record_versions(workspace_id,id,project_id,record_type,record_id,record_revision,actor_profile_id,operation_id,schema_version,key_epoch,encrypted_envelope)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ${prior ? 'ON CONFLICT(workspace_id,record_type,record_id,record_revision) DO NOTHING' : ''}`,
    [workspaceId, randomUUID(), projectId, record.kind, record.id, metadata?.revision ?? h.revision, metadata?.actorId ?? h.accountId,
      metadata?.operationId ?? h.operationId, h.schema, h.keyEpoch, record.envelope]);
  }
  async #persist(application: pg.PoolClient, payload: PlanningPayload, context: PlanningContext, result: Awaited<ReturnType<typeof validatePlanningPayload>>['result'], now: Date): Promise<PlanningReceipt> {
    const b = payload.mutation.body.binding, graph = result.state;
    const metadataRow = (state: PlanningState, record: PlanningRecord) => record.kind === 'project' ? state.project :
      record.kind === 'phase' ? state.phases.find((row) => row.id === record.id) : record.kind === 'milestone' ? state.milestones.find((row) => row.id === record.id) :
        record.kind === 'task' ? state.tasks.find((row) => row.id === record.id) : state.blockers?.find((row) => row.id === record.id);
    for (const record of payload.records) {
      const prior = context.records.find((r) => r.kind === record.kind && r.id === record.id), rowBefore = metadataRow(context.graph, record), rowAfter = metadataRow(graph, record);
      if (!rowAfter) throw invalid();
      if (prior && rowBefore) await this.#version(application, prior, b.workspaceId, b.projectId, true,
        { revision: rowBefore.revision, actorId: prior.envelope.header.accountId, operationId: prior.envelope.header.operationId });
      const h = record.envelope.header;
      if (!prior && record.kind !== 'project') {
        const table = record.kind === 'phase' ? 'project_phases' : record.kind === 'milestone' ? 'milestones' : record.kind === 'task' ? 'tasks' : 'blockers';
        if ((await application.query(`SELECT 1 FROM app.${table} WHERE workspace_id=$1 AND id=$2`, [b.workspaceId, record.id])).rowCount) throw invalid();
      }
      if (record.kind === 'project') {
        const row = graph.project;
        await application.query(`UPDATE app.projects SET state=$3,archived=$4,phase_label=$5,manager_profile_id=$6,team_id=$7,revision=$8,key_epoch=$9,encrypted_envelope=$10,updated_at=$11,
          review_enabled=$12,review_policy_revision=$13 WHERE workspace_id=$1 AND id=$2`,
          [b.workspaceId, record.id, row.state, row.archived, row.phaseLabel, row.managerProfileId, row.teamId, row.revision, h.keyEpoch, record.envelope, now, row.reviewEnabled ?? false, row.reviewPolicyRevision ?? '1']);
      } else if (record.kind === 'phase') {
        const row = graph.phases.find((r) => r.id === record.id)!;
        const persisted = await application.query(`INSERT INTO app.project_phases(workspace_id,id,project_id,state,archived,display_order,lead_profile_id,revision,key_epoch,encrypted_envelope,updated_at)
          VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT(workspace_id,id) DO UPDATE SET state=EXCLUDED.state,archived=EXCLUDED.archived,display_order=EXCLUDED.display_order,
          lead_profile_id=EXCLUDED.lead_profile_id,revision=EXCLUDED.revision,key_epoch=EXCLUDED.key_epoch,encrypted_envelope=EXCLUDED.encrypted_envelope,updated_at=EXCLUDED.updated_at WHERE app.project_phases.project_id=EXCLUDED.project_id RETURNING id`,
        [b.workspaceId, row.id, b.projectId, row.state, row.archived, row.displayOrder, row.leadProfileId, row.revision, h.keyEpoch, record.envelope, now]);
        if (!persisted.rowCount) throw invalid();
      } else if (record.kind === 'milestone') {
        const row = graph.milestones.find((r) => r.id === record.id)!;
        const persisted = await application.query(`INSERT INTO app.milestones(workspace_id,id,project_id,phase_id,owner_profile_id,state,revision,key_epoch,encrypted_envelope,updated_at)
          VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT(workspace_id,id) DO UPDATE SET phase_id=EXCLUDED.phase_id,owner_profile_id=EXCLUDED.owner_profile_id,state=EXCLUDED.state,
          revision=EXCLUDED.revision,key_epoch=EXCLUDED.key_epoch,encrypted_envelope=EXCLUDED.encrypted_envelope,updated_at=EXCLUDED.updated_at WHERE app.milestones.project_id=EXCLUDED.project_id RETURNING id`,
        [b.workspaceId, row.id, b.projectId, row.phaseId, row.ownerProfileId, row.state, row.revision, h.keyEpoch, record.envelope, now]);
        if (!persisted.rowCount) throw invalid();
      } else if (record.kind === 'task') {
        const row = graph.tasks.find((r) => r.id === record.id)!;
        if (!prior) {
          await application.query(`INSERT INTO app.tasks(workspace_id,id,project_id,phase_id,milestone_id,lead_profile_id,state,revision,key_epoch,encrypted_envelope,created_at,updated_at,
            team_id,content_revision,reviewer_profile_id,submitted_revision,submitted_policy_revision,approval_operation_id)
            VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$11,$12,$13,$14,$15,$16,$17)`,
          [b.workspaceId,row.id,b.projectId,row.phaseId,row.milestoneId,row.leadProfileId,row.state,row.revision,h.keyEpoch,record.envelope,now,
            row.teamId ?? null,row.contentRevision ?? row.revision,row.reviewerProfileId ?? null,row.submittedRevision ?? null,row.submittedPolicyRevision ?? null,row.approvalOperationId ?? null]);
        } else await application.query(`UPDATE app.tasks SET phase_id=$3,milestone_id=$4,state=$5,revision=$6,key_epoch=$7,encrypted_envelope=$8,updated_at=$9,
          lead_profile_id=$11,team_id=$12,content_revision=$13,reviewer_profile_id=$14,submitted_revision=$15,submitted_policy_revision=$16,approval_operation_id=$17
          WHERE workspace_id=$1 AND id=$2 AND project_id=$10`,
        [b.workspaceId,row.id,row.phaseId,row.milestoneId,row.state,row.revision,h.keyEpoch,record.envelope,now,b.projectId,row.leadProfileId,
          row.teamId ?? null,row.contentRevision ?? row.revision,row.reviewerProfileId ?? null,row.submittedRevision ?? null,row.submittedPolicyRevision ?? null,row.approvalOperationId ?? null]);
        // Preserve original assigned_by/assigned_at for every surviving assignee.
        await application.query('DELETE FROM app.task_assignments WHERE workspace_id=$1 AND project_id=$2 AND task_id=$3 AND NOT(member_id=ANY($4::uuid[]))',
          [b.workspaceId,b.projectId,row.id,row.assigneeIds]);
        const previous = context.graph.tasks.find((task) => task.id === row.id)?.assigneeIds ?? [];
        for (const member of row.assigneeIds.filter((id) => !previous.includes(id))) await application.query(`INSERT INTO app.task_assignments(workspace_id,task_id,project_id,member_id,assigned_by,assigned_at)
          VALUES($1,$2,$3,$4,$5,$6)`, [b.workspaceId,row.id,b.projectId,member,b.accountId,now]);
      } else {
        const row = graph.blockers?.find((blocker) => blocker.id === record.id); if (!row) throw invalid();
        const persisted = await application.query(`INSERT INTO app.blockers(workspace_id,id,project_id,task_id,responsible_profile_id,created_by,created_at,resolved_by,resolved_at,state,
          revision,content_revision,key_epoch,encrypted_envelope,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
          ON CONFLICT(workspace_id,id) DO UPDATE SET responsible_profile_id=EXCLUDED.responsible_profile_id,resolved_by=EXCLUDED.resolved_by,resolved_at=EXCLUDED.resolved_at,
            state=EXCLUDED.state,revision=EXCLUDED.revision,content_revision=EXCLUDED.content_revision,key_epoch=EXCLUDED.key_epoch,encrypted_envelope=EXCLUDED.encrypted_envelope,updated_at=EXCLUDED.updated_at
          WHERE app.blockers.project_id=EXCLUDED.project_id AND app.blockers.task_id=EXCLUDED.task_id RETURNING id`,
        [b.workspaceId,row.id,b.projectId,row.taskId,row.responsibleProfileId,row.createdBy,row.createdAt,row.resolvedBy,row.resolvedAt,row.state,
          row.revision,row.contentRevision,h.keyEpoch,record.envelope,now]);
        if (!persisted.rowCount) throw invalid();
      }
      const table=record.kind==='project'?'projects':record.kind==='phase'?'project_phases':record.kind==='milestone'?'milestones':record.kind==='task'?'tasks':'blockers';
      await application.query(`UPDATE app.${table} SET schema_version=$3 WHERE workspace_id=$1 AND id=$2`,[b.workspaceId,record.id,h.schema]);
      await this.#version(application, record, b.workspaceId, b.projectId, false, { revision: rowAfter.revision, actorId: b.accountId, operationId: b.operationId });
    }
    if (payload.outcome) {
      const command = payload.mutation.body.command;
      const phaseId = 'phaseId' in command ? command.phaseId : 'milestoneId' in command ? graph.milestones.find((m) => m.id === command.milestoneId)?.phaseId ?? null : null;
      await application.query(`INSERT INTO app.updates(workspace_id,id,project_id,phase_id,author_profile_id,revision,key_epoch,encrypted_envelope,created_at,updated_at,schema_version)
        VALUES($1,$2,$3,$4,$5,1,$6,$7,$8,$8,$9)`, [b.workspaceId, payload.outcome.id, b.projectId, phaseId, b.accountId, b.keyEpoch, payload.outcome.envelope, now,payload.outcome.envelope.header.schema]);
      await this.#version(application, { kind: 'update', ...payload.outcome }, b.workspaceId, b.projectId);
    }
    await application.query(`INSERT INTO app.audit_events(workspace_id,id,project_id,actor_profile_id,operation_id,action,record_type,record_id,key_epoch,encrypted_envelope,created_at,schema_version)
      VALUES($1,$2,$3,$4,$5,$6,'project',$3,$7,$8,$9,$10)`, [b.workspaceId, payload.audit.id, b.projectId, b.accountId, b.operationId, `planning.${payload.mutation.body.command.action}`, b.keyEpoch, payload.audit.envelope, now,payload.audit.envelope.header.schema]);
    const requestHash = await digestObject(payload), head = await digestObject(payload.mutation), body = payload.mutation.body;
    const receipt = parse(planningReceipt, { version: 1, workspaceId: b.workspaceId, projectId: b.projectId, operationId: b.operationId, dataGeneration: b.dataGeneration,
      requestHash, planningVersion: body.nextVersion, planningHead: head, graphDigest: body.afterGraphDigest, committedAt: now.toISOString(), mutation: payload.mutation });
    await application.query(`INSERT INTO app.planning_operations(workspace_id,project_id,operation_id,data_generation,planning_version,request_digest,signed_mutation,closing_snapshot,movements,receipt,created_at,upgrade_items)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, [b.workspaceId, b.projectId, b.operationId, b.dataGeneration, body.nextVersion, requestHash, payload.mutation,
      result.snapshot ?? null, JSON.stringify(graph.movements.slice(context.graph.movements.length)), receipt, now,payload.upgradeItems?JSON.stringify(payload.upgradeItems):null]);
    await application.query(`INSERT INTO app.project_planning_heads(workspace_id,project_id,planning_version,planning_head,graph_digest,updated_at) VALUES($1,$2,$3,$4,$5,$6)
      ON CONFLICT(workspace_id,project_id) DO UPDATE SET planning_version=EXCLUDED.planning_version,planning_head=EXCLUDED.planning_head,graph_digest=EXCLUDED.graph_digest,updated_at=EXCLUDED.updated_at`,
    [b.workspaceId, b.projectId, body.nextVersion, head, body.afterGraphDigest, now]);
    await application.query(`INSERT INTO app.operation_receipts(workspace_id,id,data_generation,operation_id,actor_profile_id,project_id,action,request_digest,encrypted_envelope,created_at)
      VALUES($1,$2,$3,$4,$5,$6,'planning.change',$7,$8,$9)`, [b.workspaceId, randomUUID(), b.dataGeneration, b.operationId, b.accountId, b.projectId, requestHash, payload.audit.envelope, now]);
    const outboxId=randomUUID();
    await application.query(`INSERT INTO app.outbox(workspace_id,id,data_generation,operation_id,project_id,event_type,deduplication_key,encrypted_envelope,created_at,updated_at)
      VALUES($1,$2,$3,$4,$5,'planning.changed',$6,$7,$8,$8)`, [b.workspaceId, outboxId, b.dataGeneration, b.operationId, b.projectId, `planning:${b.operationId}`, payload.audit.envelope, now]);
    await enqueueNotificationJob(application,{workspaceId:b.workspaceId,outboxId,dataGeneration:b.dataGeneration,operationId:b.operationId,
      events:planningNotificationEvents(context.graph,result.state,b.accountId)},now);
    return receipt;
  }
  async save(cookie: string, csrf: string, input: unknown): Promise<PlanningView> {
    const payload = parse(planningPayload, input), binding = payload.mutation.body.binding;
    const view = await this.#with(binding, cookie, csrf, async (application, control, authority, now): Promise<PlanningView> => {
      if (binding.dataGeneration !== authority.principal.dataGeneration) throw changed();
      const receipt = await this.#receipt(application, binding, authority.principal, await digestObject(payload));
      if (receipt) return { state: 'completed', receipt };
      const body=payload.mutation.body;
      const upgrade=body.command.action==='upgrade_content'&&'upgrade'in body?
        await assertCurrentUpgradeBatch(this.#o.databases,application,authority.principal,body.upgrade,payload.upgradeItems,now):null;
      if(!upgrade)await assertAuthoritativeContentWrite(control,binding.workspaceId,[...payload.records.map(r=>r.envelope.header.schema),payload.audit.envelope.header.schema,...(payload.outcome?[payload.outcome.envelope.header.schema]:[])]);
      if (Date.parse(binding.expiresAt) <= now.getTime() || Date.parse(binding.issuedAt) > now.getTime() + 30000) throw changed();
      const context = await this.#context(application, control, authority, now, { workspaceId: binding.workspaceId, projectId: binding.projectId, operationId: binding.operationId }, { issuedAt: binding.issuedAt, expiresAt: binding.expiresAt });
      if (!same(context.binding, binding)) throw changed();
      let validated: Awaited<ReturnType<typeof validatePlanningPayload>>;
      try { validated = await validatePlanningPayload(payload, binding, context.graph, context.records); }
      catch (error) { if (error instanceof PlanningError) throw error; throw invalid(); }
      await assertPlanningFileEvidence(application,context,payload,await this.#security(control,authority.principal));
      if (validated.result.snapshot) {
        const stamp = 'closingSettings' in payload.mutation.body ? payload.mutation.body.closingSettings : undefined;
        if (!stamp) throw changed();
        const settings = await readReportingSettings(application, control, authority.principal);
        if (stamp.workspaceId !== binding.workspaceId || stamp.revision !== settings.revision || stamp.head !== settings.head ||
          stamp.initialDigest !== await digestObject(settings.initial) || settings.timezone !== null && stamp.timezone !== settings.timezone) throw changed();
      }
      if (context.history.length >= PLANNING_HISTORY_MAX_OPERATIONS || validated.result.state.phases.length + validated.result.state.milestones.length + validated.result.state.tasks.length + (validated.result.state.blockers?.length ?? 0) + 1 > PLANNING_MAX_RECORDS) throw oversized();
      const nextRecords = new Map(context.records.map((record) => [`${record.kind}:${record.id}`, record]));
      for (const record of payload.records) nextRecords.set(`${record.kind}:${record.id}`, record);
      if (Buffer.byteLength(canonicalJson(planningFrame({...context,graph:validated.result.state,records:[...nextRecords.values()]})))>PLANNING_MAX_BYTES)throw oversized();
      if (Buffer.byteLength(canonicalJson({ ...context, graph: validated.result.state, records: [...nextRecords.values()], history: [...context.history, payload.mutation],
        audits: [...context.audits, payload.audit], outcomes: [...context.outcomes, ...(payload.outcome ? [payload.outcome] : [])] })) > PLANNING_HISTORY_MAX_BYTES) throw oversized();
      if(!upgrade)await this.#designations(application, context, validated.result, now);
      const outcome = await this.#persist(application, payload, context, validated.result, now);
      if(upgrade)await recordUpgradeBatch(application,authority.principal,binding.operationId,payload,upgrade.proof,upgrade.items,now);
      await this.#o.hooks?.beforeCommit?.(); return { state: 'completed', receipt: outcome };
    });
    await this.#o.hooks?.afterCommit?.(); return view;
  }
}
