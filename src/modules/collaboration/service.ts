import { planningWireValue } from '../../shared/planning-api.js';
import { randomUUID } from 'node:crypto';
import type pg from 'pg';
import { z } from 'zod';
import type { Databases } from '../../db.js';
import { assertAuthoritativeContentWrite,tenantTransaction } from '../../persistence.js';
import { assertCurrentUpgradeBatch,recordUpgradeBatch } from '../upgrades/ledger.js';
import { AppError } from '../../errors.js';
import { canonicalJson, digestObject } from '../../shared/crypto.js';
import { collaborationBindingFromPlanning, collaborationContextRequest, collaborationHistoryRequest, collaborationListRequest,
  collaborationPayload, collaborationReceipt, collaborationReference, collaborationStatusRequest, assertCollaborationCurrentBinding,
  validateCollaborationPayload, verifyCollaborationEntry, CollaborationError, COLLABORATION_MAX_PAGE_BYTES,
  type CollaborationContext, type CollaborationEntry, type CollaborationHistory, type CollaborationPage, type CollaborationPayload,
  type CollaborationReceipt, type CollaborationView, type VerifiedCollaborationEntry } from '../../shared/collaboration.js';
import type { PlanningContext, PlanningSecurityResolver } from '../../shared/planning-api.js';
import type { SessionPrincipal, SessionService } from '../identity/sessions.js';
import type { ServiceSecrets } from '../identity/secrets.js';
import { PlanningService } from '../work/planning.js';
import { enqueueNotificationJob, type NotificationEventInput } from '../notifications/delivery.js';

interface Options { databases: Databases; sessions: SessionService; secrets: ServiceSecrets; origin: string; planning?: PlanningService;
  requestBudget?: (scope: { workspaceId: string; accountId: string }) => Promise<void>;
  hooks?: { beforeCommit?: () => Promise<void>; afterCommit?: () => Promise<void> } }
interface OperationRow { payload: CollaborationPayload; receipt: CollaborationReceipt; request_digest: string; data_generation: string; project_id: string; entry_revision: string }
const invalid = () => new AppError('COLLABORATION_INVALID', 'Invalid encrypted collaboration operation', 400);
const changed = () => new AppError('COLLABORATION_CHANGED', 'The entry or access changed; refresh before continuing', 409);
const missing = () => new AppError('COLLABORATION_NOT_FOUND', 'Entry not available', 404);
const unavailable = () => new AppError('COLLABORATION_UNAVAILABLE', 'Collaboration is temporarily unavailable; retain the encrypted draft', 503);
const oversized = () => new AppError('COLLABORATION_TOO_LARGE', 'This collaboration feed exceeds the supported read limit', 413);
const same = (a: unknown, b: unknown) => canonicalJson(a) === canonicalJson(b);
function parse<T>(schema: z.ZodType<T>, value: unknown): T { const result = schema.safeParse(value); if (!result.success) throw invalid(); return result.data; }
const reference = (value: { workspaceId: string; projectId: string; operationId: string }) => ({ workspaceId: value.workspaceId, projectId: value.projectId, operationId: value.operationId });

/** Entry-local immutable operations share the planning fence, never its revision CAS. */
export class CollaborationService {
  readonly #planning: PlanningService;
  constructor(readonly options: Options) { this.#planning = options.planning ?? new PlanningService({ databases:options.databases,sessions:options.sessions,secrets:options.secrets,origin:options.origin }); }
  async #with<T>(cookie: string, csrf: string, ref: z.infer<typeof collaborationReference>,
    action: (application: pg.PoolClient, planning: PlanningContext, principal: SessionPrincipal, now: Date, securityAt: PlanningSecurityResolver) => Promise<T>): Promise<T> {
    try {
      return await this.#planning.withCurrentContext(cookie, csrf, ref, async (application, planning, principal, now, securityAt) => {
        await this.options.requestBudget?.({ workspaceId: principal.workspaceId, accountId: principal.accountId });
        try { return await action(application, planning, principal, now, securityAt); }
        catch (error) {
          if (error instanceof CollaborationError) throw new AppError(`COLLABORATION_${error.code.toUpperCase()}`, 'Collaboration operation is not permitted in the current state', error.code === 'permission_denied' ? 403 : 409);
          if (error instanceof AppError) throw error;
          throw unavailable();
        }
      });
    } catch (error) {
      if (error instanceof AppError) throw error;
      if (error instanceof CollaborationError) throw new AppError(`COLLABORATION_${error.code.toUpperCase()}`, 'Collaboration operation is not permitted in the current state', error.code === 'permission_denied' ? 403 : 409);
      throw unavailable();
    }
  }
  async #entry(application: pg.PoolClient, planning: PlanningContext, kind: 'comment' | 'update', entryId: string,
    securityAt: PlanningSecurityResolver): Promise<{ entry: CollaborationEntry; verified: VerifiedCollaborationEntry } | null> {
    const table = kind === 'comment' ? 'comments' : 'updates', b = planning.binding;
    const row = (await application.query(`SELECT * FROM app.${table} WHERE workspace_id=$1 AND project_id=$2 AND id=$3`, [b.workspaceId,b.projectId,entryId])).rows[0];
    if (!row) return null;
    const operations = (await application.query<OperationRow>('SELECT * FROM app.collaboration_operations WHERE workspace_id=$1 AND project_id=$2 AND entry_kind=$3 AND entry_id=$4 ORDER BY entry_revision',
      [b.workspaceId,b.projectId,kind,entryId])).rows;
    const post = operations.find((operation) => operation.entry_revision === '1'), moderation = operations.find((operation) => operation.entry_revision === '2' && operation.payload.mutation.body.purpose==='ukda.collaboration.v1');
    const events=operations.filter(operation=>operation!==post&&operation!==moderation).map(operation=>operation.payload);
    const origin = post ? { kind:'post' as const,payload:post.payload } : (() => {
      const mutation = kind === 'update' ? planning.history.find((operation) => operation.body.outcome?.id === entryId) : undefined;
      if (!mutation) throw changed(); return { kind:'planning' as const,operationId:mutation.body.binding.operationId,entryId };
    })();
    const entry: CollaborationEntry = { origin,moderation:moderation?.payload ?? null,...(events.length?{events}:{}) };
    let verified: VerifiedCollaborationEntry;
    try { verified = await verifyCollaborationEntry(entry,planning,securityAt); } catch { throw changed(); }
    if (verified.workspaceId !== b.workspaceId || verified.projectId !== b.projectId || verified.kind !== kind || verified.entryId !== entryId ||
      verified.revision !== row.revision || verified.hidden !== row.hidden || verified.authorId !== row.author_profile_id ||
      verified.moderatedBy !== row.moderated_by || verified.moderatedAt !== (row.moderated_at ? (row.moderated_at as Date).toISOString() : null) ||
      !same(verified.current,row.encrypted_envelope) || (kind === 'comment' ? verified.taskId !== row.task_id : verified.phaseId !== row.phase_id)) throw changed();
    return { entry,verified };
  }
  async context(cookie: string, csrf: string, input: unknown): Promise<CollaborationContext> {
    const request = parse(collaborationContextRequest,input);
    return this.#with(cookie,csrf,reference(request),async (application,planning,_principal,_now,securityAt) => ({
      planning,binding:collaborationBindingFromPlanning(planning.binding,request),entry:(await this.#entry(application,planning,request.kind,request.entryId,securityAt))?.entry ?? null,
    }));
  }
  async history(cookie: string, csrf: string, input: unknown): Promise<CollaborationHistory> {
    const request = parse(collaborationHistoryRequest,input);
    return this.#with(cookie,csrf,reference(request),async (application,planning,_principal,_now,securityAt) => {
      const found = await this.#entry(application,planning,request.kind,request.entryId,securityAt); if (!found) throw missing();
      return { planning,entry:found.entry };
    });
  }
  async #receipt(application: pg.PoolClient, principal: SessionPrincipal, ref: z.infer<typeof collaborationReference>, requestHash: string): Promise<CollaborationReceipt | null> {
    const row = (await application.query<OperationRow>('SELECT * FROM app.collaboration_operations WHERE workspace_id=$1 AND operation_id=$2',[ref.workspaceId,ref.operationId])).rows[0];
    if (!row) return null;
    const receipt = parse(collaborationReceipt,row.receipt);
    if (row.project_id !== ref.projectId || row.data_generation !== principal.dataGeneration || row.request_digest !== requestHash ||
      receipt.requestHash !== requestHash || receipt.mutation.body.binding.accountId !== principal.accountId) throw changed();
    return receipt;
  }
  async status(cookie: string, csrf: string, input: unknown): Promise<CollaborationView> {
    const request = parse(collaborationStatusRequest,input);
    return this.#with(cookie,csrf,reference(request),async (application,_planning,principal) => {
      if (request.dataGeneration !== principal.dataGeneration) throw changed();
      const receipt = await this.#receipt(application,principal,request,request.requestHash); return { state:receipt ? 'completed' : 'absent',receipt };
    });
  }
  async save(cookie: string, csrf: string, input: unknown): Promise<CollaborationView> {
    const payload = parse(collaborationPayload,input), binding = payload.mutation.body.binding, requestHash = await digestObject(payload);
    const view = await this.#with(cookie,csrf,reference(binding),async (application,planning,principal,now,securityAt): Promise<CollaborationView> => {
      if (binding.dataGeneration !== principal.dataGeneration) throw changed();
      const existingReceipt = await this.#receipt(application,principal,binding,requestHash);
      if (existingReceipt) return { state:'completed',receipt:existingReceipt };
      const upgrade=payload.mutation.body.command.action==='upgrade_content'&&payload.mutation.body.purpose==='ukda.collaboration.v2'
        ? await assertCurrentUpgradeBatch(this.options.databases,application,principal,payload.mutation.body.upgrade,payload.upgradeItems,now):null;
      if(!upgrade)await tenantTransaction(this.options.databases.control,binding.workspaceId,undefined,control=>
        assertAuthoritativeContentWrite(control,binding.workspaceId,[payload.audit.envelope.header.schema,...(payload.content?[payload.content.header.schema]:[])]));
      try { await assertCollaborationCurrentBinding(binding,planning,now); } catch { throw changed(); }
      const found = await this.#entry(application,planning,binding.kind,binding.entryId,securityAt);
      let validated: Awaited<ReturnType<typeof validateCollaborationPayload>>;
      try { validated = await validateCollaborationPayload(payload,binding,planning.graph,found?.verified ?? null); }
      catch (error) { if (error instanceof CollaborationError) throw error; throw invalid(); }
      const result = validated.result, command = payload.mutation.body.command, posting = command.action === 'post_comment' || command.action === 'post_update';
      const original = posting || upgrade ? payload.content! : found!.verified.current;
      if (posting) {
        const collision = (await application.query('SELECT 1 FROM app.comments WHERE workspace_id=$1 AND id=$2 UNION ALL SELECT 1 FROM app.updates WHERE workspace_id=$1 AND id=$2',[binding.workspaceId,binding.entryId])).rowCount;
        if (collision) throw changed();
        const table = binding.kind === 'comment' ? 'comments' : 'updates', parent = binding.kind === 'comment' ? 'task_id' : 'phase_id';
        await application.query(`INSERT INTO app.${table}(workspace_id,id,project_id,${parent},author_profile_id,revision,key_epoch,encrypted_envelope,schema_version,created_at,updated_at)
          VALUES($1,$2,$3,$4,$5,1,$6,$7,$10,$8,$9)`,[binding.workspaceId,binding.entryId,binding.projectId,binding.kind === 'comment' ? result.taskId : result.phaseId,binding.accountId,binding.keyEpoch,original,result.createdAt,now,original.header.schema]);
      } else {
        const table = binding.kind === 'comment' ? 'comments' : 'updates';
        const updated = await application.query(`UPDATE app.${table} SET hidden=$4,moderated_by=$5,moderated_at=$6,revision=$7,updated_at=$8,
          encrypted_envelope=$10,key_epoch=$11,schema_version=$12 WHERE workspace_id=$1 AND project_id=$2 AND id=$3 AND revision=$9`,
          [binding.workspaceId,binding.projectId,binding.entryId,result.hidden,result.moderatedBy,result.moderatedAt,result.revision,now,
            found!.verified.revision,original,original.header.keyEpoch,original.header.schema]);
        if (updated.rowCount !== 1) throw changed();
      }
      await application.query(`INSERT INTO app.record_versions(workspace_id,id,project_id,record_type,record_id,record_revision,actor_profile_id,operation_id,key_epoch,encrypted_envelope,created_at,schema_version)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,[binding.workspaceId,randomUUID(),binding.projectId,binding.kind,binding.entryId,result.revision,binding.accountId,binding.operationId,original.header.keyEpoch,original,now,original.header.schema]);
      await application.query(`INSERT INTO app.audit_events(workspace_id,id,project_id,actor_profile_id,operation_id,action,record_type,record_id,key_epoch,encrypted_envelope,created_at,schema_version)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,[binding.workspaceId,payload.audit.id,binding.projectId,binding.accountId,binding.operationId,`collaboration.${command.action}`,binding.kind,binding.entryId,binding.keyEpoch,payload.audit.envelope,now,payload.audit.envelope.header.schema]);
      const receipt = parse(collaborationReceipt,{ version:1,workspaceId:binding.workspaceId,projectId:binding.projectId,operationId:binding.operationId,
        entryId:binding.entryId,kind:binding.kind,revision:result.revision,head:result.head,dataGeneration:binding.dataGeneration,requestHash,committedAt:now.toISOString(),mutation:payload.mutation });
      await application.query(`INSERT INTO app.collaboration_operations(workspace_id,project_id,operation_id,entry_kind,entry_id,entry_revision,data_generation,request_digest,payload,receipt,created_at)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,[binding.workspaceId,binding.projectId,binding.operationId,binding.kind,binding.entryId,result.revision,binding.dataGeneration,requestHash,payload,receipt,now]);
      await application.query(`INSERT INTO app.operation_receipts(workspace_id,id,data_generation,operation_id,actor_profile_id,project_id,action,request_digest,encrypted_envelope,created_at)
        VALUES($1,$2,$3,$4,$5,$6,'collaboration.change',$7,$8,$9)`,[binding.workspaceId,randomUUID(),binding.dataGeneration,binding.operationId,binding.accountId,binding.projectId,requestHash,{ receipt },now]);
      const outboxId = randomUUID();
      await application.query(`INSERT INTO app.outbox(workspace_id,id,data_generation,operation_id,project_id,event_type,deduplication_key,encrypted_envelope,created_at,updated_at)
        VALUES($1,$2,$3,$4,$5,'collaboration.changed',$6,$7,$8,$8)`,[binding.workspaceId,outboxId,binding.dataGeneration,binding.operationId,binding.projectId,`collaboration:${binding.operationId}`,payload.audit.envelope,now]);
      const events: NotificationEventInput[] = command.action === 'post_comment' ? [{ eventType:'task.comment',recordId:binding.entryId,actorId:binding.accountId,
        recipientIds:[...planning.graph.tasks.find((task) => task.id === command.taskId)!.assigneeIds] }] : [];
      await enqueueNotificationJob(application,{ workspaceId:binding.workspaceId,outboxId,dataGeneration:binding.dataGeneration,operationId:binding.operationId,events },now);
      if(upgrade)await recordUpgradeBatch(application,principal,binding.operationId,payload,upgrade.proof,upgrade.items,now);
      await this.options.hooks?.beforeCommit?.(); return { state:'completed',receipt };
    });
    await this.options.hooks?.afterCommit?.(); return view;
  }
  async list(cookie: string, csrf: string, input: unknown): Promise<CollaborationPage> {
    const request = parse(collaborationListRequest,input);
    return this.#with(cookie,csrf,{ workspaceId:request.workspaceId,projectId:request.projectId,operationId:randomUUID() },async (application,planning,_principal,_now,securityAt) => {
      if (request.taskId && !planning.graph.tasks.some((task) => task.id === request.taskId) || request.phaseId && !planning.graph.phases.some((phase) => phase.id === request.phaseId)) throw missing();
      const table = request.kind === 'comment' ? 'comments' : 'updates', parent = request.kind === 'comment' ? 'task_id' : 'phase_id', filter = request.taskId ?? request.phaseId ?? null;
      const rows = (await application.query<{ id:string;revision:string }>(`SELECT id,revision FROM app.${table} WHERE workspace_id=$1 AND project_id=$2 AND ($4::boolean OR hidden=false)
        AND ($3::uuid IS NULL OR ${parent}=$3) ORDER BY id LIMIT 10001`,[request.workspaceId,request.projectId,filter,request.includeHidden === true])).rows;
      if (rows.length > 10000) throw oversized();
      const anchor = await digestObject({ workspaceId:request.workspaceId,projectId:request.projectId,kind:request.kind,filter,
        ...(request.includeHidden ? {includeHidden:true} : {}),dataGeneration:planning.binding.dataGeneration,securityHead:planning.binding.securityHead,rows });
      if (request.anchor && request.anchor !== anchor || request.after && !rows.some((row) => row.id === request.after)) throw changed();
      const remaining = request.after ? rows.filter((row) => row.id > request.after!) : rows, selected = remaining.slice(0,request.limit), entries: CollaborationEntry[] = [];
      for (const row of selected) { const value = await this.#entry(application,planning,request.kind,row.id,securityAt); if (!value || value.verified.hidden && !request.includeHidden) throw changed(); entries.push(value.entry); }
      const page: CollaborationPage = { planning,entries,anchor,nextCursor:remaining.length > selected.length ? selected.at(-1)!.id : null,complete:remaining.length <= selected.length };
      if (Buffer.byteLength(canonicalJson(planningWireValue(page))) > COLLABORATION_MAX_PAGE_BYTES) throw oversized(); return page;
    });
  }
}
