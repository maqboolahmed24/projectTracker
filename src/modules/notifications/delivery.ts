import { createHash, randomUUID } from 'node:crypto';
import type pg from 'pg';
import { z } from 'zod';
import type { Databases } from '../../db.js';
import { AppError } from '../../errors.js';
import { tenantTransaction } from '../../persistence.js';
import { identifier, positiveCounter } from '../../shared/contracts.js';
import type { PlanningState } from '../../shared/planning.js';
import { deletionElapsed } from '../lifecycle/deadline.js';

const notificationEvent = z.strictObject({ eventType: z.enum(['task.assignment','task.status','task.comment','review.requested']),
  recordId: identifier, actorId: identifier, recipientIds: z.array(identifier).max(2000) });
export type NotificationEventInput = z.infer<typeof notificationEvent>;
const descriptor = notificationEvent.extend({ eventId: identifier });
export const notificationJob = z.strictObject({ workspaceId: identifier, outboxId: identifier, dataGeneration: positiveCounter });
function eventId(workspaceId: string, operationId: string, eventType: string, recordId: string): string {
  const bytes=createHash('sha256').update(JSON.stringify(['ukda.notification.v1',workspaceId,operationId,eventType,recordId])).digest().subarray(0,16);
  bytes[6]=(bytes[6]!&15)|128; bytes[8]=(bytes[8]!&63)|128;
  const hex=bytes.toString('hex'); return `${hex.slice(0,8)}-${hex.slice(8,12)}-${hex.slice(12,16)}-${hex.slice(16,20)}-${hex.slice(20)}`;
}

/** Only trusted business services call this, while holding their write transaction. */
export async function enqueueNotificationJob(client: pg.PoolClient, input: {
  workspaceId: string; outboxId: string; dataGeneration: string; operationId: string; events: NotificationEventInput[];
}, now: Date): Promise<void> {
  const job=notificationJob.parse({workspaceId:input.workspaceId,outboxId:input.outboxId,dataGeneration:input.dataGeneration}), events=z.array(notificationEvent).max(6000).parse(input.events).map(event=>({
    ...event,recipientIds:[...new Set(event.recipientIds)].sort(),eventId:eventId(input.workspaceId,input.operationId,event.eventType,event.recordId),
  }));
  if(new Set(events.map(event=>event.eventId)).size!==events.length) throw new Error('Duplicate notification event');
  const updated=await client.query(`UPDATE app.outbox SET notification_events=$4,notification_version=1
    WHERE workspace_id=$1 AND id=$2 AND data_generation=$3 AND operation_id=$5 AND state='pending'`,
  [job.workspaceId,job.outboxId,job.dataGeneration,JSON.stringify(events),input.operationId]);
  if(updated.rowCount!==1) throw new Error('Notification outbox missing');
  await client.query(`SELECT graphile_worker.add_job('notification_delivery',$1::json,
    job_key:=$2,max_attempts:=10,run_at:=$3)`,[JSON.stringify(job),`notification:${job.workspaceId}:${job.dataGeneration}:${job.outboxId}`,now]);
}

/** Recipients come from the actual before/after state, never a client recipient list. */
export function planningNotificationEvents(before: PlanningState, after: PlanningState, actorId: string): NotificationEventInput[] {
  const events:NotificationEventInput[]=[];
  for(const task of after.tasks) {
    const prior=before.tasks.find(row=>row.id===task.id), recipients=[...new Set([...(prior?.assigneeIds??[]),...task.assigneeIds])].sort();
    if(JSON.stringify([...(prior?.assigneeIds??[])].sort())!==JSON.stringify([...task.assigneeIds].sort()))
      events.push({eventType:'task.assignment',recordId:task.id,actorId,recipientIds:recipients});
    if(prior&&prior.state!==task.state) events.push({eventType:'task.status',recordId:task.id,actorId,recipientIds:recipients});
    if(task.state==='review'&&task.reviewerProfileId&&(prior?.state!=='review'||prior.reviewerProfileId!==task.reviewerProfileId))
      events.push({eventType:'review.requested',recordId:task.id,actorId,recipientIds:[task.reviewerProfileId]});
  }
  return events;
}

/** Retryable delivery has no business-side effect; deduplication survives lost replies. */
export async function deliverNotificationJob(databases: Databases, input: unknown, options: {
  now?:()=>Date; beforeCommit?:()=>Promise<void>;
}={}): Promise<void> {
  const job=notificationJob.parse(input), now=options.now?.()??new Date();
  await tenantTransaction(databases.application,job.workspaceId,undefined,async application=>{
    await application.query("SELECT pg_advisory_xact_lock_shared(hashtextextended('ukda.workspace:' || $1,0))",[job.workspaceId]);
    const projected=(await application.query('SELECT * FROM app.workspaces WHERE workspace_id=$1',[job.workspaceId])).rows[0];
    if(!projected) return;
    const authority=await tenantTransaction(databases.control,job.workspaceId,undefined,async control=>
      (await control.query('SELECT security_head,security_version,data_generation,lifecycle,delete_after,restore_quarantine FROM security.workspaces WHERE workspace_id=$1',[job.workspaceId])).rows[0]);
    if (authority && deletionElapsed(authority as {lifecycle:string;delete_after:Date|null}, now)) return;
    if(!authority||projected.fence_closed||authority.restore_quarantine||projected.security_head!==authority.security_head||
      projected.security_version!==authority.security_version||projected.data_generation!==authority.data_generation)
      throw new AppError('SECURITY_FENCED','Notification delivery awaits current security state',503);
    const outbox=(await application.query('SELECT * FROM app.outbox WHERE workspace_id=$1 AND id=$2 FOR UPDATE',[job.workspaceId,job.outboxId])).rows[0];
    if(!outbox||outbox.state==='complete') return;
    if(job.dataGeneration!==authority.data_generation||outbox.data_generation!==job.dataGeneration||!['active','pending_deletion'].includes(authority.lifecycle)) {
      await application.query("UPDATE app.outbox SET state='complete',updated_at=$3 WHERE workspace_id=$1 AND id=$2",[job.workspaceId,job.outboxId,now]); return;
    }
    if(outbox.notification_version!==1) throw new Error('Legacy outbox has no notification descriptor');
    const events=z.array(descriptor).max(6000).parse(outbox.notification_events);
    for(const event of events) for(const recipientId of event.recipientIds) {
      if(recipientId===event.actorId) continue;
      await application.query("SELECT set_config('ukda.profile_id',$1,true)",[recipientId]);
      const active=(await application.query("SELECT 1 FROM app.profiles WHERE workspace_id=$1 AND id=$2 AND state='active'",[job.workspaceId,recipientId])).rowCount;
      if(!active) continue;
      if(outbox.project_id) {
        if(!(await application.query('SELECT app.can_read_project($1) AS allowed',[outbox.project_id])).rows[0]?.allowed) continue;
        if((await application.query('SELECT muted FROM app.notification_preferences WHERE workspace_id=$1 AND profile_id=$2 AND project_id=$3',[job.workspaceId,recipientId,outbox.project_id])).rows[0]?.muted) continue;
      }
      await application.query(`INSERT INTO app.notifications(workspace_id,id,recipient_profile_id,project_id,event_id,event_type,record_id,created_at,updated_at)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$8) ON CONFLICT(workspace_id,recipient_profile_id,event_id) DO NOTHING`,
      [job.workspaceId,randomUUID(),recipientId,outbox.project_id,event.eventId,event.eventType,event.recordId,now]);
    }
    await application.query("SELECT set_config('ukda.profile_id','',true)");
    await application.query("UPDATE app.outbox SET state='complete',attempts=attempts+1,revision=revision+1,updated_at=$3 WHERE workspace_id=$1 AND id=$2",[job.workspaceId,job.outboxId,now]);
    await options.beforeCommit?.();
  });
}
