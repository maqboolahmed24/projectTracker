import { randomUUID } from 'node:crypto';
import type { TestContext } from 'node:test';
import { transaction } from '../src/db.js';
import { ProjectCreateService } from '../src/modules/work/project-create.js';
import { PlanningService } from '../src/modules/work/planning.js';
import { ReportingService } from '../src/modules/work/reporting.js';
import { prepareProjectCreate } from '../src/client/project-create-crypto.js';
import { preparePlanning, readPlanning, type PlanningIntent, type PlanningPrivateContent } from '../src/client/planning-crypto.js';
import { digestObject } from '../src/shared/crypto.js';
import type { PlanningPayload } from '../src/shared/planning-api.js';
import { accessChangeFixture } from './access-change-fixture.js';
import { origin } from './password-change-fixture.js';

export async function planningFixture(t: TestContext) {
  let f: Awaited<ReturnType<typeof accessChangeFixture>>;
  t.after(async () => { if (f) await transaction(f.admin.application, async (c) => {
    const jobs = await c.query('SELECT key FROM graphile_worker.jobs WHERE key LIKE $1', [`notification:${f.workspaceId}:%`]);
    for (const row of jobs.rows) await c.query('SELECT graphile_worker.remove_job($1)', [row.key]);
    // Fixture-owned immutable histories are removed only by the test admin at teardown.
    await c.query("SET LOCAL session_replication_role='replica'");
    for (const table of ['planning_operations','project_planning_heads','operation_receipts','outbox','audit_events','record_versions','updates','comments','blockers','task_assignments','tasks','milestones','project_phases'])
      await c.query(`DELETE FROM app.${table} WHERE workspace_id=$1`, [f.workspaceId]);
  }); });
  f = await accessChangeFixture(t);
  const create = new ProjectCreateService({ ...f, origin });
  async function createProject(name = 'Private project') {
    const request = { workspaceId: f.workspaceId, projectId: randomUUID(), operationId: randomUUID() }, auth = f.auth();
    const context = await create.context(auth.cookieValue, auth.csrfToken, request), payload = await prepareProjectCreate({ request, context, history: await f.history(), name }, f.originalBundle);
    await create.stage(auth.cookieValue, auth.csrfToken, payload);
    await create.finalize(auth.cookieValue, auth.csrfToken, { workspaceId: f.workspaceId, operationId: request.operationId, requestHash: await digestObject(payload) });
    return request.projectId;
  }
  const projectId = await createProject(); let hooks: NonNullable<ConstructorParameters<typeof PlanningService>[0]['hooks']> = {}, offset = 0;
  const make = () => new PlanningService({ ...f, origin, hooks, now: () => new Date(Date.now() + offset) }); let service = make();
  const reference = (id: string = projectId) => ({ workspaceId: f.workspaceId, projectId: id, operationId: randomUUID() });
  async function context(id: string = projectId, auth = f.auth()) { return service.context(auth.cookieValue, auth.csrfToken, reference(id)); }
  async function prepare(command: PlanningIntent, options: { content?: PlanningPrivateContent; outcome?: string; projectId?: string } = {}, auth = f.auth(), bundle = f.originalBundle) {
    const current = await context(options.projectId, auth);
    const closes = ['complete_project','cancel_project','complete_phase','cancel_phase','accept_milestone','cancel_milestone'].includes(command.action);
    const closingSettings = closes ? { settings: await new ReportingService({ ...f, origin, planning: service }).settings(auth, { workspaceId: f.workspaceId }),
      history: await f.history(), materials: (await f.refresh(auth, bundle)).delivery.materials,
      accountId: current.binding.accountId, deviceId: current.binding.deviceId } : undefined;
    return preparePlanning({ context: current, history: await f.history(), accountId: current.binding.accountId, deviceId: current.binding.deviceId,
      ...(closingSettings ? { closingSettings } : {}), command, ...(options.content ? { content: options.content } : {}), ...(options.outcome !== undefined ? { outcome: options.outcome } : {}) }, bundle);
  }
  const save = (payload: PlanningPayload, auth = f.auth()) => service.save(auth.cookieValue, auth.csrfToken, payload);
  async function execute(command: PlanningIntent, options: Parameters<typeof prepare>[1] = {}) { const payload = await prepare(command, options); return save(payload); }
  async function status(payload: PlanningPayload) { const b = payload.mutation.body.binding, auth = f.auth(); return service.status(auth.cookieValue, auth.csrfToken,
    { workspaceId: b.workspaceId, projectId: b.projectId, operationId: b.operationId, dataGeneration: b.dataGeneration, requestHash: await digestObject(payload) }); }
  async function read() { const current = await context(); return readPlanning({ context: current, history: await f.history(), accountId: f.accountId, deviceId: f.deviceId }, f.originalBundle); }
  return { ...f, projectId, createProject, reference, context, preparePlanning: prepare, save, execute, planningStatus: status, read, get planning() { return service; },
    setPlanningHooks(value: typeof hooks = {}) { hooks = value; service = make(); }, advancePlanning(ms: number) { offset += ms; } };
}
