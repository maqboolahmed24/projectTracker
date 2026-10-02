import { expect, test } from '@playwright/test';
import { randomUUID } from 'node:crypto';
import { authenticationFixture, password } from './authentication-fixture.js';
import { ownerPage, enrol } from './planning-helpers.js';

test('CP08: title-only defaults, shared assignees, parent gates and multiple encrypted blockers use one task', async ({ page, browser }) => {
  test.setTimeout(90000);
  const f = await authenticationFixture(), context = await browser.newContext({ ignoreHTTPSErrors: true }), member = await context.newPage(), phaseId = randomUUID(), milestoneId = randomUUID(), blockerIds = [randomUUID(), randomUUID()];
  try {
    await ownerPage(page, f); const project = await page.evaluate(() => window.clientRuntime.projectCreation.create({ name: 'Private execution project' }));
    const person = await enrol(page, member, f, false, [project.projectId]);
    const uploads: string[] = [];
    for (const actor of [page, member]) actor.on('request', (request) => { if (request.url().endsWith('/v1/work/planning/save')) uploads.push(request.postData() ?? ''); });
    const defaults = await page.evaluate(async (projectId) => {
      const task = await window.clientRuntime.planning.createTask({ projectId, title: 'Private owner default task' });
      const graph = (await window.clientRuntime.planning.read(projectId)).graph;
      await window.clientRuntime.planning.execute({ reviewed: (await window.clientRuntime.planning.read(projectId)).pin, projectId, command: { action: 'cancel_task', taskId: task.taskId }, outcome: 'Default task is intentionally cancelled' });
      return graph.tasks.find((t) => t.id === task.taskId);
    }, project.projectId);
    expect(defaults!.assigneeIds).toEqual([]); expect(defaults!.state).toBe('todo');
    const personal = await member.evaluate(async (projectId) => {
      const task = await window.clientRuntime.planning.createTask({ projectId, title: 'Private member default task' });
      return { task, row: (await window.clientRuntime.planning.read(projectId)).graph.tasks.find((t) => t.id === task.taskId)! };
    }, project.projectId);
    expect(personal.row.assigneeIds).toEqual([person.accountId]);
    const task = await page.evaluate(async ({ projectId, ownerId, memberId, phaseId, milestoneId, personalTask }) => {
      const p = window.clientRuntime.planning;
      await p.execute({ reviewed: (await p.read(projectId)).pin, projectId, command: { action: 'cancel_task', taskId: personalTask }, outcome: 'Use one shared task for delivery' });
      await p.execute({ projectId, command: { action: 'create_phase', phase: { id: phaseId, displayOrder: 0, leadProfileId: ownerId } }, content: { name: 'Private execution wave' } });
      await p.execute({ projectId, command: { action: 'create_milestone', milestone: { id: milestoneId, phaseId, ownerProfileId: ownerId } }, content: { name: 'Private delivery checkpoint' } });
      const task = await p.createTask({ projectId, title: 'Private shared task', description: 'One delivery worked on together', acceptanceCriteria: 'Both assignees agree it works',
        phaseId, milestoneId, assigneeIds: [ownerId, memberId], leadProfileId: ownerId, priority: 'high', dueDate: '2026-10-05' });
      let projectGate = false, phaseGate = false;
      try { await p.execute({ reviewed: (await p.read(projectId)).pin, projectId, command: { action: 'start_task', taskId: task.taskId } }); } catch { projectGate = true; }
      await p.execute({ reviewed: (await p.read(projectId)).pin, projectId, command: { action: 'start_project' } });
      try { await p.execute({ reviewed: (await p.read(projectId)).pin, projectId, command: { action: 'start_task', taskId: task.taskId } }); } catch { phaseGate = true; }
      await p.execute({ reviewed: (await p.read(projectId)).pin, projectId, command: { action: 'start_phase', phaseId } });
      return { ...task, projectGate, phaseGate };
    }, { projectId: project.projectId, ownerId: f.accountId, memberId: person.accountId, phaseId, milestoneId, personalTask: personal.task.taskId });
    expect(task.projectGate).toBe(true); expect(task.phaseGate).toBe(true);
    const blocked = await member.evaluate(async ({ projectId, taskId, blockerIds, memberId, ownerId }) => {
      const p = window.clientRuntime.planning; await p.execute({ reviewed: (await p.read(projectId)).pin, projectId, command: { action: 'start_task', taskId } });
      for (const id of blockerIds) await p.execute({ projectId, command: { action: 'create_blocker', blocker: { id, taskId, responsibleProfileId: memberId } }, content: { reason: 'Private waiting for dependency', nextAction: 'Private contact dependency owner' } });
      let otherResponsibleDenied = false;
      try { await p.execute({ reviewed: (await p.read(projectId)).pin, projectId, command: { action: 'edit_blocker', blockerId: blockerIds[0]!, responsibleProfileId: ownerId }, content: { reason: 'Cannot assign another person', nextAction: 'Ask manager' } }); } catch { otherResponsibleDenied = true; }
      await p.execute({ reviewed: (await p.read(projectId)).pin, projectId, command: { action: 'resolve_blocker', blockerId: blockerIds[0]! }, outcome: 'Private dependency one delivered' });
      let partialBlocked = false; try { await p.execute({ reviewed: (await p.read(projectId)).pin, projectId, command: { action: 'request_task_completion', taskId, acceptanceConfirmed: true } }); } catch { partialBlocked = true; }
      return { otherResponsibleDenied, partialBlocked, read: await p.read(projectId) };
    }, { projectId: project.projectId, taskId: task.taskId, blockerIds, memberId: person.accountId, ownerId: f.accountId });
    expect(blocked.partialBlocked).toBe(true); expect(blocked.otherResponsibleDenied).toBe(true);
    expect([...blocked.read.graph.tasks.find((t) => t.id === task.taskId)!.assigneeIds].sort()).toEqual([f.accountId, person.accountId].sort());
    await page.evaluate(async ({ projectId, taskId, memberId }) => {
      const p = window.clientRuntime.planning;
      await p.execute({ reviewed: (await p.read(projectId)).pin, projectId, command: { action: 'assign_task', taskId, assigneeIds: [memberId], leadProfileId: null, teamId: null } });
      await p.execute({ reviewed: (await p.read(projectId)).pin, projectId, command: { action: 'cancel_task', taskId }, outcome: 'Private pause by cancellation' });
      await p.execute({ reviewed: (await p.read(projectId)).pin, projectId, command: { action: 'restore_task', taskId }, outcome: 'Private restored delivery' });
    }, { projectId: project.projectId, taskId: task.taskId, memberId: person.accountId });
    const done = await member.evaluate(async ({ projectId, taskId, blockerId }) => {
      const p = window.clientRuntime.planning; let restoredBlocked = false;
      try { await p.execute({ reviewed: (await p.read(projectId)).pin, projectId, command: { action: 'request_task_completion', taskId, acceptanceConfirmed: true } }); } catch { restoredBlocked = true; }
      await p.execute({ reviewed: (await p.read(projectId)).pin, projectId, command: { action: 'resolve_blocker', blockerId }, outcome: 'Private dependency two delivered' });
      await p.execute({ reviewed: (await p.read(projectId)).pin, projectId, command: { action: 'request_task_completion', taskId, acceptanceConfirmed: true } });
      let doneBlockerDenied = false;
      try { await p.execute({ reviewed: (await p.read(projectId)).pin, projectId, command: { action: 'reopen_blocker', blockerId }, outcome: 'Must reopen finished task' }); } catch { doneBlockerDenied = true; }
      return { restoredBlocked, doneBlockerDenied, read: await p.read(projectId) };
    }, { projectId: project.projectId, taskId: task.taskId, blockerId: blockerIds[1]! });
    expect(done.restoredBlocked).toBe(true); expect(done.doneBlockerDenied).toBe(true);
    expect(done.read.graph.tasks.find((t) => t.id === task.taskId)).toMatchObject({ state: 'done', leadProfileId: null });
    const closure = await page.evaluate(async ({ projectId, taskId, phaseId, milestoneId }) => {
      const p = window.clientRuntime.planning; await p.execute({ reviewed: (await p.read(projectId)).pin, projectId, command: { action: 'accept_milestone', milestoneId }, outcome: 'Private shared delivery accepted' });
      const accepted = await p.read(projectId); await p.execute({ reviewed: (await p.read(projectId)).pin, projectId, command: { action: 'reopen_task', taskId }, outcome: 'Private follow-up work' });
      const reopened = await p.read(projectId); let closureDenied = false;
      try { await p.execute({ reviewed: (await p.read(projectId)).pin, projectId, command: { action: 'complete_phase', phaseId }, outcome: 'Cannot close unfinished reopened task' }); } catch { closureDenied = true; }
      await p.execute({ reviewed: (await p.read(projectId)).pin, projectId, command: { action: 'request_task_completion', taskId, acceptanceConfirmed: true } });
      await p.execute({ reviewed: (await p.read(projectId)).pin, projectId, command: { action: 'accept_milestone', milestoneId }, outcome: 'Private final acceptance' });
      await p.execute({ reviewed: (await p.read(projectId)).pin, projectId, command: { action: 'complete_phase', phaseId }, outcome: 'Private complete wave' });
      await p.execute({ reviewed: (await p.read(projectId)).pin, projectId, command: { action: 'complete_project' }, outcome: 'Private complete project' });
      return { accepted, reopened, closureDenied, closed: await p.read(projectId) };
    }, { projectId: project.projectId, taskId: task.taskId, phaseId, milestoneId });
    expect(closure.reopened.graph.milestones[0]!.state).toBe('open'); expect(closure.closureDenied).toBe(true); expect(closure.closed.graph.project.state).toBe('complete');
    expect(closure.closed.audits.slice(0, closure.accepted.audits.length)).toEqual(closure.accepted.audits);
    expect(uploads.every((body) => !['Private', 'One delivery worked on together', 'Both assignees agree it works'].some((text) => body.includes(text)))).toBe(true);
  } finally { await Promise.allSettled([page.evaluate(() => window.clientRuntime?.close()), member.evaluate(() => window.clientRuntime?.close())]); await context.close(); await f.close(); }
});

test('CP08: independent review rejects, resubmits and approves exact content; material edits and reviewer loss cannot reuse approval', async ({ page, browser }) => {
  test.setTimeout(90000);
  const f = await authenticationFixture(), context = await browser.newContext({ ignoreHTTPSErrors: true }), reviewer = await context.newPage();
  try {
    await ownerPage(page, f);
    const project = await page.evaluate(() => window.clientRuntime.projectCreation.create({ name: 'Private reviewed browser project' }));
    const other = await enrol(page, reviewer, f, true);
    const task = await page.evaluate(async ({ projectId, ownerId, reviewerId }) => {
      const p = window.clientRuntime.planning; await p.execute({ reviewed: (await p.read(projectId)).pin, projectId, command: { action: 'start_project' } });
      const task = await p.createTask({ projectId, title: 'Private review task', assigneeIds: [ownerId], acceptanceCriteria: 'Private result checked' });
      await p.execute({ reviewed: (await p.read(projectId)).pin, projectId, command: { action: 'set_project_review', enabled: true, reviewers: [{ taskId: task.taskId, reviewerProfileId: reviewerId }] }, outcome: 'Private require independent review' });
      await p.execute({ reviewed: (await p.read(projectId)).pin, projectId, command: { action: 'request_task_completion', taskId: task.taskId, acceptanceConfirmed: true } });
      const submitted = (await p.read(projectId)).graph.tasks[0]!; let selfDenied = false;
      try { await p.execute({ reviewed: (await p.read(projectId)).pin, projectId, command: { action: 'approve_task', taskId: task.taskId, submittedRevision: submitted.submittedRevision!, submittedPolicyRevision: submitted.submittedPolicyRevision! } }); } catch { selfDenied = true; }
      return { ...task, submitted, selfDenied };
    }, { projectId: project.projectId, ownerId: f.accountId, reviewerId: other.accountId });
    expect(task.selfDenied).toBe(true);
    await reviewer.evaluate(async ({ projectId, taskId }) => window.clientRuntime.planning.execute({ reviewed: (await window.clientRuntime.planning.read(projectId)).pin, projectId, command: { action: 'reject_task', taskId }, outcome: 'Private rejection needs one correction' }), { projectId: project.projectId, taskId: task.taskId });
    const edit = await page.evaluate(async ({ projectId, taskId }) => {
      const p = window.clientRuntime.planning;
      await p.execute({ reviewed: (await p.read(projectId)).pin, projectId, command: { action: 'request_task_completion', taskId, acceptanceConfirmed: true } });
      await p.execute({ reviewed: (await p.read(projectId)).pin, projectId, command: { action: 'edit_task', taskId }, content: { title: 'Private changed review task', description: 'Private requested correction', acceptanceCriteria: 'Private revised conditions' } });
      const invalidated = (await p.read(projectId)).graph.tasks[0]!;
      await p.execute({ reviewed: (await p.read(projectId)).pin, projectId, command: { action: 'request_task_completion', taskId, acceptanceConfirmed: true } });
      return { invalidated, submitted: (await p.read(projectId)).graph.tasks[0]! };
    }, { projectId: project.projectId, taskId: task.taskId });
    expect(edit.invalidated).toMatchObject({ state: 'in_progress', submittedRevision: null, approvalOperationId: null });
    const approval = await reviewer.evaluate(async ({ projectId, taskId, old, current }) => {
      const p = window.clientRuntime.planning; let staleDenied = false;
      try { await p.execute({ reviewed: (await p.read(projectId)).pin, projectId, command: { action: 'approve_task', taskId, submittedRevision: old.submittedRevision!, submittedPolicyRevision: old.submittedPolicyRevision! } }); } catch { staleDenied = true; }
      await p.execute({ reviewed: (await p.read(projectId)).pin, projectId, command: { action: 'approve_task', taskId, submittedRevision: current.submittedRevision!, submittedPolicyRevision: current.submittedPolicyRevision! } });
      return { staleDenied, read: await p.read(projectId) };
    }, { projectId: project.projectId, taskId: task.taskId, old: task.submitted, current: edit.submitted });
    expect(approval.staleDenied).toBe(true); expect(approval.read.graph.tasks[0]!.state).toBe('done');
    expect(approval.read.records.find((r) => r.id === task.taskId)!.content.title).toBe('Private changed review task');
    const disabled = await page.evaluate(async ({ projectId, taskId }) => {
      const p = window.clientRuntime.planning; let doneEditDenied = false;
      try { await p.execute({ reviewed: (await p.read(projectId)).pin, projectId, command: { action: 'edit_task', taskId }, content: { title: 'Forbidden edit' } }); } catch { doneEditDenied = true; }
      await p.execute({ reviewed: (await p.read(projectId)).pin, projectId, command: { action: 'reopen_task', taskId }, outcome: 'Private more work needed' });
      await p.execute({ reviewed: (await p.read(projectId)).pin, projectId, command: { action: 'request_task_completion', taskId, acceptanceConfirmed: true } });
      await p.execute({ reviewed: (await p.read(projectId)).pin, projectId, command: { action: 'set_project_review', enabled: false, reviewers: [] }, outcome: 'Private reviewed policy disabled' });
      return { doneEditDenied, read: await p.read(projectId) };
    }, { projectId: project.projectId, taskId: task.taskId });
    expect(disabled.doneEditDenied).toBe(true); expect(disabled.read.graph.tasks[0]!.state).toBe('in_progress');
    await page.evaluate(async ({ projectId, taskId, reviewerId, roleId }) => {
      const p = window.clientRuntime.planning;
      await p.execute({ reviewed: (await p.read(projectId)).pin, projectId, command: { action: 'set_project_review', enabled: true, reviewers: [{ taskId, reviewerProfileId: reviewerId }] }, outcome: 'Private independent review restored' });
      await p.execute({ reviewed: (await p.read(projectId)).pin, projectId, command: { action: 'request_task_completion', taskId, acceptanceConfirmed: true } });
      await window.clientRuntime.accessChanges.demoteOwner({ accountId: reviewerId, roleId, projectIds: [] });
    }, { projectId: project.projectId, taskId: task.taskId, reviewerId: other.accountId, roleId: f.genesis.body.roles.member });
    const loss = await page.evaluate(async ({ projectId, taskId, ownerId }) => {
      const p = window.clientRuntime.planning, missing = await p.read(projectId); let selfFallbackDenied = false;
      try { await p.execute({ reviewed: (await p.read(projectId)).pin, projectId, command: { action: 'select_task_reviewer', taskId, reviewerProfileId: ownerId } }); } catch { selfFallbackDenied = true; }
      await p.execute({ reviewed: (await p.read(projectId)).pin, projectId, command: { action: 'assign_task', taskId, assigneeIds: [], leadProfileId: null, teamId: null } });
      await p.execute({ reviewed: (await p.read(projectId)).pin, projectId, command: { action: 'select_task_reviewer', taskId, reviewerProfileId: ownerId } });
      await p.execute({ reviewed: (await p.read(projectId)).pin, projectId, command: { action: 'request_task_completion', taskId, acceptanceConfirmed: true } });
      const submitted = (await p.read(projectId)).graph.tasks[0]!;
      await p.execute({ reviewed: (await p.read(projectId)).pin, projectId, command: { action: 'approve_task', taskId, submittedRevision: submitted.submittedRevision!, submittedPolicyRevision: submitted.submittedPolicyRevision! } });
      return { missing, selfFallbackDenied, read: await p.read(projectId) };
    }, { projectId: project.projectId, taskId: task.taskId, ownerId: f.accountId });
    expect(loss.missing.graph.tasks[0]!.reviewerProfileId).toBeNull(); expect(loss.selfFallbackDenied).toBe(true); expect(loss.read.graph.tasks[0]!.state).toBe('done');
    expect(loss.read.outcomes.some((r) => r.text === 'Private rejection needs one correction')).toBe(true);
    expect(await reviewer.evaluate(async (projectId) => { try { await window.clientRuntime.planning.read(projectId); return false; } catch { return true; } }, project.projectId)).toBe(true);
  } finally { await Promise.allSettled([page.evaluate(() => window.clientRuntime?.close()), reviewer.evaluate(() => window.clientRuntime?.close())]); await context.close(); await f.close(); }
});

test('CP08: lost task save reloads its exact encrypted receipt once and Forget removes the pending ciphertext', async ({ page }) => {
  const f = await authenticationFixture(), operationId = randomUUID();
  try {
    await ownerPage(page, f); const project = await page.evaluate(() => window.clientRuntime.projectCreation.create({ name: 'Private task retry project' }));
    const created = await page.evaluate((projectId) => window.clientRuntime.planning.createTask({ projectId, title: 'Private initial task' }), project.projectId);
    let saves = 0; page.on('request', (r) => { if (r.url().endsWith('/v1/work/planning/save')) saves++; });
    await page.route('**/v1/work/planning/save', async (route) => { const reply = await route.fetch(); expect(reply.status()).toBe(200); await route.abort('failed'); }, { times: 1 });
    expect(await page.evaluate(async ({ projectId, taskId, operationId }) => {
      try { await window.clientRuntime.planning.execute({ reviewed: (await window.clientRuntime.planning.read(projectId)).pin, projectId, operationId, command: { action: 'edit_task', taskId }, content: { title: 'Private durable task edit', description: 'Private pending description', acceptanceCriteria: 'Private pending criteria' } }); return false; } catch { return true; }
    }, { projectId: project.projectId, taskId: created.taskId, operationId })).toBe(true);
    const pending = await page.evaluate(async ({ workspaceId, operationId }) => {
      const store = await window.ukda.IndexedPlanningStore.open(location.origin); try { return await store.get(workspaceId, operationId); } finally { store.close(); }
    }, { workspaceId: f.workspaceId, operationId });
    expect(JSON.stringify(pending)).not.toContain('Private');
    await page.reload(); await page.waitForFunction(() => !!window.ukda);
    const result = await page.evaluate(async ({ workspaceId, accountId, deviceId, trustedServiceKeys, password, operationId, projectId }) => {
      window.clientRuntime = await window.ukda.openClient({ trustedServiceKeys }); await window.clientRuntime.auth.login({ workspaceId, accountId, deviceId }, password);
      const first = await window.clientRuntime.planning.resume(operationId), again = await window.clientRuntime.planning.resume(operationId), read = await window.clientRuntime.planning.read(projectId);
      await window.clientRuntime.auth.forget({ workspaceId, accountId, deviceId }); const store = await window.ukda.IndexedPlanningStore.open(location.origin);
      try { return { first, again, read, cleared: await store.get(workspaceId, operationId) === undefined }; } finally { store.close(); }
    }, { workspaceId: f.workspaceId, accountId: f.accountId, deviceId: f.deviceId, trustedServiceKeys: f.trustedServiceKeys, password, operationId, projectId: project.projectId });
    expect(saves).toBe(1); expect(result.first.receipt).toEqual(result.again.receipt); expect(result.cleared).toBe(true);
    expect(result.read.graph.tasks).toHaveLength(1); expect(result.read.graph.tasks[0]!.contentRevision).toBe('2');
    expect(result.read.records.find((r) => r.id === created.taskId)!.content.title).toBe('Private durable task edit');
    expect(result.read.audits.filter((r) => r.data.action === 'edit_task')).toHaveLength(1);
  } finally { await Promise.allSettled([page.evaluate(() => window.clientRuntime?.close())]); await f.close(); }
});
