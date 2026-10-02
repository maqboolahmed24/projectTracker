import { expect, test } from '@playwright/test';
import { randomUUID } from 'node:crypto';
import { authenticationFixture, password } from './authentication-fixture.js';
import { ownerPage, enrol } from './planning-helpers.js';

test('CP11: encrypted upgrade survives a lost start reply and reload, then another Owner finishes verified native batches', async ({ page, browser }, testInfo) => {
  test.setTimeout(180000);
  const f = await authenticationFixture(), secondContext = await browser.newContext({ ignoreHTTPSErrors: true }), second = await secondContext.newPage();
  let stage = 'setup';
  const diagnostics: { path: string; status: number }[] = [];
  for (const tab of [page, second]) tab.on('response', response => {
    const path = new URL(response.url()).pathname;
    if (path.startsWith('/v1/')) diagnostics.push({ path, status: response.status() });
  });
  try {
    await ownerPage(page, f);
    const project = await page.evaluate(() => window.clientRuntime.projectCreation.create({ name: 'Private upgrade project' }));
    await enrol(page, second, f, true);
    const setup = await page.evaluate(async ({ projectId, ownerId, memberRole }) => {
      const c = window.clientRuntime, p = c.planning, phaseId = crypto.randomUUID(), milestoneId = crypto.randomUUID();
      await c.teams.create({ name: 'Private upgrade team', memberIds: [ownerId] });
      await c.roles.create({ displayName: 'Private upgrade role', permissions: ['read_project'] });
      await c.enrolments.issueJoin({ accountId: crypto.randomUUID(), operationId: crypto.randomUUID(), kind: 'join_member', roleId: memberRole,
        projectIds: [], displayName: 'Private pending upgrade profile' });
      await p.execute({ projectId, command: { action: 'create_phase', phase: { id: phaseId, displayOrder: 0, leadProfileId: null } }, content: { name: 'Private upgrade wave' } });
      await p.execute({ projectId, command: { action: 'create_milestone', milestone: { id: milestoneId, phaseId, ownerProfileId: null } }, content: { name: 'Private upgrade milestone' } });
      const task = await p.createTask({ projectId, title: 'Private retained upgrade task', phaseId, milestoneId, assigneeIds: [ownerId], leadProfileId: ownerId });
      await p.execute({ projectId, command: { action: 'create_blocker', blocker: { id: crypto.randomUUID(), taskId: task.taskId, responsibleProfileId: ownerId } },
        content: { reason: 'Private retained blocker', nextAction: 'Private next action' } });
      await c.collaboration.postComment({ projectId, taskId: task.taskId, text: 'Private retained upgrade comment' });
      await c.collaboration.postUpdate({ projectId, phaseId, text: 'Private retained upgrade update' });
      await c.reporting.publish({ kind: 'project', projectId });
      return { taskId: task.taskId, before: await p.read(projectId) };
    }, { projectId: project.projectId, ownerId: f.accountId, memberRole: f.genesis.body.roles.member });
    const operationId = randomUUID(), starts: string[] = [];
    page.on('request', request => { if (request.url().endsWith('/v1/upgrades/start')) starts.push(request.postData() ?? ''); });
    await page.route('**/v1/upgrades/start', async route => {
      const response = await route.fetch(); expect(response.status()).toBe(200); await route.abort('failed');
    }, { times: 1 });
    stage = 'lost start reply';
    expect(await page.evaluate(async operationId => {
      try { await window.clientRuntime.upgrades.start(operationId); return false; } catch { return true; }
    }, operationId)).toBe(true);
    expect(await page.evaluate(() => window.clientRuntime.upgrades.pending())).toEqual([operationId]);
    stage = 'reload and receipt recovery';
    await page.reload(); await page.waitForFunction(() => !!window.ukda);
    const resumed = await page.evaluate(async ({ workspaceId, accountId, deviceId, trustedServiceKeys, password, operationId }) => {
      window.clientRuntime = await window.ukda.openClient({ trustedServiceKeys });
      await window.clientRuntime.auth.login({ workspaceId, accountId, deviceId }, password);
      const result = await window.clientRuntime.upgrades.resume(operationId);
      return { result, pending: await window.clientRuntime.upgrades.pending() };
    }, { workspaceId: f.workspaceId, accountId: f.accountId, deviceId: f.deviceId, trustedServiceKeys: f.trustedServiceKeys, password, operationId });
    expect(resumed.result.state).toBe('completed'); expect(resumed.pending).toEqual([]); expect(starts).toHaveLength(1);
    expect(starts[0]!.includes('Private')).toBe(false);
    const migrationId = resumed.result.migrationId;
    stage = 'content maintenance and first batch';
    expect(await page.evaluate(async projectId => {
      try { await window.clientRuntime.planning.createTask({ projectId, title: 'Must remain unsaved during upgrade' }); return false; } catch { return true; }
    }, project.projectId)).toBe(true);
    const first = await page.evaluate(migrationId => window.clientRuntime.upgrades.advance(migrationId), migrationId);
    expect(first.state).toBe('completed');
    await page.evaluate(() => window.clientRuntime.auth.logout());
    stage = 'another Owner resumes';
    const beginning = await second.evaluate(migrationId => window.clientRuntime.upgrades.progress(migrationId), migrationId);
    expect(beginning.completed).toBeGreaterThan(0); expect(beginning.total).toBeGreaterThan(10);
    let previous = beginning.completed, ready = false;
    // Finite fixture loop: each successful batch must advance the persisted count.
    for (let batch = 0; batch <= beginning.total; batch++) {
      const result = await second.evaluate(migrationId => window.clientRuntime.upgrades.advance(migrationId), migrationId);
      if (result.state === 'ready_to_finish') { ready = true; break; }
      expect(result.state).toBe('completed');
      const progress = await second.evaluate(migrationId => window.clientRuntime.upgrades.progress(migrationId), migrationId);
      expect(progress.completed).toBeGreaterThan(previous); previous = progress.completed;
    }
    expect(ready).toBe(true); expect(previous).toBe(beginning.total);
    stage = 'verified finalisation';
    const finished = await second.evaluate(migrationId => window.clientRuntime.upgrades.finish(migrationId), migrationId);
    expect(finished.state).toBe('completed');
    const progress = await second.evaluate(migrationId => window.clientRuntime.upgrades.progress(migrationId), migrationId);
    expect(progress.state).toBe('completed'); expect(progress.writeSchema).toBe(2);
    stage = 'normal schema 2 work';
    const after = await second.evaluate(async ({ projectId, taskId }) => {
      const c = window.clientRuntime, retained = await c.planning.read(projectId), comments = await c.collaboration.read({ projectId, kind: 'comment' });
      const staleSummary = await c.reporting.read({ kind: 'project', projectId });
      await c.planning.execute({ projectId, reviewed: retained.pin, command: { action: 'edit_task', taskId }, content: { title: 'Private edited schema 2 task' } });
      await c.collaboration.postComment({ projectId, taskId, text: 'Private new schema 2 comment' });
      await c.reporting.publish({ kind: 'project', projectId });
      return { retained, comments, staleSummary: staleSummary.status, current: await c.planning.read(projectId), pending: await c.upgrades.pending() };
    }, { projectId: project.projectId, taskId: setup.taskId });
    expect(after.retained.records.find(r => r.kind === 'task' && r.id === setup.taskId)!.content.title).toBe('Private retained upgrade task');
    expect(after.retained.graph.tasks[0]!.contentRevision).toBe(setup.before.graph.tasks[0]!.contentRevision);
    expect(after.comments.records[0]!.text).toBe('Private retained upgrade comment');
    expect(after.staleSummary).not.toBe('current'); expect(after.pending).toEqual([]);
    expect(after.current.records.find(r => r.kind === 'task' && r.id === setup.taskId)!.content.title).toBe('Private edited schema 2 task');
  } catch (error) {
    await testInfo.attach('upgrade-stage', { body: JSON.stringify({ stage, requests: diagnostics }, null, 2), contentType: 'application/json' }); throw error;
  } finally {
    await Promise.allSettled([page.evaluate(() => window.clientRuntime?.close()), second.evaluate(() => window.clientRuntime?.close())]);
    await secondContext.close(); await f.close();
  }
});
