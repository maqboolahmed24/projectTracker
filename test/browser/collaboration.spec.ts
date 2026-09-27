import { expect, test } from '@playwright/test';
import { randomUUID } from 'node:crypto';
import { authenticationFixture, password } from './authentication-fixture.js';
import { ownerPage, enrol, otherPassword } from './planning-helpers.js';

test('CP09: simultaneous encrypted comments survive independently and remain attached after carrying shared work', async ({ page, browser }) => {
  test.setTimeout(90000);
  const f = await authenticationFixture(), context = await browser.newContext({ ignoreHTTPSErrors: true }), member = await context.newPage(), phaseA = randomUUID(), phaseB = randomUUID();
  try {
    await ownerPage(page, f); const project = await page.evaluate(() => window.clientRuntime.projectCreation.create({ name: 'Private conversation project' }));
    const person = await enrol(page, member, f, false, [project.projectId]);
    const task = await page.evaluate(async ({ projectId, memberId, phaseA, phaseB }) => {
      const p = window.clientRuntime.planning; await p.execute({ reviewed: (await p.read(projectId)).pin, projectId, command: { action: 'start_project' } });
      for (const [id, displayOrder] of [[phaseA, 0], [phaseB, 1]] as const) {
        await p.execute({ projectId, command: { action: 'create_phase', phase: { id, displayOrder, leadProfileId: null } }, content: { name: `Private wave ${displayOrder}` } });
        await p.execute({ reviewed: (await p.read(projectId)).pin, projectId, command: { action: 'start_phase', phaseId: id } });
      }
      return p.createTask({ projectId, title: 'Private collaborative work', phaseId: phaseA, assigneeIds: [memberId] });
    }, { projectId: project.projectId, memberId: person.accountId, phaseA, phaseB });
    const uploads: string[] = []; for (const actor of [page, member]) actor.on('request', (r) => { if (r.url().endsWith('/v1/collaboration/save')) uploads.push(r.postData() ?? ''); });
    const posts = await Promise.all([
      page.evaluate(({ projectId, taskId }) => window.clientRuntime.collaboration.postComment({ projectId, taskId, text: 'Private owner concurrent comment' }), { projectId: project.projectId, taskId: task.taskId }),
      member.evaluate(({ projectId, taskId }) => window.clientRuntime.collaboration.postComment({ projectId, taskId, text: 'Private member concurrent comment' }), { projectId: project.projectId, taskId: task.taskId }),
    ]);
    expect(new Set(posts.map((p) => p.entryId)).size).toBe(2);
    await expect.poll(() => member.evaluate(async (entryId) => (await window.clientRuntime.inbox.list()).records.filter((notice) => notice.eventType === 'task.comment' && notice.recordId === entryId).length,
      posts[0]!.entryId), { timeout: 15000 }).toBe(1);
    const inbox = await member.evaluate(async ({ entryId, projectId }) => {
      const i = window.clientRuntime.inbox, notice = (await i.list()).records.find((r) => r.recordId === entryId)!;
      await i.setRead([{ id: notice.id, expectedRevision: notice.revision }], true);
      const read = await i.resolve(notice.id), before = await i.preference(projectId);
      await i.setProjectMuted(projectId, true, before.revision); const muted = await i.preference(projectId);
      await i.setProjectMuted(projectId, false, muted.revision); return { read, muted, current: await i.preference(projectId) };
    }, { entryId: posts[0]!.entryId, projectId: project.projectId });
    expect(inbox.read.readAt).not.toBeNull(); expect(inbox.muted.muted).toBe(true); expect(inbox.current.muted).toBe(false);
    const result = await page.evaluate(async ({ projectId, taskId, phaseB }) => {
      const c = window.clientRuntime.collaboration, before = await c.read({ projectId, kind: 'comment', taskId });
      await window.clientRuntime.planning.execute({ reviewed: (await window.clientRuntime.planning.read(projectId)).pin, projectId, command: { action: 'carry_task', taskId, phaseId: phaseB, milestoneId: null }, outcome: 'Private carry with discussion intact' });
      await c.postComment({ projectId, taskId, text: 'Private correction is another entry' });
      return { before, after: await c.read({ projectId, kind: 'comment', taskId }) };
    }, { projectId: project.projectId, taskId: task.taskId, phaseB });
    expect(result.before.records.map((r) => r.text).sort()).toEqual(['Private member concurrent comment', 'Private owner concurrent comment']);
    expect(result.after.records).toHaveLength(3); expect(result.before.records.every((old) => result.after.records.some((r) => r.entryId === old.entryId && r.text === old.text))).toBe(true);
    await member.evaluate(async ({ projectId, phaseId }) => {
      await window.clientRuntime.collaboration.postUpdate({ projectId, text: 'Private project discussion update' });
      await window.clientRuntime.collaboration.postUpdate({ projectId, phaseId, text: 'Private wave discussion update' });
    }, { projectId: project.projectId, phaseId: phaseB });
    const wave = await member.evaluate(({ projectId, phaseId }) => window.clientRuntime.collaboration.read({ projectId, kind: 'update', phaseId }), { projectId: project.projectId, phaseId: phaseB });
    expect(wave.records.some((r) => r.text === 'Private wave discussion update')).toBe(true);
    expect(uploads).toHaveLength(5); expect(uploads.every((body) => !body.includes('Private'))).toBe(true);
  } finally { await Promise.allSettled([page.evaluate(() => window.clientRuntime?.close()), member.evaluate(() => window.clientRuntime?.close())]); await context.close(); await f.close(); }
});

test('CP09: scoped moderation hides feeds, retains encrypted originals and reasons, and works after archive without changing planning outcomes', async ({ page, browser }) => {
  test.setTimeout(90000);
  const f = await authenticationFixture(), context = await browser.newContext({ ignoreHTTPSErrors: true }), member = await context.newPage();
  try {
    await ownerPage(page, f); const project = await page.evaluate(() => window.clientRuntime.projectCreation.create({ name: 'Private moderation project' }));
    const person = await enrol(page, member, f, false, [project.projectId]);
    const task = await page.evaluate(async ({ projectId, memberId }) => {
      await window.clientRuntime.planning.execute({ reviewed: (await window.clientRuntime.planning.read(projectId)).pin, projectId, command: { action: 'start_project' } });
      const task = await window.clientRuntime.planning.createTask({ projectId, title: 'Private moderated task', assigneeIds: [memberId] });
      const role = await window.clientRuntime.roles.create({ displayName: 'Private commenter', permissions: ['read_project', 'comment'] });
      await window.clientRuntime.accessChanges.setAccess({ accountId: memberId, roleId: role.roleId, projectIds: [projectId] }); return task;
    }, { projectId: project.projectId, memberId: person.accountId });
    const reauthenticated = await member.evaluate(async ({ workspaceId, accountId, deviceId, password }) => {
      let oldSessionRejected = false; try { await window.clientRuntime.auth.refresh(); } catch { oldSessionRejected = true; }
      const login = await window.clientRuntime.auth.login({ workspaceId, accountId, deviceId }, password);
      return { oldSessionRejected, sessionGeneration: login.session.sessionGeneration };
    }, { workspaceId: f.workspaceId, accountId: person.accountId, deviceId: person.deviceId, password: otherPassword });
    expect(reauthenticated.oldSessionRejected).toBe(true); expect(reauthenticated.sessionGeneration).toBe('2');
    const post = await member.evaluate(({ projectId, taskId }) => window.clientRuntime.collaboration.postComment({ projectId, taskId, text: 'Private retained original comment' }), { projectId: project.projectId, taskId: task.taskId });
    expect(await member.evaluate(async ({ projectId, entryId }) => { const reviewed=(await window.clientRuntime.collaboration.history({projectId,entryId,kind:'comment'})).pin;
      try { await window.clientRuntime.collaboration.hide({ projectId, entryId, reviewed, kind: 'comment', reason: 'Forbidden member moderation' }); return false; } catch { return true; } }, { projectId: project.projectId, entryId: post.entryId })).toBe(true);
    const hidden = await page.evaluate(async ({ projectId, taskId, entryId }) => {
      const c = window.clientRuntime.collaboration;
      await c.hide({ projectId, kind: 'comment', entryId, reviewed:(await c.history({projectId,entryId,kind:'comment'})).pin, reason: 'Private moderation reason retained' });
      return { feed: await c.read({ projectId, kind: 'comment', taskId }), history: await c.history({ projectId, kind: 'comment', entryId }) };
    }, { projectId: project.projectId, taskId: task.taskId, entryId: post.entryId });
    expect(hidden.feed.records).toHaveLength(0); expect(hidden.history.text).toBe('Private retained original comment');
    expect(hidden.history.moderation!.reason).toBe('Private moderation reason retained'); expect(hidden.history.hidden).toBe(true);
    const archive = await page.evaluate(async ({ projectId, taskId }) => {
      const p = window.clientRuntime.planning, c = window.clientRuntime.collaboration;
      const update = await c.postUpdate({ projectId, text: 'Private immutable project update' });
      await p.execute({ reviewed: (await p.read(projectId)).pin, projectId, command: { action: 'cancel_task', taskId }, outcome: 'Private explicit cancellation' });
      await p.execute({ reviewed: (await p.read(projectId)).pin, projectId, command: { action: 'complete_project' }, outcome: 'Private original closing outcome' });
      const before = await p.read(projectId); await p.execute({ reviewed: (await p.read(projectId)).pin, projectId, command: { action: 'archive_project' } });
      let appendDenied = false; try { await c.postUpdate({ projectId, text: 'Cannot append after archive' }); } catch { appendDenied = true; }
      await c.hide({ projectId, kind: 'update', entryId: update.entryId, reviewed:(await c.history({projectId,entryId:update.entryId,kind:'update'})).pin, reason: 'Private archived moderation' });
      const outcomeId = before.graph.snapshots.at(-1)!.outcome.recordId;
      await c.hide({ projectId, kind: 'update', entryId: outcomeId, reviewed:(await c.history({projectId,entryId:outcomeId,kind:'update'})).pin, reason: 'Private hide outcome from normal feed' });
      return { before, appendDenied, after: await p.read(projectId), update: await c.history({ projectId, kind: 'update', entryId: update.entryId }),
        outcome: await c.history({ projectId, kind: 'update', entryId: outcomeId }), feed: await c.read({ projectId, kind: 'update' }) };
    }, { projectId: project.projectId, taskId: task.taskId });
    expect(archive.appendDenied).toBe(true); expect(archive.update.text).toBe('Private immutable project update'); expect(archive.outcome.text).toBe('Private original closing outcome');
    expect(archive.after.graph.snapshots).toEqual(archive.before.graph.snapshots); expect(archive.after.audits.slice(0, archive.before.audits.length)).toEqual(archive.before.audits);
    expect(archive.feed.records.some((r) => r.entryId === archive.outcome.entryId || r.entryId === archive.update.entryId)).toBe(false);
  } finally { await Promise.allSettled([page.evaluate(() => window.clientRuntime?.close()), member.evaluate(() => window.clientRuntime?.close())]); await context.close(); await f.close(); }
});

test('CP09: lost comment response resumes once after reload and Forget clears its encrypted request', async ({ page }) => {
  const f = await authenticationFixture(), operationId = randomUUID();
  try {
    await ownerPage(page, f); const project = await page.evaluate(() => window.clientRuntime.projectCreation.create({ name: 'Private comment retry project' }));
    const task = await page.evaluate((projectId) => window.clientRuntime.planning.createTask({ projectId, title: 'Private retry task' }), project.projectId);
    let saves = 0; page.on('request', (r) => { if (r.url().endsWith('/v1/collaboration/save')) saves++; });
    await page.route('**/v1/collaboration/save', async (route) => { const reply = await route.fetch(); expect(reply.status()).toBe(200); await route.abort('failed'); }, { times: 1 });
    expect(await page.evaluate(async ({ projectId, taskId, operationId }) => { try { await window.clientRuntime.collaboration.postComment({ projectId, taskId, operationId, text: 'Private durable comment' }); return false; } catch { return true; } }, { projectId: project.projectId, taskId: task.taskId, operationId })).toBe(true);
    const stored = await page.evaluate(async ({ workspaceId, operationId }) => { const store = await window.ukda.IndexedCollaborationStore.open(location.origin);
      try { return await store.get(workspaceId, operationId); } finally { store.close(); } }, { workspaceId: f.workspaceId, operationId });
    expect(JSON.stringify(stored)).not.toContain('Private');
    await page.reload(); await page.waitForFunction(() => !!window.ukda);
    const result = await page.evaluate(async ({ workspaceId, accountId, deviceId, trustedServiceKeys, password, projectId, taskId, operationId }) => {
      window.clientRuntime = await window.ukda.openClient({ trustedServiceKeys }); await window.clientRuntime.auth.login({ workspaceId, accountId, deviceId }, password);
      const first = await window.clientRuntime.collaboration.resume(operationId), again = await window.clientRuntime.collaboration.resume(operationId),
        feed = await window.clientRuntime.collaboration.read({ projectId, kind: 'comment', taskId });
      await window.clientRuntime.auth.forget({ workspaceId, accountId, deviceId }); const store = await window.ukda.IndexedCollaborationStore.open(location.origin);
      try { return { first, again, feed, cleared: await store.get(workspaceId, operationId) === undefined }; } finally { store.close(); }
    }, { workspaceId: f.workspaceId, accountId: f.accountId, deviceId: f.deviceId, trustedServiceKeys: f.trustedServiceKeys, password, projectId: project.projectId, taskId: task.taskId, operationId });
    expect(saves).toBe(1); expect(result.first.receipt).toEqual(result.again.receipt); expect(result.feed.records).toHaveLength(1);
    expect(result.feed.records[0]!.text).toBe('Private durable comment'); expect(result.cleared).toBe(true);
  } finally { await Promise.allSettled([page.evaluate(() => window.clientRuntime?.close())]); await f.close(); }
});
