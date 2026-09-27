import { expect, test, type BrowserContext, type Page } from '@playwright/test';
import { randomUUID } from 'node:crypto';
import { authenticationFixture, origin, password } from './authentication-fixture.js';
import { enrol, otherPassword, ownerPage } from './planning-helpers.js';

// One real workspace throughout: fixture activation uses the real OPAQUE/crypto
// protocol and databases; all subsequent operations use browser Workers/IndexedDB.
test('CP13: iterative shared delivery survives device approval, member reset, Owner recovery and removal', async ({ page, browser }) => {
  test.setTimeout(240000);
  const f = await authenticationFixture(), contexts: BrowserContext[] = [], pages: Page[] = [page];
  const fresh = async () => {
    const context = await browser.newContext({ ignoreHTTPSErrors: true }); contexts.push(context);
    const actor = await context.newPage(); pages.push(actor); return actor;
  };
  const open = async (actor: Page) => {
    await actor.goto(origin); await actor.waitForFunction(() => !!window.ukda);
    await actor.evaluate(async trustedServiceKeys => { window.clientRuntime = await window.ukda.openClient({ trustedServiceKeys }); }, f.trustedServiceKeys);
  };
  const second = await fresh(), member = await fresh();
  const phaseA = randomUUID(), phaseB = randomUUID(), milestoneId = randomUUID(), blockerId = randomUUID();
  try {
    await ownerPage(page, f);
    const successor = await test.step('First Owner adds an equal Owner', () => enrol(page, second, f, true));
    const project = await page.evaluate(() => window.clientRuntime.projectCreation.create({ name: 'Private integrated delivery' }));
    const person = await test.step('Invite a scoped member', () => enrol(page, member, f, false, [project.projectId]));
    const task = await test.step('Create two waves and one shared task', () => page.evaluate(async ({ projectId, ownerId, memberId, phaseA, phaseB, milestoneId }) => {
      const p = window.clientRuntime.planning;
      await p.execute({ projectId, reviewed: (await p.read(projectId)).pin, command: { action: 'start_project' } });
      for (const [id, displayOrder] of [[phaseA, 0], [phaseB, 1]] as const) {
        await p.execute({ projectId, command: { action: 'create_phase', phase: { id, displayOrder, leadProfileId: null } }, content: { name: `Private iteration ${displayOrder + 1}` } });
        await p.execute({ projectId, reviewed: (await p.read(projectId)).pin, command: { action: 'start_phase', phaseId: id } });
      }
      await p.execute({ projectId, command: { action: 'create_milestone', milestone: { id: milestoneId, phaseId: phaseB, ownerProfileId: ownerId } }, content: { name: 'Private acceptance checkpoint' } });
      return p.createTask({ projectId, title: 'Private shared outcome', phaseId: phaseA, assigneeIds: [ownerId, memberId], leadProfileId: ownerId, acceptanceCriteria: 'Both contributors deliver one outcome' });
    }, { projectId: project.projectId, ownerId: f.accountId, memberId: person.accountId, phaseA, phaseB, milestoneId }));
    const ref = { projectId: project.projectId, taskId: task.taskId };
    await test.step('Role denial, blockers, discussion and real notification delivery', async () => {
      expect(await member.evaluate(async () => { try { await window.clientRuntime.roles.create({ displayName: 'Forbidden member role', permissions: ['read_project'] }); return false; } catch { return true; } })).toBe(true);
      await member.evaluate(async ({ projectId, taskId, blockerId, accountId }) => {
        const p = window.clientRuntime.planning;
        await p.execute({ projectId, reviewed: (await p.read(projectId)).pin, command: { action: 'start_task', taskId } });
        await p.execute({ projectId, command: { action: 'create_blocker', blocker: { id: blockerId, taskId, responsibleProfileId: accountId } }, content: { reason: 'Private missing dependency', nextAction: 'Private arrange delivery' } });
      }, { ...ref, blockerId, accountId: person.accountId });
      expect(await member.evaluate(async ({ projectId, taskId }) => { const p = window.clientRuntime.planning; try { await p.execute({ projectId, reviewed: (await p.read(projectId)).pin, command: { action: 'request_task_completion', taskId, acceptanceConfirmed: true } }); return false; } catch { return true; } }, ref)).toBe(true);
      const post = await page.evaluate(({ projectId, taskId }) => window.clientRuntime.collaboration.postComment({ projectId, taskId, text: 'Private retained integrated discussion' }), ref);
      await expect.poll(() => member.evaluate(async entryId => (await window.clientRuntime.inbox.list()).records.filter(n => n.eventType === 'task.comment' && n.recordId === entryId).length, post.entryId), { timeout: 20000 }).toBe(1);
      await member.evaluate(async ({ projectId, blockerId }) => { const p = window.clientRuntime.planning; await p.execute({ projectId, reviewed: (await p.read(projectId)).pin, command: { action: 'resolve_blocker', blockerId }, outcome: 'Private dependency received' }); }, { projectId: project.projectId, blockerId });
    });
    await test.step('Carry forward, require independent review and reject a stale approval', async () => {
      const old = await page.evaluate(async ({ projectId, taskId, phaseA, phaseB, milestoneId, reviewerId }) => {
        const p = window.clientRuntime.planning;
        await p.execute({ projectId, reviewed: (await p.read(projectId)).pin, command: { action: 'carry_task', taskId, phaseId: phaseB, milestoneId }, outcome: 'Private continue in next iteration' });
        await p.execute({ projectId, reviewed: (await p.read(projectId)).pin, command: { action: 'complete_phase', phaseId: phaseA }, outcome: 'Private first iteration learned' });
        await p.execute({ projectId, reviewed: (await p.read(projectId)).pin, command: { action: 'set_project_review', enabled: true, reviewers: [{ taskId, reviewerProfileId: reviewerId }] }, outcome: 'Private independent acceptance' });
        await p.execute({ projectId, reviewed: (await p.read(projectId)).pin, command: { action: 'request_task_completion', taskId, acceptanceConfirmed: true } });
        const old = (await p.read(projectId)).graph.tasks[0]!;
        await p.execute({ projectId, reviewed: (await p.read(projectId)).pin, command: { action: 'edit_task', taskId }, content: { title: 'Private revised shared outcome', acceptanceCriteria: 'Both contributors deliver the revised outcome' } });
        await p.execute({ projectId, reviewed: (await p.read(projectId)).pin, command: { action: 'request_task_completion', taskId, acceptanceConfirmed: true } });
        return old;
      }, { ...ref, phaseA, phaseB, milestoneId, reviewerId: successor.accountId });
      const approved = await second.evaluate(async ({ projectId, taskId, old }) => {
        const p = window.clientRuntime.planning; let staleDenied = false;
        try { await p.execute({ projectId, reviewed: (await p.read(projectId)).pin, command: { action: 'approve_task', taskId, submittedRevision: old.submittedRevision!, submittedPolicyRevision: old.submittedPolicyRevision! } }); } catch { staleDenied = true; }
        const current = (await p.read(projectId)).graph.tasks[0]!;
        await p.execute({ projectId, reviewed: (await p.read(projectId)).pin, command: { action: 'approve_task', taskId, submittedRevision: current.submittedRevision!, submittedPolicyRevision: current.submittedPolicyRevision! } });
        return { staleDenied, graph: (await p.read(projectId)).graph };
      }, { ...ref, old });
      expect(approved.staleDenied).toBe(true); expect(approved.graph.tasks).toHaveLength(1);
      expect(approved.graph.tasks[0]).toMatchObject({ id: task.taskId, state: 'done', phaseId: phaseB });
      expect(approved.graph.tasks[0]!.assigneeIds.slice().sort()).toEqual([f.accountId, person.accountId].sort());
    });
    await test.step('Closure, archive/reopen, reporting and deletion cancellation', async () => {
      const closed = await page.evaluate(async ({ projectId, phaseB, milestoneId }) => {
        const p = window.clientRuntime.planning;
        await window.clientRuntime.collaboration.postUpdate({ projectId, phaseId: phaseB, text: 'Private iteration delivered' });
        await p.execute({ projectId, reviewed: (await p.read(projectId)).pin, command: { action: 'accept_milestone', milestoneId }, outcome: 'Private accepted shared result' });
        await p.execute({ projectId, reviewed: (await p.read(projectId)).pin, command: { action: 'complete_phase', phaseId: phaseB }, outcome: 'Private second iteration complete' });
        await p.execute({ projectId, reviewed: (await p.read(projectId)).pin, command: { action: 'complete_project' }, outcome: 'Private delivery complete' });
        const closed = await p.read(projectId);
        await p.execute({ projectId, reviewed: (await p.read(projectId)).pin, command: { action: 'archive_project' } });
        let archiveDenied = false;
        try { await p.createTask({ projectId, title: 'Forbidden archived task' }); } catch { archiveDenied = true; }
        await p.execute({ projectId, reviewed: (await p.read(projectId)).pin, command: { action: 'unarchive_project' } });
        await p.execute({ projectId, reviewed: (await p.read(projectId)).pin, command: { action: 'reopen_project' } });
        const reopened = await p.read(projectId), scope = { kind: 'project' as const, projectId };
        const local = await window.clientRuntime.reporting.calculate(scope);
        await window.clientRuntime.reporting.publish(scope);
        return { closed, reopened, archiveDenied, local, published: await window.clientRuntime.reporting.read(scope) };
      }, { projectId: project.projectId, phaseB, milestoneId });
      expect(closed.archiveDenied).toBe(true); expect(closed.reopened.graph.snapshots).toEqual(closed.closed.graph.snapshots);
      expect(closed.reopened.audits.slice(0, closed.closed.audits.length)).toEqual(closed.closed.audits);
      expect(closed.local.components[0]!.result.progress).toMatchObject({ taskCount: 1, percentage: 100 });
      expect(closed.published.status).toBe('current');
      const memberCalculation = await member.evaluate(projectId => window.clientRuntime.reporting.calculate({ kind: 'project', projectId }), project.projectId);
      // Requests occur at different server times; compare every calculated field
      // while preserving their distinct, correctly labelled observation times.
      const { asOfUtc: memberTime, ...memberResult } = memberCalculation.components[0]!.result;
      const { asOfUtc: ownerTime, ...ownerResult } = closed.local.components[0]!.result;
      expect(Date.parse(memberTime)).toBeGreaterThanOrEqual(Date.parse(ownerTime));
      expect(memberResult).toEqual(ownerResult);
      await page.evaluate(() => window.clientRuntime.lifecycle.requestDeletion('Browser workspace'));
      expect(await second.evaluate(async projectId => { try { await window.clientRuntime.planning.createTask({ projectId, title: 'Forbidden during deletion' }); return false; } catch { return true; } }, project.projectId)).toBe(true);
      const exported = JSON.parse((await second.evaluate(() => window.clientRuntime.exports.generate({ acknowledgePlaintext: true }))).json);
      expect(exported.complete).toBe(true); expect(exported.tasks).toHaveLength(1); expect(exported.comments[0].text).toBe('Private retained integrated discussion');
      expect((await second.evaluate(() => window.clientRuntime.lifecycle.cancelDeletion())).state).toBe('completed');
    });
    await test.step('Logout/login and another approved device retain the same shared history', async () => {
      await member.evaluate(async ({ workspaceId, accountId, deviceId, password }) => { const c = window.clientRuntime; await c.auth.logout(); await c.auth.login({ workspaceId, accountId, deviceId }, password); }, { workspaceId: f.workspaceId, accountId: person.accountId, deviceId: person.deviceId, password: otherPassword });
      const paired = await fresh(); await open(paired);
      const begun = await paired.evaluate(async ({ workspaceId, accountId, password }) => {
        const c = window.clientRuntime, login = await c.auth.login({ workspaceId, accountId }, password);
        return { access: login.session.accessLevel, denied: (await fetch(`/v1/workspaces/${workspaceId}/projects`)).status, pairing: await c.pairing.begin() };
      }, { workspaceId: f.workspaceId, accountId: person.accountId, password: otherPassword });
      expect(begun.access).toBe('restricted'); expect(begun.denied).toBe(403);
      const claimed = await member.evaluate(operationId => window.clientRuntime.pairing.claim(operationId), begun.pairing.operationId);
      await paired.evaluate(({ operationId, fingerprint }) => window.clientRuntime.pairing.confirmRecipient(operationId, fingerprint!), claimed);
      await member.evaluate(({ operationId, fingerprint }) => window.clientRuntime.pairing.confirmApprover(operationId, fingerprint!), claimed);
      await member.route('**/v1/auth/pairing/commit', async route => { const reply = await route.fetch(); expect(reply.status()).toBe(200); await route.abort('failed'); }, { times: 1 });
      expect(await member.evaluate(async operationId => { try { await window.clientRuntime.pairing.approve(operationId); return false; } catch { return true; } }, claimed.operationId)).toBe(true);
      await member.evaluate(operationId => window.clientRuntime.pairing.approve(operationId), claimed.operationId);
      expect((await paired.evaluate(operationId => window.clientRuntime.pairing.resumeRecipient(operationId, 'Second member device'), claimed.operationId)).state).toBe('content_ready');
      expect((await paired.evaluate(projectId => window.clientRuntime.planning.read(projectId), project.projectId)).graph.tasks[0]!.state).toBe('done');
    });
    const resetMember = await fresh();
    await test.step('Owner resets member credentials; revoked devices lose access', async () => {
      const resetId = randomUUID(); f.recoveryOperations.add(resetId);
      const issued = await page.evaluate(({ accountId, resetId }) => window.clientRuntime.recoveries.issueReset(accountId, resetId), { accountId: person.accountId, resetId });
      await open(resetMember);
      const begun = await resetMember.evaluate(({ workspaceId, code }) => window.clientRuntime.recoveries.beginReset(workspaceId, code), { workspaceId: f.workspaceId, code: issued.code });
      await page.evaluate(operation => window.clientRuntime.recoveries.claim(operation!), begun.operation);
      const prepared = await resetMember.evaluate(async localId => {
        const c = window.clientRuntime, nextPassword = 'A reset integrated member password 280913';
        const prepared = await c.recoveries.prepare(localId, nextPassword, nextPassword);
        await c.recoveries.confirmRecipient(localId, prepared.fingerprint!); return prepared;
      }, begun.localId);
      await page.evaluate(({ operation, fingerprint }) => window.clientRuntime.recoveries.approve(operation!, fingerprint!), prepared);
      const delivered = await resetMember.evaluate(async ({ localId, workspaceId, accountId }) => {
        const c = window.clientRuntime, pending = await c.recoveries.resume(localId);
        await c.auth.login({ workspaceId, accountId, deviceId: pending.deviceId! }, 'A reset integrated member password 280913'); return c.recoveries.resume(localId);
      }, { localId: begun.localId, workspaceId: f.workspaceId, accountId: person.accountId });
      expect(delivered.access).toBe('content_ready');
      expect(await member.evaluate(async workspaceId => (await fetch(`/v1/workspaces/${workspaceId}/projects`)).status, f.workspaceId)).toBe(401);
      expect((await resetMember.evaluate(({ projectId, taskId }) => window.clientRuntime.collaboration.read({ projectId, taskId, kind: 'comment' }), ref)).records[0]!.text).toBe('Private retained integrated discussion');
    });
    const recoveredOwner = await fresh();
    await test.step('Owner phrase recovery retains history and equal Owner removes the recovered Owner', async () => {
      const operationId = randomUUID(); f.recoveryOperations.add(operationId); await open(recoveredOwner);
      const recovered = await recoveredOwner.evaluate(async ({ kit, phrase, operationId }) => {
        const c = window.clientRuntime, nextPassword = 'A recovered integrated owner password 372951';
        await c.recoveries.beginPhrase(kit, operationId); await c.recoveries.provePhrase(operationId, phrase);
        const nextPhrase = await window.ukda.recovery.newOwnerPhrase(), positions = [2, 11, 21];
        const prepared = await c.recoveries.prepare(operationId, nextPassword, nextPassword, { phrase: nextPhrase, positions, answers: positions.map(i => nextPhrase.split(' ')[i]!) });
        await c.recoveries.confirmRecipient(operationId, prepared.fingerprint!); await c.recoveries.approvePhrase(operationId, prepared.fingerprint!, phrase);
        const pending = await c.recoveries.resume(operationId); await c.auth.login({ workspaceId: kit.workspaceId, accountId: kit.accountId, deviceId: pending.deviceId! }, nextPassword);
        return c.recoveries.resume(operationId, nextPhrase);
      }, { kit: { origin, workspaceId: f.workspaceId, accountId: f.accountId, genesisFingerprint: f.receipt.genesisFingerprint }, phrase: f.phrase, operationId });
      expect(recovered.access).toBe('content_ready');
      expect((await recoveredOwner.evaluate(projectId => window.clientRuntime.planning.read(projectId), project.projectId)).graph.tasks[0]!.state).toBe('done');
      expect(await page.evaluate(async workspaceId => (await fetch(`/v1/workspaces/${workspaceId}/projects`)).status, f.workspaceId)).toBe(401);
      await second.evaluate(accountId => window.clientRuntime.accessChanges.remove({ accountId }), f.accountId);
      expect(await recoveredOwner.evaluate(async workspaceId => (await fetch(`/v1/workspaces/${workspaceId}/projects`)).status, f.workspaceId)).toBe(401);
      await second.evaluate(() => window.clientRuntime.accessChanges.refreshKeys());
      const exported = JSON.parse((await second.evaluate(() => window.clientRuntime.exports.generate({ acknowledgePlaintext: true }))).json);
      expect(exported.complete).toBe(true); expect(exported.tasks[0].title).toBe('Private revised shared outcome');
      expect(exported.comments[0].text).toBe('Private retained integrated discussion'); expect(exported.history.planning.length).toBeGreaterThan(20);
    });
  } finally {
    await Promise.allSettled(pages.map(actor => actor.evaluate(() => window.clientRuntime?.close())));
    await Promise.allSettled(contexts.map(context => context.close())); await f.close();
  }
});
