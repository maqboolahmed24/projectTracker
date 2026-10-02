import { expect, test, type Page } from '@playwright/test';
import { randomUUID } from 'node:crypto';
import { authenticationFixture, origin, password } from './authentication-fixture.js';
import type { ClientRuntime } from '../../src/client/runtime.js';

declare global { interface Window { clientRuntime: ClientRuntime } }
type Fixture = Awaited<ReturnType<typeof authenticationFixture>>;
const otherPassword = 'A retained project password 539820';
async function ownerPage(page: Page, f: Fixture) {
  await page.goto('/'); await page.waitForFunction(() => !!window.ukda);
  await page.evaluate(async ({ workspaceId, accountId, deviceId, wrapper, operationId, genesis, receipt, trustedServiceKeys, password }) => {
    const c = window.ukda, devices = await c.IndexedDeviceStore.open(); await devices.stage(wrapper, operationId);
    await devices.commit(operationId, { workspaceId, accountId, deviceId, operationId, credentialGeneration: '1' }); devices.close();
    const pins = await c.IndexedPairingStore.open(location.origin); await c.seedActivationPin(pins, genesis, receipt); pins.close();
    window.clientRuntime = await c.openClient({ trustedServiceKeys }); await window.clientRuntime.auth.login({ workspaceId, accountId, deviceId }, password);
    await window.clientRuntime.accessChanges.refreshKeys();
  }, { workspaceId: f.workspaceId, accountId: f.accountId, deviceId: f.deviceId, wrapper: f.wrapper, operationId: f.operationId,
    genesis: f.genesis, receipt: f.receipt, trustedServiceKeys: f.trustedServiceKeys, password });
}
async function enrol(owner: Page, recipient: Page, f: Fixture, asOwner = false, projectIds: string[] = []) {
  const accountId = randomUUID(), operationId = randomUUID();
  const issued = await owner.evaluate(({ accountId, operationId, roleId, asOwner, projectIds }) => window.clientRuntime.enrolments.issueJoin({
    accountId, operationId, kind: asOwner ? 'join_owner' : 'join_member', roleId, projectIds, displayName: 'Private pending project profile' }),
  { accountId, operationId, roleId: asOwner ? f.genesis.body.roles.owner : f.genesis.body.roles.member, asOwner, projectIds });
  await recipient.goto(origin); await recipient.waitForFunction(() => !!window.ukda);
  const begun = await recipient.evaluate(async ({ workspaceId, code, genesisFingerprint, trustedServiceKeys }) => {
    window.clientRuntime = await window.ukda.openClient({ trustedServiceKeys }); return window.clientRuntime.enrolments.beginJoin({ workspaceId, code, genesisFingerprint });
  }, { workspaceId: f.workspaceId, code: issued.code, genesisFingerprint: f.receipt.genesisFingerprint, trustedServiceKeys: f.trustedServiceKeys });
  await owner.evaluate((operation) => window.clientRuntime.enrolments.claim(operation!), begun.operation);
  const prepared = await recipient.evaluate(async ({ localId, password, asOwner }) => {
    const phrase = asOwner ? await window.ukda.recovery.newOwnerPhrase() : null, positions = [1, 11, 20];
    const result = await window.clientRuntime.enrolments.prepare(localId, password, password, 'Private confirmed project profile',
      phrase ? { phrase, positions, answers: positions.map((index) => phrase.split(' ')[index]!) } : undefined);
    await window.clientRuntime.enrolments.confirmRecipient(localId, result.fingerprint!); return { ...result, phrase };
  }, { localId: begun.localId, password: otherPassword, asOwner });
  await owner.evaluate(({ operation, fingerprint }) => window.clientRuntime.enrolments.approve(operation!, fingerprint!), prepared);
  const result = await recipient.evaluate(async ({ localId, workspaceId, accountId, password, phrase }) => {
    const pending = await window.clientRuntime.enrolments.resume(localId); await window.clientRuntime.auth.login({ workspaceId, accountId, deviceId: pending.deviceId! }, password);
    const result = await window.clientRuntime.enrolments.resume(localId, phrase ?? undefined); return { deviceId: result.deviceId!, access: result.access };
  }, { localId: begun.localId, workspaceId: f.workspaceId, accountId, password: otherPassword, phrase: prepared.phrase });
  expect(result.access).toBe('content_ready'); return { accountId, deviceId: result.deviceId, phrase: prepared.phrase };
}


test('CP07: manual wave and milestone completion preserves encrypted closing snapshots through archive, reopen and later edits', async ({ page }) => {
  test.setTimeout(60000);
  const f = await authenticationFixture(), phaseId = randomUUID(), milestoneId = randomUUID();
  try {
    await ownerPage(page, f); const project = await page.evaluate(() => window.clientRuntime.projectCreation.create({ name: 'Private browser planning project' }));
    const uploads: string[] = []; page.on('request', (request) => { if (request.url().endsWith('/v1/work/planning/save')) uploads.push(request.postData() ?? ''); });
    const result = await page.evaluate(async ({ projectId, phaseId, milestoneId }) => {
      const planning = window.clientRuntime.planning;
      await planning.execute({ reviewed: (await planning.read(projectId)).pin, projectId, command: { action: 'start_project' } });
      await planning.execute({ projectId, command: { action: 'create_phase', phase: { id: phaseId, displayOrder: 0, leadProfileId: null } },
        content: { name: 'Private browser discovery', objective: 'Understand customer needs', startDate: '2026-09-01', dueDate: '2026-09-20', completionCriteria: 'A reviewed brief' } });
      await planning.execute({ reviewed: (await planning.read(projectId)).pin, projectId, command: { action: 'start_phase', phaseId } });
      await planning.execute({ projectId, command: { action: 'create_milestone', milestone: { id: milestoneId, phaseId, ownerProfileId: null } }, content: { name: 'Private checkpoint' } });
      let incompleteRejected = false; try { await planning.execute({ reviewed: (await planning.read(projectId)).pin, projectId, command: { action: 'complete_phase', phaseId }, outcome: 'Premature finish' }); } catch { incompleteRejected = true; }
      await planning.execute({ reviewed: (await planning.read(projectId)).pin, projectId, command: { action: 'accept_milestone', milestoneId }, outcome: 'Private manual acceptance' });
      await planning.execute({ reviewed: (await planning.read(projectId)).pin, projectId, command: { action: 'complete_phase', phaseId }, outcome: 'Private wave learning' });
      await planning.execute({ reviewed: (await planning.read(projectId)).pin, projectId, command: { action: 'complete_project' }, outcome: 'Private project conclusion' });
      const closed = await planning.read(projectId);
      await planning.execute({ reviewed: (await planning.read(projectId)).pin, projectId, command: { action: 'archive_project' } });
      let archivedRejected = false; try { await planning.execute({ reviewed: (await planning.read(projectId)).pin, projectId, command: { action: 'edit_project', patch: {} }, content: { name: 'Forbidden archived edit' } }); } catch { archivedRejected = true; }
      await planning.execute({ reviewed: (await planning.read(projectId)).pin, projectId, command: { action: 'unarchive_project' } }); await planning.execute({ reviewed: (await planning.read(projectId)).pin, projectId, command: { action: 'reopen_project' } });
      await planning.execute({ reviewed: (await planning.read(projectId)).pin, projectId, command: { action: 'edit_project', patch: { phaseLabel: 'phase' } }, content: { name: 'Private changed project' } });
      const reopened = await planning.read(projectId); return { incompleteRejected, archivedRejected, closed, reopened };
    }, { projectId: project.projectId, phaseId, milestoneId });
    expect(result.incompleteRejected).toBe(true); expect(result.archivedRejected).toBe(true);
    expect(result.closed.graph.project.state).toBe('complete'); expect(result.closed.graph.snapshots).toHaveLength(3);
    expect(result.reopened.graph.snapshots).toEqual(result.closed.graph.snapshots); expect(result.reopened.graph.project).toMatchObject({ state: 'active', archived: false, phaseLabel: 'phase' });
    expect(result.reopened.records.find((record) => record.kind === 'project')!.content.name).toBe('Private changed project');
    expect(result.reopened.audits.slice(0, result.closed.audits.length)).toEqual(result.closed.audits);
    expect(result.closed.audits.at(-1)!.data.snapshotContents.find((record) => record.kind === 'project')!.content.name).toBe('Private browser planning project');
    expect(uploads.length).toBe(11); expect(uploads.every((body) => !['Private', 'Understand customer needs', 'A reviewed brief'].some((text) => body.includes(text)))).toBe(true);
  } finally { await Promise.allSettled([page.evaluate(() => window.clientRuntime?.close())]); await f.close(); }
});

test('CP07: lost planning save resumes after reload once; an unsent stale draft cannot overwrite later work and Forget clears drafts', async ({ page }) => {
  const f = await authenticationFixture(), operationId = randomUUID(), staleId = randomUUID(), phaseId = randomUUID();
  try {
    await ownerPage(page, f); const project = await page.evaluate(() => window.clientRuntime.projectCreation.create({ name: 'Private retry project' })); let lost = false;
    await page.route('**/v1/work/planning/save', async (route) => { const response = await route.fetch(); expect(response.status()).toBe(200); lost = true; await route.abort('failed'); }, { times: 1 });
    expect(await page.evaluate(async ({ projectId, operationId, phaseId }) => { try { await window.clientRuntime.planning.execute({ projectId, operationId,
      command: { action: 'create_phase', phase: { id: phaseId, displayOrder: 0, leadProfileId: null } }, content: { name: 'Private retry wave' } }); return false; } catch { return true; } },
    { projectId: project.projectId, operationId, phaseId })).toBe(true); expect(lost).toBe(true);
    await page.reload(); await page.waitForFunction(() => !!window.ukda);
    const resumed = await page.evaluate(async ({ workspaceId, accountId, deviceId, password, trustedServiceKeys, operationId, projectId }) => {
      window.clientRuntime = await window.ukda.openClient({ trustedServiceKeys }); await window.clientRuntime.auth.login({ workspaceId, accountId, deviceId }, password);
      const first = await window.clientRuntime.planning.resume(operationId), again = await window.clientRuntime.planning.resume(operationId), read = await window.clientRuntime.planning.read(projectId);
      return { first, again, read };
    }, { workspaceId: f.workspaceId, accountId: f.accountId, deviceId: f.deviceId, password, trustedServiceKeys: f.trustedServiceKeys, operationId, projectId: project.projectId });
    expect(resumed.first.receipt).toEqual(resumed.again.receipt); expect(resumed.read.graph.phases).toHaveLength(1);
    expect(resumed.read.records.find((record) => record.id === phaseId)!.content.name).toBe('Private retry wave');
    await page.route('**/v1/work/planning/save', (route) => route.abort('failed'), { times: 1 });
    expect(await page.evaluate(async ({ projectId, operationId }) => { try { await window.clientRuntime.planning.execute({ reviewed: (await window.clientRuntime.planning.read(projectId)).pin, projectId, operationId, command: { action: 'edit_project', patch: {} },
      content: { name: 'A stale private edit' } }); return false; } catch { return true; } }, { projectId: project.projectId, operationId: staleId })).toBe(true);
    const current = await page.evaluate(async ({ projectId, staleId }) => {
      await window.clientRuntime.planning.execute({ reviewed: (await window.clientRuntime.planning.read(projectId)).pin, projectId, command: { action: 'edit_project', patch: {} }, content: { name: 'The later private edit' } });
      let staleRejected = false; try { await window.clientRuntime.planning.resume(staleId); } catch { staleRejected = true; }
      return { staleRejected, view: await window.clientRuntime.planning.read(projectId) };
    }, { projectId: project.projectId, staleId });
    expect(current.staleRejected).toBe(true); expect(current.view.records.find((record) => record.kind === 'project')!.content.name).toBe('The later private edit');
    expect(await page.evaluate(async ({ workspaceId, accountId, deviceId, operationId, staleId }) => {
      await window.clientRuntime.auth.forget({ workspaceId, accountId, deviceId }); const store = await window.ukda.IndexedPlanningStore.open(location.origin);
      try { return await store.get(workspaceId, operationId) === undefined && await store.get(workspaceId, staleId) === undefined; } finally { store.close(); }
    }, { workspaceId: f.workspaceId, accountId: f.accountId, deviceId: f.deviceId, operationId, staleId })).toBe(true);
  } finally { await Promise.allSettled([page.evaluate(() => window.clientRuntime?.close())]); await f.close(); }
});

test('CP07: restricted licences retain readable planning history but block new encrypted planning writes', async ({ page }) => {
  const f = await authenticationFixture();
  try {
    await ownerPage(page, f); const project = await page.evaluate(() => window.clientRuntime.projectCreation.create({ name: 'Private restricted planning' }));
    await page.evaluate(async (projectId) => window.clientRuntime.planning.execute({ reviewed: (await window.clientRuntime.planning.read(projectId)).pin, projectId, command: { action: 'start_project' } }), project.projectId);
    await f.restrictLicence(); let saves = 0; page.on('request', (request) => { if (request.url().endsWith('/v1/work/planning/save')) saves++; });
    const result = await page.evaluate(async (projectId) => {
      const read = await window.clientRuntime.planning.read(projectId); let rejected = false;
      try { await window.clientRuntime.planning.execute({ reviewed: (await window.clientRuntime.planning.read(projectId)).pin, projectId, command: { action: 'edit_project', patch: {} }, content: { name: 'Restricted write blocked' } }); } catch { rejected = true; }
      return { read, rejected };
    }, project.projectId);
    expect(result.rejected).toBe(true); expect(saves).toBe(0); expect(result.read.records.find((record) => record.kind === 'project')!.content.name).toBe('Private restricted planning');
    expect(result.read.graph.project.state).toBe('active');
  } finally { await Promise.allSettled([page.evaluate(() => window.clientRuntime?.close())]); await f.close(); }
});

test('CP07: shared assigned Todo work blocks closure, carries without losing identity, reopens acceptance and cancels only through explicit disposition', async ({ page, browser }) => {
  test.setTimeout(60000);
  const f = await authenticationFixture(), memberContext = await browser.newContext({ ignoreHTTPSErrors: true }), member = await memberContext.newPage(),
    phaseA = randomUUID(), phaseB = randomUUID(), milestoneId = randomUUID(), taskId = randomUUID();
  try {
    await ownerPage(page, f); const project = await page.evaluate(() => window.clientRuntime.projectCreation.create({ name: 'Private shared planning project' }));
    const target = await enrol(page, member, f, false, [project.projectId]);
    const result = await page.evaluate(async ({ projectId, ownerId, memberId, phaseA, phaseB, milestoneId, taskId }) => {
      const planning = window.clientRuntime.planning;
      await planning.execute({ reviewed: (await planning.read(projectId)).pin, projectId, command: { action: 'start_project' } });
      for (const [id, displayOrder] of [[phaseA, 0], [phaseB, 1]] as const) {
        await planning.execute({ projectId, command: { action: 'create_phase', phase: { id, displayOrder, leadProfileId: null } }, content: { name: `Private shared wave ${displayOrder}` } });
        await planning.execute({ reviewed: (await planning.read(projectId)).pin, projectId, command: { action: 'start_phase', phaseId: id } });
      }
      await planning.execute({ projectId, command: { action: 'create_milestone', milestone: { id: milestoneId, phaseId: phaseB, ownerProfileId: null } }, content: { name: 'Private destination checkpoint' } });
      await planning.execute({ reviewed: (await planning.read(projectId)).pin, projectId, command: { action: 'accept_milestone', milestoneId }, outcome: 'Initial empty checkpoint accepted' });
      await planning.execute({ projectId, command: { action: 'create_task', task: { id: taskId, phaseId: phaseA, milestoneId: null, assigneeIds: [ownerId, memberId], leadProfileId: ownerId } },
        content: { title: 'Private shared delivery', description: 'One task completed together', dueDate: '2026-10-01', acceptanceCriteria: 'Working starter' } });
      const prepared = await planning.read(projectId); let phaseDenied = false, projectDenied = false;
      try { await planning.execute({ reviewed: (await planning.read(projectId)).pin, projectId, command: { action: 'complete_phase', phaseId: phaseA }, outcome: 'Unfinished task cannot finish a wave' }); } catch { phaseDenied = true; }
      try { await planning.execute({ reviewed: (await planning.read(projectId)).pin, projectId, command: { action: 'complete_project' }, outcome: 'Unfinished task cannot finish a project' }); } catch { projectDenied = true; }
      await planning.execute({ reviewed: (await planning.read(projectId)).pin, projectId, command: { action: 'carry_task', taskId, phaseId: phaseB, milestoneId }, outcome: 'Carry existing work into next iteration' });
      const carried = await planning.read(projectId);
      await planning.execute({ reviewed: (await planning.read(projectId)).pin, projectId, command: { action: 'cancel_phase', phaseId: phaseB, tasks: [{ taskId, action: 'cancel' }], milestones: [{ milestoneId, action: 'cancel' }] }, outcome: 'Explicit cancellation of remaining scope' });
      const cancelled = await planning.read(projectId);
      await planning.execute({ reviewed: (await planning.read(projectId)).pin, projectId, command: { action: 'complete_phase', phaseId: phaseA }, outcome: 'Original wave ended after carrying work' });
      await planning.execute({ reviewed: (await planning.read(projectId)).pin, projectId, command: { action: 'complete_project' }, outcome: 'Project closed after explicit dispositions' });
      return { prepared, carried, cancelled, phaseDenied, projectDenied, closed: await planning.read(projectId) };
    }, { projectId: project.projectId, ownerId: f.accountId, memberId: target.accountId, phaseA, phaseB, milestoneId, taskId });
    expect(result.phaseDenied).toBe(true); expect(result.projectDenied).toBe(true); expect(result.prepared.graph.tasks).toHaveLength(1);
    expect(result.prepared.graph.tasks[0]).toMatchObject({ id: taskId, state: 'todo', leadProfileId: f.accountId });
    expect([...result.prepared.graph.tasks[0]!.assigneeIds].sort()).toEqual([f.accountId, target.accountId].sort());
    expect(result.carried.graph.tasks).toHaveLength(1); expect(result.carried.graph.tasks[0]).toMatchObject({ id: taskId, phaseId: phaseB, milestoneId, leadProfileId: f.accountId });
    expect(result.carried.graph.tasks[0]!.assigneeIds).toEqual(result.prepared.graph.tasks[0]!.assigneeIds);
    expect(result.carried.graph.milestones[0]!.state).toBe('open'); expect(result.carried.graph.snapshots[0]!.milestones[0]!.state).toBe('accepted');
    expect(result.carried.graph.movements[0]).toMatchObject({ taskId, fromPhaseId: phaseA, toPhaseId: phaseB });
    expect(result.cancelled.graph.tasks[0]!.state).toBe('cancelled'); expect(result.closed.graph.project.state).toBe('complete');
    expect(result.cancelled.records.find((r) => r.id === taskId)!.content).toEqual(result.prepared.records.find((r) => r.id === taskId)!.content);
    const memberView = await member.evaluate((projectId) => window.clientRuntime.planning.read(projectId), project.projectId);
    expect(memberView.records.find((r) => r.id === taskId)!.content.title).toBe('Private shared delivery'); expect(memberView.graph.tasks).toHaveLength(1);
  } finally {
    await Promise.allSettled([page.evaluate(() => window.clientRuntime?.close()), member.evaluate(() => window.clientRuntime?.close())]);
    await memberContext.close(); await f.close();
  }
});
