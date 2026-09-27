import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { IDBFactory } from 'fake-indexeddb';
import { base64urlDecode, canonicalJson, digestObject, encryptContent, signObject } from '../src/shared/crypto.js';
import { prepareCollaboration, prepareCollaborationUpgrade, readCollaboration, verifyCollaborationUpgradeTargets } from '../src/client/collaboration-crypto.js';
import { CollaborationController, type CollaborationTransport } from '../src/client/collaboration-controller.js';
import { IndexedCollaborationStore } from '../src/client/collaboration-store.js';
import { IndexedPlanningStore } from '../src/client/planning-store.js';
import { IndexedPairingStore } from '../src/client/pairing.js';
import { refreshAccessKeys } from '../src/client/access-change-crypto.js';
import type { AuthController } from '../src/client/auth-controller.js';
import { collaborationClientFixture } from './collaboration-client-fixture.js';
import { origin } from './project-create-client-fixture.js';
import { signedUpgradeStart, signedUpgradeFinish } from './upgrade-client-fixture.js';
import { collaborationMutation, verifyCollaborationEntry } from '../src/shared/collaboration.js';
import { openVerifiedPlanning, planningSecurityResolver } from '../src/client/planning-crypto.js';
import type { UpgradeRecordRef } from '../src/shared/encrypted-upgrades.js';

test('CP11 collaboration: schema upgrades retain original comments, planning outcomes and moderation; later hides preserve pins and valid-signer substitution fails',async()=>{
  const f=await collaborationClientFixture(),entryId=randomUUID(),
    post=await prepareCollaboration({...await f.input(entryId,'comment'),command:{action:'post_comment',entryId,taskId:f.taskId},text:'Original private comment'},f.owner.bundle);
  await f.apply(post);await f.command({action:'start_project'});
  const cancelled=await f.command({action:'cancel_task',taskId:f.taskId},'Original cancellation outcome'),outcomeId=cancelled.outcome!.id,
    outcome=(await readCollaboration(await f.readInput([(await f.entry(outcomeId))!]),f.owner.bundle)).records[0]!;
  await f.apply(await prepareCollaboration({...await f.input(outcomeId,'update'),command:{action:'hide_update',entryId:outcomeId,expectedRevision:outcome.revision,previousHead:outcome.head,originalDigest:outcome.originalDigest},reason:'Retained original moderation'},f.owner.bundle));
  const before=await readCollaboration(await f.readInput([(await f.entry(entryId))!,(await f.entry(outcomeId))!],true),f.owner.bundle),
    oldComment=canonicalJson((await f.entry(entryId))!.origin),oldOutcome=canonicalJson((await f.entry(outcomeId))!),oldPlanning=canonicalJson((await f.planning.context()).history),
    sources:UpgradeRecordRef[]=[];
  for(const [id,kind] of [[entryId,'comment'],[outcomeId,'update']] as const) {
    const input=await f.input(id,kind),entry=await verifyCollaborationEntry(input.context.entry,input.context.planning,planningSecurityResolver(f.planning.f.history,f.planning.f.state)),h=entry.currentHeader;
    sources.push({kind,id,projectId:f.planning.projectId,revision:entry.revision,contentRevision:null,envelopeRevision:h.revision,schema:1,keyEpoch:h.keyEpoch,digest:await digestObject(entry.current)});
  }
  const migration=await signedUpgradeStart(f.planning.f,sources);f.planning.upgrade(3);
  const input=await f.input(entryId,'comment'),upgrade=await prepareCollaborationUpgrade({...input,...migration},f.owner.bundle),
    opened=await openVerifiedPlanning({...input,context:input.context.planning},f.owner.bundle),forged=structuredClone(upgrade),
    key=base64urlDecode(opened.ring.find(key=>key.epoch===input.context.binding.keyEpoch)!.key,32),signing=base64urlDecode(f.owner.bundle.signingPrivateKey,64);
  try {
    forged.content=await encryptContent(forged.content!.header,{text:'Substituted private comment'},key,signing);
    const item=forged.upgradeItems![0]!;item.envelope=forged.content;item.target.digest=await digestObject(forged.content);
    if(forged.mutation.body.purpose!=='ukda.collaboration.v2')throw new Error('Expected modern upgrade');
    forged.mutation.body.contentDigest=item.target.digest;forged.mutation.body.upgrade!.items[0]!.target.digest=item.target.digest;
    forged.mutation=collaborationMutation.parse(await signObject(forged.mutation.body,signing));
    await assert.rejects(readCollaboration(await f.readInput([{...(await f.entry(entryId))!,events:[forged]}]),f.owner.bundle));
  }finally{key.fill(0);signing.fill(0);}
  await f.apply(upgrade);
  await f.apply(await prepareCollaborationUpgrade({...await f.input(outcomeId,'update'),...migration},f.owner.bundle));
  const targets=[...await verifyCollaborationUpgradeTargets(await f.input(entryId,'comment'),f.owner.bundle),...await verifyCollaborationUpgradeTargets(await f.input(outcomeId,'update'),f.owner.bundle)];
  await signedUpgradeFinish(f.planning.f,targets);
  const read=await readCollaboration({...await f.readInput([(await f.entry(entryId))!,(await f.entry(outcomeId))!],true),entryPins:before.records.map(row=>row.pin)},f.owner.bundle);
  assert.equal(read.records[0]!.text,'Original private comment');assert.equal(read.records[0]!.revision,'2');assert.equal(read.records[1]!.revision,'3');
  assert.equal(read.records[1]!.moderation!.reason,'Retained original moderation');assert.equal(canonicalJson((await f.entry(entryId))!.origin),oldComment);
  const {events:_events,...legacyOutcome}=(await f.entry(outcomeId))!;assert.equal(canonicalJson(legacyOutcome),oldOutcome);
  assert.equal(canonicalJson((await f.planning.context()).history),oldPlanning);
  const current=read.records[0]!;
  await f.apply(await prepareCollaboration({...await f.input(entryId,'comment'),entryPin:current.pin,command:{action:'hide_comment',entryId,expectedRevision:current.revision,previousHead:current.head,originalDigest:current.originalDigest},reason:'Moderation after representation upgrade'},f.owner.bundle));
  const latest=(await readCollaboration({...await f.readInput([(await f.entry(entryId))!],true),entryPins:[current.pin]},f.owner.bundle)).records[0]!;
  assert.equal(latest.revision,'3');assert.equal(latest.text,current.text);assert.equal(latest.moderation!.reason,'Moderation after representation upgrade');
  const rolledBack={...(await f.entry(entryId))!,events:[]};
  await assert.rejects(readCollaboration({...await f.readInput([rolledBack],true),entryPins:[latest.pin]},f.owner.bundle));
});

test('CP09 client: independent encrypted posts survive a changed planning head, corrections append, and moderation preserves original with rollback pins', async () => {
  const f = await collaborationClientFixture(), firstId = randomUUID(), secondId = randomUUID(),
    first = await prepareCollaboration({ ...await f.input(firstId, 'comment'), command: { action: 'post_comment', entryId: firstId, taskId: f.taskId }, text: 'Private initial comment' }, f.owner.bundle),
    second = await prepareCollaboration({ ...await f.input(secondId, 'comment'), command: { action: 'post_comment', entryId: secondId, taskId: f.taskId }, text: 'Private correction as new comment' }, f.owner.bundle);
  await f.command({ action: 'start_project' }); await f.apply(first); await f.apply(second);
  assert.equal(f.records.size, 2); assert.equal(canonicalJson(first).includes('Private'), false);
  const visible = await readCollaboration(await f.readInput([...f.records.values()]), f.owner.bundle);
  assert.equal(visible.records[0]!.text, 'Private initial comment'); assert.equal(visible.records[1]!.text, 'Private correction as new comment');
  const entry = visible.records[0]!, original = canonicalJson(f.records.get(firstId)),
    hidden = await prepareCollaboration({ ...await f.input(firstId, 'comment'), entryPin: entry.pin,
      command: { action: 'hide_comment', entryId: firstId, expectedRevision: '1', previousHead: entry.head, originalDigest: entry.originalDigest }, reason: 'Private retained moderation reason' }, f.owner.bundle);
  assert.equal(hidden.content, null); assert.equal(canonicalJson(hidden).includes('Private'), false); await f.apply(hidden);
  assert.equal(canonicalJson({ ...f.records.get(firstId)!, moderation: null }), original);
  const history = await readCollaboration({ ...await f.readInput([f.records.get(firstId)!], true), entryPins: [entry.pin] }, f.owner.bundle);
  assert.equal(history.records[0]!.text, 'Private initial comment'); assert.equal(history.records[0]!.moderation!.reason, 'Private retained moderation reason');
  await assert.rejects(readCollaboration(await f.readInput([f.records.get(firstId)!]), f.owner.bundle));
  await assert.rejects(readCollaboration({ ...await f.readInput([{ ...f.records.get(firstId)!, moderation: null }], true), entryPins: [history.records[0]!.pin] }, f.owner.bundle));
  const tampered = structuredClone(first); tampered.content!.header.recordId = randomUUID();
  await assert.rejects(readCollaboration(await f.readInput([{ origin: { kind: 'post', payload: tampered }, moderation: null }]), f.owner.bundle));
  await assert.rejects(prepareCollaboration({ ...await f.input(randomUUID(), 'comment'), command: { action: 'post_comment', entryId: randomUUID(), taskId: f.taskId }, text: ' ' }, f.owner.bundle));
});

test('CP09 client: archived planning outcomes remain readable and cryptographically unchanged after moderation', async () => {
  const f = await collaborationClientFixture(); await f.command({ action: 'start_project' });
  await f.command({ action: 'cancel_task', taskId: f.taskId }, 'Private task cancellation');
  const closed = await f.command({ action: 'complete_project' }, 'Private original closing outcome'), outcomeId = closed.outcome!.id;
  await f.command({ action: 'archive_project' });
  const originalPlanning = await f.planning.context(), entry = (await readCollaboration(await f.readInput([(await f.entry(outcomeId))!]), f.owner.bundle)).records[0]!;
  const payload = await prepareCollaboration({ ...await f.input(outcomeId, 'update'), command: { action: 'hide_update', entryId: outcomeId, expectedRevision: '1', previousHead: entry.head, originalDigest: entry.originalDigest }, reason: 'Private outcome moderation' }, f.owner.bundle);
  await f.apply(payload); const read = await readCollaboration(await f.readInput([(await f.entry(outcomeId))!], true), f.owner.bundle);
  assert.equal(read.records[0]!.text, 'Private original closing outcome'); assert.equal(read.records[0]!.moderation!.reason, 'Private outcome moderation');
  assert.equal(canonicalJson((await f.planning.context()).history), canonicalJson(originalPlanning.history));
  assert.equal(canonicalJson((await f.planning.context()).outcomes), canonicalJson(originalPlanning.outcomes));
  const entryId = randomUUID();
  await assert.rejects(prepareCollaboration({ ...await f.input(entryId, 'update'), command: { action: 'post_update', entryId, phaseId: null }, text: 'Archived append denied' }, f.owner.bundle));
});

test('CP09 controller: lost reply reloads exact encrypted post once, validates receipt, and Forget removes corrupt pending requests', async () => {
  const f = await collaborationClientFixture(), factory = new IDBFactory(), name = randomUUID(), pins = await IndexedPairingStore.open(origin, randomUUID(), factory), planningPins = await IndexedPlanningStore.open(origin, randomUUID(), factory);
  await pins.recordVerifiedHistory(f.planning.f.history);
  let operations = await IndexedCollaborationStore.open(origin, name, factory), saves = 0, lost = true;
  const actor = { workspaceId: f.planning.f.workspaceId, accountId: f.owner.accountId, deviceId: f.owner.deviceId },
    auth = { origin, current: () => ({ localAccess: 'unlocked', session: { ...actor, credentialGeneration: '1', sessionGeneration: '1', dataGeneration: '1' } }),
      worker: { readCollaboration: (input: Parameters<typeof readCollaboration>[0]) => readCollaboration(input, f.owner.bundle),
        prepareCollaboration: (input: Parameters<typeof prepareCollaboration>[0]) => prepareCollaboration(input, f.owner.bundle) } } as unknown as AuthController,
    transport: CollaborationTransport = { origin, context: (ref) => f.context(ref.entryId, ref.kind, ref.operationId),
      status: async (ref) => ({ state: f.receipts.has(ref.operationId) ? 'completed' : 'absent', receipt: f.receipts.get(ref.operationId) ?? null }),
      save: async (payload) => { saves++; assert.equal(canonicalJson((await operations.get(actor.workspaceId, payload.mutation.body.binding.operationId))?.payload), canonicalJson(payload));
        const receipt = await f.apply(payload); if (lost) { lost = false; throw new Error('Lost comment response'); } return { state: 'completed', receipt }; },
      history: async (ref) => ({ planning: await f.planning.context(ref.operationId), entry: (await f.entry(ref.entryId))! }),
      list: async request => ({ planning: await f.planning.context(), entries: [...f.records.values()].filter(entry => request.includeHidden || !entry.moderation),
        anchor: await digestObject({ids:[...f.records.keys()],includeHidden:request.includeHidden === true}), nextCursor: null, complete: true }) },
    security = { history: async () => ({ genesis: f.planning.f.history.genesis, transitions: f.planning.f.history.transitions, anchor: f.planning.f.history.expected, current: f.planning.f.history.expected }) },
    access = { refreshKeys: () => refreshAccessKeys({ history: f.planning.f.history, delivery: { ...actor, current: f.planning.f.history.expected, materials: f.planning.f.materials } }, f.owner.bundle) };
  let controller = new CollaborationController(auth, transport, operations, pins, planningPins, access, security); const operationId = randomUUID();
  await assert.rejects(controller.postComment({ projectId: f.planning.projectId, taskId: f.taskId, operationId, text: 'Private durable post' }), /Lost comment response/);
  const pending = await operations.get(actor.workspaceId, operationId); assert.ok(pending); assert.equal(canonicalJson(pending).includes('Private'), false);
  operations.close(); operations = await IndexedCollaborationStore.open(origin, name, factory); controller = new CollaborationController(auth, transport, operations, pins, planningPins, access, security);
  const first = await controller.resume(operationId), again = await controller.resume(operationId); assert.deepEqual(first.receipt, again.receipt); assert.equal(saves, 1);
  const read = await controller.read({ projectId: f.planning.projectId, kind: 'comment', taskId: f.taskId }); assert.equal(read.records[0]!.text, 'Private durable post');
  const entry = read.records[0]!;
  await controller.hide({ projectId:f.planning.projectId,entryId:entry.entryId,kind:'comment',reason:'Retained history reason',reviewed:entry.pin });
  assert.equal((await controller.read({projectId:f.planning.projectId,kind:'comment',taskId:f.taskId})).records.length,0);
  const retained = await controller.read({projectId:f.planning.projectId,kind:'comment',taskId:f.taskId,includeHidden:true});
  assert.equal(retained.records[0]!.text,'Private durable post');
  assert.equal(retained.records[0]!.moderation?.reason,'Retained history reason');
  const normalList=transport.list;
  transport.list=async request=>normalList({...request,includeHidden:true});
  await assert.rejects(controller.read({projectId:f.planning.projectId,kind:'comment',taskId:f.taskId}), 'A hidden entry cannot be injected into the ordinary feed');
  transport.list=normalList;
  const receipt = f.receipts.get(operationId)!; f.receipts.set(operationId, { ...receipt, requestHash: '0'.repeat(64) }); await assert.rejects(controller.resume(operationId)); f.receipts.set(operationId, receipt);
  const db = await new Promise<IDBDatabase>((resolve, reject) => { const request = factory.open(name, 1); request.onsuccess = () => resolve(request.result); request.onerror = reject; });
  await new Promise<void>((resolve, reject) => { const tx = db.transaction('operations', 'readwrite'); tx.objectStore('operations').put({ ...pending, payload: null }, `${origin}:${actor.workspaceId}:${operationId}`); tx.oncomplete = () => resolve(); tx.onabort = reject; }); db.close();
  await controller.forgetDevice(actor); assert.equal(await operations.get(actor.workspaceId, operationId), undefined); operations.close(); planningPins.close(); pins.close();
});
