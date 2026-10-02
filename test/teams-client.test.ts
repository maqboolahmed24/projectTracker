import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { IDBFactory } from 'fake-indexeddb';
import { base64urlDecode, base64urlEncode, canonicalJson, digestObject, encryptContent, randomKey, signObject } from '../src/shared/crypto.js';
import { teamBinding, teamMutation, type TeamContext, type TeamHistoryPage, type TeamPayload, type TeamReceipt } from '../src/shared/teams.js';
import { prepareTeamChange, prepareTeamUpgrade, readTeamHistory, readTeams, readWorkspaceKeyRing, verifyTeamUpgradeTargets, type EncryptedTeamsPage, type PrepareTeamChangeInput } from '../src/client/teams-crypto.js';
import { TeamsController, HttpTeamsTransport, type TeamsTransport } from '../src/client/teams-controller.js';
import { IndexedTeamsStore } from '../src/client/teams-store.js';
import { IndexedPairingStore } from '../src/client/pairing.js';
import type { AuthController } from '../src/client/auth-controller.js';
import { ownerFixture, join, origin, type OwnerFixture, type Actor } from './project-create-client-fixture.js';
import { signedUpgradeStart, signedUpgradeFinish } from './upgrade-client-fixture.js';

function contextFor(f: OwnerFixture, request: { workspaceId: string; teamId: string; operationId: string; action: 'create' | 'update' | 'upgrade_content' } = { workspaceId: f.workspaceId, teamId: randomUUID(), operationId: randomUUID(), action: 'create' }, previous: TeamPayload | null = null): Promise<TeamContext> {
  return (async () => ({ binding: teamBinding.parse({ ...request, expectedRevision: previous?.envelope.header.revision ?? '0',
    previousDigest: previous ? await digestObject(previous.envelope) : null, previousMemberIds: previous?.mutation.body.memberIds ?? [],
    securityHead: f.state.securityHead, securityVersion: f.state.securityVersion, dataGeneration: f.state.dataGeneration, keyEpoch: f.state.workspaceKeyEpoch,
    authorizer: { accountId: f.owner.accountId, deviceId: f.owner.deviceId, keyGeneration: f.state.devices[f.owner.deviceId]!.keyGeneration,
      signingPublicKey: f.owner.bundle.signingPublicKey } }), previous: previous?.envelope ?? null, previousSignedChange: previous }))();
}

test('CP11 teams: authenticated schema migration preserves membership and plaintext, rejects valid-signer substitutions and keeps legacy history',async()=>{
  const f=await ownerFixture(),first=await draft(f),original=canonicalJson(first.payload),h=first.payload.envelope.header,
    source={kind:'team' as const,id:h.recordId,projectId:null,revision:h.revision,contentRevision:null,envelopeRevision:h.revision,schema:1 as const,keyEpoch:h.keyEpoch,digest:await digestObject(first.payload.envelope)},
    migration=await signedUpgradeStart(f,[source]);
  const context=await contextFor(f,{workspaceId:f.workspaceId,teamId:h.recordId,operationId:randomUUID(),action:'update'},first.payload);
  context.binding=teamBinding.parse({...context.binding,version:3,writeSchema:1,action:'upgrade_content',issuedAt:new Date().toISOString(),expiresAt:new Date(Date.now()+600_000).toISOString()});
  const upgraded=await prepareTeamUpgrade({...keys(f),context,...migration},f.owner.bundle);
  assert.equal(upgraded.envelope.header.schema,2);assert.equal(upgraded.envelope.header.revision,'2');assert.equal(canonicalJson(first.payload),original);
  assert.equal((await readTeams({...keys(f),page:pageFor(f,[upgraded])},f.owner.bundle)).records[0]!.name,'Private operations team');
  const forged=structuredClone(upgraded),ring=await readWorkspaceKeyRing(keys(f),f.state,f.owner.bundle),key=base64urlDecode(ring.find(k=>k.epoch===f.state.workspaceKeyEpoch)!.key,32),signing=base64urlDecode(f.owner.bundle.signingPrivateKey,64);
  try {
    forged.envelope=await encryptContent(forged.envelope.header,{name:'Changed during representation upgrade',description:''},key,signing);
    const item=forged.upgradeItems![0]!;item.envelope=forged.envelope;item.target.digest=await digestObject(forged.envelope);
    assert.equal(forged.mutation.body.version,3);if(forged.mutation.body.version!==3)throw new Error('Expected v3');
    forged.mutation.body.contentDigest=item.target.digest;forged.mutation.body.upgrade!.items[0]!.target.digest=item.target.digest;
    forged.mutation=teamMutation.parse(await signObject(forged.mutation.body,signing));
    await assert.rejects(readTeams({...keys(f),page:pageFor(f,[forged])},f.owner.bundle));
  }finally{key.fill(0);signing.fill(0);}
  const after=await contextFor(f,{workspaceId:f.workspaceId,teamId:h.recordId,operationId:randomUUID(),action:'update'},upgraded);
  after.binding=teamBinding.parse({...after.binding,version:3,writeSchema:1,issuedAt:new Date().toISOString(),expiresAt:new Date(Date.now()+600_000).toISOString()});
  const targets=await verifyTeamUpgradeTargets({...keys(f),context:after},f.owner.bundle);await signedUpgradeFinish(f,targets);
  const next=await contextFor(f,{workspaceId:f.workspaceId,teamId:h.recordId,operationId:randomUUID(),action:'update'},upgraded);
  next.binding=teamBinding.parse({...next.binding,version:3,writeSchema:2,issuedAt:new Date().toISOString(),expiresAt:new Date(Date.now()+600_000).toISOString()});
  const changed=await prepareTeamChange({...keys(f),context:next,request:{workspaceId:f.workspaceId,teamId:h.recordId,operationId:next.binding.operationId,action:'update'},name:'Explicit subsequent edit',memberIds:[]},f.owner.bundle),
    history=await readTeamHistory({...keys(f),pages:[await historyPage(f,[first.payload,upgraded,changed])]},f.owner.bundle);
  assert.equal(changed.envelope.header.schema,2);assert.deepEqual(history.records.map(row=>row.action),['create','upgrade_content','update']);
  assert.deepEqual(history.records[1]!.before,history.records[1]!.after);assert.equal(history.records[2]!.after.name,'Explicit subsequent edit');
});
function keys(f: OwnerFixture, actor: Actor = f.owner) { return { history: f.history, accountId: actor.accountId, deviceId: actor.deviceId, materials: f.materials }; }
function pageFor(f: OwnerFixture, payloads: TeamPayload[]): EncryptedTeamsPage { return { records: payloads.map((payload) => ({ id: payload.envelope.header.recordId,
  revision: payload.envelope.header.revision, key_epoch: payload.envelope.header.keyEpoch, encrypted_envelope: payload.envelope,
  memberIds: payload.mutation.body.memberIds, signedChange: payload })).sort((a, b) => a.id.localeCompare(b.id)), nextCursor: null,
  securityHead: f.state.securityHead, securityVersion: f.state.securityVersion, dataGeneration: f.state.dataGeneration }; }
async function draft(f: OwnerFixture, name = 'Private operations team', memberIds = [f.owner.accountId], previous: TeamPayload | null = null) {
  const context = await contextFor(f, { workspaceId: f.workspaceId, teamId: previous?.envelope.header.recordId ?? randomUUID(), operationId: randomUUID(), action: previous ? 'update' : 'create' }, previous);
  const request = { workspaceId: f.workspaceId, teamId: context.binding.teamId, operationId: context.binding.operationId, action: context.binding.action };
  return { context, request, payload: await prepareTeamChange({ ...keys(f), context, request, name, memberIds }, f.owner.bundle) };
}
async function historyPage(f: OwnerFixture, payloads: TeamPayload[]): Promise<TeamHistoryPage> {
  const last = payloads.at(-1)!;
  return { workspaceId: f.workspaceId, teamId: last.envelope.header.recordId, securityHead: f.state.securityHead,
    securityVersion: f.state.securityVersion, dataGeneration: f.state.dataGeneration,
    anchor: { revision: last.envelope.header.revision, digest: await digestObject(last.envelope) },
    records: payloads.map((payload) => ({ payload, recordedAt: new Date().toISOString() })), nextRevision: null, complete: true };
}

test('CP09 teams history: v1 and signed-time v2 changes replay before/after under historical authority and reject incomplete chains', async () => {
  const f = await ownerFixture(), first = await draft(f), original = canonicalJson(first.payload), member = await join(f),
    context = await contextFor(f, { workspaceId: f.workspaceId, teamId: first.context.binding.teamId, operationId: randomUUID(), action: 'update' }, first.payload);
  context.binding = teamBinding.parse({ ...context.binding, version: 2, issuedAt: new Date(Date.now() - 1000).toISOString(), expiresAt: new Date(Date.now() + 60_000).toISOString() });
  const request = { workspaceId: f.workspaceId, teamId: context.binding.teamId, operationId: context.binding.operationId, action: 'update' as const },
    second = await prepareTeamChange({ ...keys(f), context, request, name: 'Revised private team', description: 'Changed purpose', memberIds: [member.accountId] }, f.owner.bundle),
    page = await historyPage(f, [first.payload, second]), pages: TeamHistoryPage[] = [
      { ...page, records: [page.records[0]!], complete: false, nextRevision: '1' }, { ...page, records: [page.records[1]!] }];
  const read = (value: TeamHistoryPage[]) => readTeamHistory({ ...keys(f, member), pages: value }, member.bundle), result = await read(pages);
  assert.equal(canonicalJson(first.payload), original); assert.equal(second.mutation.body.version, 2);
  assert.deepEqual(result.records.map((record) => record.revision), ['1', '2']);
  assert.equal(result.records[0]!.signedAt, null); assert.equal(result.records[0]!.before, null);
  assert.equal(result.records[1]!.signedAt, 'version' in context.binding ? context.binding.issuedAt : 'invalid');
  assert.equal(result.records[1]!.actorId, f.owner.accountId); assert.equal(result.records[1]!.deviceId, f.owner.deviceId);
  assert.deepEqual(result.records[1]!.before, result.records[0]!.after);
  assert.deepEqual(result.records[1]!.after, { name: 'Revised private team', description: 'Changed purpose', memberIds: [member.accountId] });
  assert.equal(result.records[0]!.serverRecordedAt, page.records[0]!.recordedAt);
  await assert.rejects(read([pages[1]!])); await assert.rejects(read([pages[1]!, pages[0]!]));
  await assert.rejects(read([{ ...page, records: [page.records[0]!] }]));
  await assert.rejects(read([{ ...page, anchor: { ...page.anchor, digest: 'a'.repeat(64) } }]));
  await assert.rejects(read([{ ...page, securityHead: 'a'.repeat(64) }]));
  const broken = structuredClone(page); broken.records[1]!.payload.mutation.body.binding.previousDigest = 'a'.repeat(64);
  broken.records[1]!.payload.mutation = teamMutation.parse(await signObject(broken.records[1]!.payload.mutation.body, base64urlDecode(f.owner.bundle.signingPrivateKey)));
  await assert.rejects(read([broken]));
  const expired = { ...context, binding: teamBinding.parse({ ...context.binding, issuedAt: new Date(Date.now() - 120_000).toISOString(), expiresAt: new Date(Date.now() - 60_000).toISOString() }) };
  await assert.rejects(prepareTeamChange({ ...keys(f), request, context: expired, name: 'Expired change', memberIds: [] }, f.owner.bundle));
  // Historical timestamp validity is structural, never current freshness.
  const old = structuredClone(page), oldPayload = old.records[1]!.payload;
  oldPayload.mutation.body.binding = expired.binding;
  oldPayload.mutation = teamMutation.parse(await signObject(oldPayload.mutation.body, base64urlDecode(f.owner.bundle.signingPrivateKey)));
  assert.equal((await read([old])).records[1]!.signedAt, 'version' in expired.binding ? expired.binding.issuedAt : 'invalid');
});

test('CP07 teams crypto: signed workspace teams decrypt for current members, survive historical security heads, and grant no project authority', async () => {
  const f = await ownerFixture(), first = await draft(f), stateBefore = canonicalJson(f.state);
  assert.equal(canonicalJson(first.payload).includes('Private operations team'), false);
  assert.equal(canonicalJson(first.payload).includes(f.owner.bundle.signingPrivateKey), false);
  assert.equal(canonicalJson(f.state), stateBefore);
  const member = await join(f), updated = await draft(f, 'Shared support team', [member.accountId], first.payload);
  const ownerPage = await readTeams({ ...keys(f), page: pageFor(f, [updated.payload]) }, f.owner.bundle);
  const memberPage = await readTeams({ ...keys(f, member), page: pageFor(f, [updated.payload]) }, member.bundle);
  assert.deepEqual(ownerPage, memberPage); assert.deepEqual(memberPage.records[0], { teamId: first.context.binding.teamId, revision: '2', name: 'Shared support team', description: '', memberIds: [member.accountId] });
  assert.equal(Object.keys(f.state.profiles[member.accountId]!.projectRoles).length, 0);
  assert.ok(f.state.profiles[member.accountId]!.scopes.every((scope) => scope.scope === 'workspace'));
  // The initial record remains readable under its older, independently verified
  // security head; the later enrolment cannot invalidate its historical signer.
  assert.equal((await readTeams({ ...keys(f, member), page: pageFor(f, [first.payload]) }, member.bundle)).records[0]!.name, 'Private operations team');
  await assert.rejects(prepareTeamChange({ ...keys(f, member), context: updated.context, request: updated.request, name: 'Unauthorized team edit', memberIds: [] }, member.bundle));
});

test('CP07 teams crypto: unsigned membership, substituted previous records, wrong signers, wrong heads and inactive recipients fail closed', async () => {
  const f = await ownerFixture(), d = await draft(f), member = await join(f), page = pageFor(f, [d.payload]);
  const unsigned = structuredClone(page); unsigned.records[0]!.memberIds.push(member.accountId);
  await assert.rejects(readTeams({ ...keys(f), page: unsigned }, f.owner.bundle));
  const tampered = structuredClone(page); tampered.records[0]!.encrypted_envelope.header.recordId = randomUUID();
  await assert.rejects(readTeams({ ...keys(f), page: tampered }, f.owner.bundle));
  const badHead = structuredClone(page); badHead.securityHead = 'a'.repeat(64);
  await assert.rejects(readTeams({ ...keys(f), page: badHead }, f.owner.bundle));
  const forged = structuredClone(d.payload); forged.mutation.body.binding.authorizer = { accountId: member.accountId, deviceId: member.deviceId, keyGeneration: '1', signingPublicKey: member.bundle.signingPublicKey };
  forged.mutation = teamMutation.parse(await signObject(forged.mutation.body, base64urlDecode(member.bundle.signingPrivateKey)));
  await assert.rejects(readTeams({ ...keys(f), page: pageFor(f, [forged]) }, f.owner.bundle));
  const updateContext = await contextFor(f, { workspaceId: f.workspaceId, teamId: d.context.binding.teamId, operationId: randomUUID(), action: 'update' }, d.payload);
  const request = { workspaceId: f.workspaceId, teamId: updateContext.binding.teamId, operationId: updateContext.binding.operationId, action: 'update' as const };
  await assert.rejects(prepareTeamChange({ ...keys(f), request, context: { ...updateContext, binding: { ...updateContext.binding, previousMemberIds: [] } }, name: 'Tampered prior members', memberIds: [] }, f.owner.bundle));
  await assert.rejects(prepareTeamChange({ ...keys(f), request, context: { ...updateContext, previousSignedChange: null }, name: 'Unsigned prior', memberIds: [] }, f.owner.bundle));
  await assert.rejects(prepareTeamChange({ ...keys(f), request, context: updateContext, name: 'Inactive member', memberIds: [randomUUID()] }, f.owner.bundle));
  await assert.rejects(prepareTeamChange({ ...keys(f), request, context: updateContext, name: '  ', memberIds: [] }, f.owner.bundle));
});

test('CP07 teams controller: exact encrypted drafts resume lost replies once, enforce generations, and Forget removes corrupt scoped records', async () => {
  const f = await ownerFixture(), factory = new IDBFactory(), database = randomUUID(), pins = await IndexedPairingStore.open(origin, randomUUID(), factory);
  await pins.recordVerifiedHistory(f.history); let store = await IndexedTeamsStore.open(origin, database, factory);
  const reference = { workspaceId: f.workspaceId, accountId: f.owner.accountId, deviceId: f.owner.deviceId };
  let generation = '1', receipt: TeamReceipt | null = null, saved: TeamPayload | null = null, saves = 0, lose = true;
  const auth = { origin, current: () => ({ localAccess: 'unlocked', session: { ...reference, credentialGeneration: generation, sessionGeneration: '1', dataGeneration: '1' } }),
    worker: { prepareTeamChange: (value: PrepareTeamChangeInput) => prepareTeamChange(value, f.owner.bundle), readTeams: (value: Parameters<typeof readTeams>[0]) => readTeams(value, f.owner.bundle),
      readTeamHistory: (value: Parameters<typeof readTeamHistory>[0]) => readTeamHistory(value, f.owner.bundle) } } as unknown as AuthController;
  const transport: TeamsTransport = { origin, context: (input) => contextFor(f, input, saved), status: async () => ({ receipt }), list: async () => pageFor(f, saved ? [saved] : []),
    history: async () => historyPage(f, [saved!]),
    save: async (payload) => { saves++; const b = payload.mutation.body.binding;
      assert.equal(canonicalJson((await store.get(f.workspaceId, b.operationId))?.payload), canonicalJson(payload)); saved = payload;
      receipt = { version: 1, workspaceId: b.workspaceId, teamId: b.teamId, operationId: b.operationId, actorId: b.authorizer.accountId,
        revision: payload.envelope.header.revision, dataGeneration: b.dataGeneration, requestHash: await digestObject(payload) };
      if (lose) { lose = false; throw new Error('lost team save reply'); } return receipt;
    } };
  const security = { delivery: async () => ({ ...reference, current: f.history.expected, materials: f.materials }),
    deliveryHistory: async () => ({ genesis: f.history.genesis, transitions: f.history.transitions, anchor: f.history.expected, current: f.history.expected }) };
  const access = { refreshKeys: async () => ({ complete: true as const, scopeCount: 1, ...f.history.expected, custodyEpoch: '1', ownershipVersion: '1' }) };
  let controller = new TeamsController(auth, transport, store, pins, access, security); const operationId = randomUUID(), teamId = randomUUID(), name = 'Secret durable team';
  await assert.rejects(controller.create({ name, teamId, operationId }), /lost team save reply/); assert.equal(saves, 1);
  const record = await store.get(f.workspaceId, operationId); assert.ok(record); assert.equal(canonicalJson(record).includes(name), false);
  store.close(); store = await IndexedTeamsStore.open(origin, database, factory); controller = new TeamsController(auth, transport, store, pins, access, security);
  const resumed = await controller.resume(operationId); assert.equal(resumed.state, 'completed'); assert.equal(saves, 1);
  assert.equal((await controller.list()).records[0]!.name, name);
  assert.equal((await controller.history(teamId)).records[0]!.after.name, name);
  generation = '2'; await assert.rejects(controller.resume(operationId)); generation = '1';
  const valid = receipt!; receipt = { ...valid, teamId: randomUUID() }; await assert.rejects(controller.resume(operationId)); receipt = valid;
  await assert.rejects(controller.create({ name: 'Different intent', operationId })); assert.equal(saves, 1);
  const db = await new Promise<IDBDatabase>((resolve, reject) => { const r = factory.open(database, 1); r.onsuccess = () => resolve(r.result); r.onerror = reject; });
  await new Promise<void>((resolve, reject) => { const tx = db.transaction('operations', 'readwrite'); tx.objectStore('operations').put({ ...record, payload: null }, `${origin}:${f.workspaceId}:${operationId}`); tx.oncomplete = () => resolve(); tx.onabort = reject; }); db.close();
  await controller.forgetDevice(reference); assert.equal(await store.get(f.workspaceId, operationId), undefined); assert.deepEqual(await controller.pending(), []);
  store.close(); pins.close();
});

test('CP07 teams transport: authenticated POSTs carry only encrypted changes or opaque references', async () => {
  const f = await ownerFixture(), reference = { workspaceId: f.workspaceId, teamId: randomUUID(), operationId: randomUUID() }; let requests = 0;
  const blocked = new HttpTeamsTransport(origin, () => undefined, async () => { requests++; throw new Error('must not send'); });
  assert.throws(() => blocked.status(reference)); assert.equal(requests, 0);
  const csrf = base64urlEncode(await randomKey()), transport = new HttpTeamsTransport(origin, () => csrf, async (url, options) => {
    assert.equal(options?.method, 'POST'); assert.equal(new Headers(options?.headers).get('x-csrf-token'), csrf);
    assert.deepEqual(JSON.parse(String(options?.body)), { workspaceId: f.workspaceId, limit: 10 });
    const response = new Response(JSON.stringify(pageFor(f, [])), { status: 200, headers: { 'content-type': 'application/json' } });
    Object.defineProperty(response, 'url', { value: String(url) }); return response;
  });
  assert.deepEqual((await transport.list({ workspaceId: f.workspaceId, limit: 10 })).records, []);
});
