import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { IDBFactory } from 'fake-indexeddb';
import { base64urlDecode, base64urlEncode, canonicalJson, decryptContent, digestObject, randomKey } from '../src/shared/crypto.js';
import { createProjectBinding, validateProjectCreatePayload, projectCreateHeader, type ProjectCreateRequest, type ProjectCreatePayload,
  type ProjectCreateReceipt, type ProjectCreateView } from '../src/shared/project-create.js';
import { deriveScopeProvisionPlan } from '../src/shared/scope-provision.js';
import { prepareProjectCreate } from '../src/client/project-create-crypto.js';
import { IndexedProjectCreateStore, type ProjectCreateRecord } from '../src/client/project-create-store.js';
import { ProjectCreateController, HttpProjectCreateTransport, type ProjectCreateTransport } from '../src/client/project-create-controller.js';
import { IndexedPairingStore, readOwnerCustodyKeyMaterial, readRecoveryCustodyKeyMaterial } from '../src/client/pairing.js';
import { recoveryKeys } from '../src/client/recovery.js';
import { refreshAccessKeys } from '../src/client/access-change-crypto.js';
import type { AuthController } from '../src/client/auth-controller.js';
import { origin, ownerFixture, join, append, actorAuthority, type OwnerFixture, type Actor } from './project-create-client-fixture.js';

function contextFor(f: OwnerFixture, request: ProjectCreateRequest = { workspaceId: f.workspaceId, operationId: randomUUID(), projectId: randomUUID() }) {
  const now = Date.now(), binding = createProjectBinding(request, f.state, actorAuthority(f), { issuedAt: new Date(now).toISOString(), expiresAt: new Date(now + 600000).toISOString() });
  return { request, context: { binding, plan: deriveScopeProvisionPlan(binding, f.state), materials: f.materials } };
}
async function commit(f: OwnerFixture, payload: ProjectCreatePayload): Promise<ProjectCreateReceipt> {
  const binding = payload.transition.body.binding; await append(f, payload.transition, binding.nextSecurityVersion);
  f.materials.push({ id: payload.custody.id, kind: 'custody_manifest', value: payload.custody.envelope, digest: await digestObject(payload.custody.envelope) });
  for (const object of payload.deliveries) f.materials.push({ id: object.id, kind: 'key_envelope', value: object.envelope, digest: await digestObject(object.envelope) });
  return { version: 1, workspaceId: f.workspaceId, operationId: binding.operationId, projectId: binding.projectId,
    securityVersion: binding.nextSecurityVersion, securityHead: f.state.securityHead, requestHash: await digestObject(payload), committedAt: new Date().toISOString(), transition: payload.transition };
}
function delivery(f: OwnerFixture, actor: Actor) { return { workspaceId: f.workspaceId, accountId: actor.accountId, deviceId: actor.deviceId, current: f.history.expected, materials: f.materials }; }

test('CP07 creation crypto: both equal Owners and their recovery kits receive project keys, retained historical keys survive, ordinary membership grants no access', async () => {
  const f = await ownerFixture(), second = await join(f, true), member = await join(f), name = 'A private iterative project name', previousHistory = canonicalJson(f.history),
    prior = await readOwnerCustodyKeyMaterial({ accountId: f.owner.accountId, deviceId: f.owner.deviceId, history: f.state, materials: f.materials }, f.owner.bundle), input = contextFor(f);
  const payload = await prepareProjectCreate({ ...input, history: f.history, name }, f.owner.bundle);
  assert.equal(canonicalJson(f.history), previousHistory); assert.equal(canonicalJson(payload).includes(name), false);
  for (const secret of [prior.payload.custodyKey, f.owner.bundle.signingPrivateKey, f.owner.phrase!]) assert.equal(canonicalJson(payload).includes(secret), false);
  assert.equal(payload.transition.body.binding.selected.length, 0); assert.equal(payload.deliveries.length, 6);
  assert.equal(payload.transition.body.deliveries.some((entry) => entry.recipient.accountId === member.accountId), false);
  await commit(f, payload);
  for (const actor of [f.owner, second]) {
    const opened = await readOwnerCustodyKeyMaterial({ accountId: actor.accountId, deviceId: actor.deviceId, history: f.state, materials: f.materials }, actor.bundle);
    assert.deepEqual(opened.manifest.workspaceKeys, prior.manifest.workspaceKeys); assert.equal(opened.manifest.custodyEpoch, '2');
    assert.notEqual(opened.payload.custodyKey, prior.payload.custodyKey);
    const key = base64urlDecode(opened.manifest.projectKeys.find((entry) => entry.projectId === input.request.projectId)!.keys[0]!.key, 32);
    try { assert.equal(canonicalJson(await decryptContent(payload.project.envelope, key, base64urlDecode(f.owner.bundle.signingPublicKey, 32), projectCreateHeader(input.context.binding))), canonicalJson({ name })); } finally { key.fill(0); }
    assert.equal((await refreshAccessKeys({ history: f.history, delivery: delivery(f, actor) }, actor.bundle)).scopeCount, 2);
    const keys = await recoveryKeys(actor.phrase!, { workspaceId: f.workspaceId, accountId: actor.accountId });
    try { const authority = f.state.recoveryAuthorities[`${actor.accountId}:1`]!, recovered = await readRecoveryCustodyKeyMaterial({ accountId: actor.accountId,
      recoveryId: authority.id, recoveryGeneration: '1', history: f.state, materials: f.materials }, keys.recipient.privateKey); assert.deepEqual(recovered.manifest, opened.manifest); }
    finally { keys.signing.privateKey.fill(0); keys.recipient.privateKey.fill(0); }
  }
  assert.equal((await refreshAccessKeys({ history: f.history, delivery: delivery(f, member) }, member.bundle)).scopeCount, 1);
  const current = await readOwnerCustodyKeyMaterial({ accountId: f.owner.accountId, deviceId: f.owner.deviceId, history: f.state, materials: f.materials }, f.owner.bundle), another = contextFor(f);
  await commit(f, await prepareProjectCreate({ ...another, history: f.history, name: 'Second simple project' }, f.owner.bundle));
  const retained = await readOwnerCustodyKeyMaterial({ accountId: second.accountId, deviceId: second.deviceId, history: f.state, materials: f.materials }, second.bundle);
  assert.deepEqual(retained.manifest.projectKeys.find((entry) => entry.projectId === input.request.projectId), current.manifest.projectKeys[0]);
  assert.deepEqual(retained.manifest.workspaceKeys, current.manifest.workspaceKeys); assert.equal(retained.manifest.projectKeys.length, 2);
});

test('CP07 creation crypto: tampered recipients, project ciphertext, stale history, expired contexts and wrong-device keys fail closed', async () => {
  const f = await ownerFixture(), member = await join(f), input = contextFor(f), name = 'Private required project';
  await assert.rejects(prepareProjectCreate({ ...input, history: f.history, name }, member.bundle));
  await assert.rejects(prepareProjectCreate({ ...input, history: f.history, name: '  ' }, f.owner.bundle));
  const altered = structuredClone(input); altered.context.plan.recipients.pop();
  await assert.rejects(prepareProjectCreate({ ...altered, history: f.history, name }, f.owner.bundle));
  const expired = structuredClone(input); expired.context.binding.issuedAt = new Date(Date.now() - 120000).toISOString(); expired.context.binding.expiresAt = new Date(Date.now() - 60000).toISOString();
  await assert.rejects(prepareProjectCreate({ ...expired, history: f.history, name }, f.owner.bundle));
  const payload = await prepareProjectCreate({ ...input, history: f.history, name }, f.owner.bundle), tampered = structuredClone(payload);
  tampered.project.envelope.header.recordId = randomUUID(); await assert.rejects(validateProjectCreatePayload(tampered, input.context.binding, f.state));
  await commit(f, payload);
  await assert.rejects(prepareProjectCreate({ ...input, history: f.history, name }, f.owner.bundle));
});

test('CP07 creation controller: encrypted durable draft survives lost commit reply and reload without duplicating the project; Forget deletes even corrupt scoped records', async () => {
  const f = await ownerFixture(), factory = new IDBFactory(), name = randomUUID(), pins = await IndexedPairingStore.open(origin, randomUUID(), factory),
    reference = { workspaceId: f.workspaceId, accountId: f.owner.accountId, deviceId: f.owner.deviceId };
  await pins.recordVerifiedHistory(f.history);
  let store = await IndexedProjectCreateStore.open(origin, name, factory), payload: ProjectCreatePayload | undefined, receipt: ProjectCreateReceipt | undefined, commits = 0, refreshes = 0;
  const auth = { origin, current: () => ({ localAccess: 'unlocked', session: { ...reference, credentialGeneration: '1', sessionGeneration: '1', dataGeneration: '1', csrfToken: 'test' } }),
    worker: { prepareProjectCreate: (input: Parameters<typeof prepareProjectCreate>[0]) => prepareProjectCreate(input, f.owner.bundle) } } as unknown as AuthController;
  const status = async (): Promise<ProjectCreateView> => receipt ? { state: 'completed', requestHash: receipt.requestHash, receipt } : payload ?
    { state: 'staged', requestHash: await digestObject(payload), receipt: null } : { state: 'absent', requestHash: null, receipt: null };
  const transport: ProjectCreateTransport = { origin, context: async (request) => contextFor(f, request).context, status,
    stage: async (value) => { assert.deepEqual((await store.get(f.workspaceId, value.transition.body.binding.operationId))?.payload, value); payload = value; return status(); },
    finalize: async () => { commits++; receipt = await commit(f, payload!); throw new Error('Lost creation reply'); },
    history: async () => ({ genesis: f.history.genesis, transitions: f.history.transitions, anchor: f.history.expected, current: f.history.expected }) };
  const access = { refreshKeys: async () => { refreshes++; return refreshAccessKeys({ history: f.history, delivery: delivery(f, f.owner) }, f.owner.bundle); } };
  let controller = new ProjectCreateController(auth, transport, store, pins, access); const operationId = randomUUID(), projectName = 'Secret launch plan';
  await assert.rejects(controller.create({ name: projectName, operationId }), /Lost creation reply/);
  assert.equal(commits, 1); const record = await store.get(f.workspaceId, operationId); assert.ok(record);
  assert.equal(canonicalJson(record).includes(projectName), false); assert.equal(canonicalJson(record).includes(f.owner.phrase!), false);
  store.close(); store = await IndexedProjectCreateStore.open(origin, name, factory); controller = new ProjectCreateController(auth, transport, store, pins, access);
  const result = await controller.resume(operationId); assert.equal(result.state, 'completed'); assert.equal(commits, 1); assert.equal(refreshes, 2);
  await assert.rejects(controller.create({ name: 'Different human intent', operationId })); assert.equal(commits, 1);
  const saved = receipt!; receipt = { ...saved, projectId: randomUUID() }; await assert.rejects(controller.resume(operationId)); receipt = saved;
  await store.put(record); await assert.rejects(store.put({ ...record, payload: { ...record.payload, project: { ...record.payload.project, id: randomUUID() } } }));
  const db = await new Promise<IDBDatabase>((resolve, reject) => { const request = factory.open(name, 1); request.onsuccess = () => resolve(request.result); request.onerror = reject; });
  await new Promise<void>((resolve, reject) => { const tx = db.transaction('operations', 'readwrite');
    tx.objectStore('operations').put({ ...record, payload: null }, `${origin}:${f.workspaceId}:${operationId}`); tx.oncomplete = () => resolve(); tx.onabort = reject; }); db.close();
  await store.forgetDevice(reference); assert.equal(await store.get(f.workspaceId, operationId), undefined); assert.deepEqual(await store.list(reference), []);
  store.close(); pins.close();
});

test('CP07 creation transport: every request requires authentication and history uploads only the opaque reference/cursor', async () => {
  const f = await ownerFixture(), reference = { workspaceId: f.workspaceId, operationId: randomUUID() }; let seen = 0;
  const unauthenticated = new HttpProjectCreateTransport(origin, () => undefined, async () => { seen++; throw new Error('Must not send'); });
  assert.throws(() => unauthenticated.status(reference)); assert.equal(seen, 0);
  const csrfToken = base64urlEncode(await randomKey()), transport = new HttpProjectCreateTransport(origin, () => csrfToken, async (url, options) => {
    assert.deepEqual(JSON.parse(String(options?.body)), reference);
    const response = new Response(JSON.stringify({ ...reference, mode: 'current', anchor: f.history.expected, current: f.history.expected,
      afterVersion: '0', genesis: f.history.genesis, transitions: [], nextAfterVersion: null }), { status: 200, headers: { 'content-type': 'application/json' } });
    Object.defineProperty(response, 'url', { value: String(url) }); return response;
  });
  assert.deepEqual((await transport.history({ ...reference, name: 'Must remain local' } as typeof reference)).anchor, f.history.expected);
});
