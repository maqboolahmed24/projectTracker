import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { IDBFactory } from 'fake-indexeddb';
import { prepareOwnerActivation } from '../src/client/activation.js';
import { newOwnerPhrase } from '../src/client/recovery.js';
import { unwrapDeviceBundle } from '../src/client/device-store.js';
import { IndexedPairingStore } from '../src/client/pairing.js';
import { IndexedRolesStore, HttpRolesTransport, prepareRoleChange, readRoleLabels, RolesController, RolesClientError, type RolesTransport, type StoredRoleOperation } from '../src/client/roles-controller.js';
import type { AuthController } from '../src/client/auth-controller.js';
import { OPAQUE_CONFIG_ID, OPAQUE_KEY_STRETCHING, type OpaquePublicConfiguration } from '../src/client/opaque.js';
import { base64urlDecode, base64urlEncode, canonicalJson, digestObject, randomKey } from '../src/shared/crypto.js';
import { roleBinding, roleLabelHeader, type RoleBinding, type RoleContext, type RolePayload, type RoleReceipt, type RoleList, type RoleView } from '../src/shared/roles.js';
import { verifySecurityHistory, type SecurityHistoryInput } from '../src/shared/security-history.js';
import type { PairingMaterial } from '../src/shared/pairing.js';

const origin = 'https://roles.ukda.example', privateName = 'Private engineering coordinators';
const next = (value: string) => String(BigInt(value) + 1n);
async function fixture() {
  const workspaceId = randomUUID(), accountId = randomUUID(), exportKey = base64urlEncode(await randomKey()), phrase = await newOwnerPhrase();
  const configuration: OpaquePublicConfiguration = { configId: OPAQUE_CONFIG_ID, setupId: 'roles-client', keyStretching: OPAQUE_KEY_STRETCHING,
    serverStaticPublicKey: base64urlEncode(await randomKey()), identifiers: { client: `ukda:${workspaceId}:${accountId}`, server: origin } };
  const prepared = await prepareOwnerActivation({ binding: { workspaceId, accountId, origin, activationId: randomUUID(), operationId: randomUUID(), reservationGeneration: '1', draftGeneration: '1' },
    configuration, exportKey, registrationRecord: base64urlEncode(await randomKey()), phrase, challengePositions: [1, 9, 19],
    challengeAnswers: [1, 9, 19].map((index) => phrase.split(' ')[index]!), displayName: 'Roles Owner', workspaceName: 'Roles workspace' });
  const genesis = prepared.payload.genesis, head = await digestObject(genesis), deviceId = genesis.body.device.id;
  const history: SecurityHistoryInput = { workspaceId, origin, genesisFingerprint: head, genesis, transitions: [], expected: { securityHead: head, securityVersion: '1' } };
  const bundle = await unwrapDeviceBundle({ workspaceId, accountId, deviceId, credentialGeneration: '1' }, prepared.deviceWrapper, exportKey);
  const materials: PairingMaterial[] = [
    { id: genesis.body.custodyId, kind: 'custody_manifest', value: prepared.payload.objects.custody, digest: await digestObject(prepared.payload.objects.custody) },
    { id: genesis.body.deviceEnvelopeId, kind: 'key_envelope', value: prepared.payload.objects.deviceCustody, digest: await digestObject(prepared.payload.objects.deviceCustody) },
  ];
  return { workspaceId, accountId, deviceId, history, state: await verifySecurityHistory(history), materials, bundle };
}
type Fixture = Awaited<ReturnType<typeof fixture>>;
function contextFor(f: Fixture, action: RoleBinding['action'] = 'create', roleId: string = randomUUID(), operationId: string = randomUUID(), label: RolePayload['label'] | null = null): RoleContext {
  const state = f.state, device = state.devices[f.deviceId]!, profile = state.profiles[f.accountId]!, now = Date.now();
  const binding = roleBinding.parse({ version: 1, origin, workspaceId: f.workspaceId, operationId, action, roleId, previous: state.roles[roleId] ?? null,
    nextRevision: next(state.roles[roleId]?.revision ?? '0'), authorizer: { accountId: f.accountId,
      device: { id: device.id, keyGeneration: device.keyGeneration, signingPublicKey: device.signingPublicKey, recipientPublicKey: device.recipientPublicKey },
      credentialGeneration: profile.credentialGeneration, sessionGeneration: profile.sessionGeneration },
    securityVersion: state.securityVersion, nextSecurityVersion: next(state.securityVersion), securityHead: state.securityHead,
    dataGeneration: state.dataGeneration, ownershipVersion: state.ownershipVersion, custodyEpoch: state.custodyEpoch, workspaceKeyEpoch: state.workspaceKeyEpoch,
    genesisFingerprint: state.genesisFingerprint, issuedAt: new Date(now).toISOString(), expiresAt: new Date(now + 600_000).toISOString() });
  return { binding, labelHeader: roleLabelHeader(binding), previousLabel: label, materials: f.materials };
}
function requestFor(context: RoleContext) {
  const { workspaceId, operationId, action, roleId } = context.binding; return { workspaceId, operationId, action, roleId };
}
async function prepare(f: Fixture, context = contextFor(f), displayName = privateName): Promise<RolePayload> {
  return prepareRoleChange({ request: requestFor(context), context, history: f.history,
    ...(context.binding.action === 'retire' ? {} : { displayName, permissions: ['read_project', 'comment'] }) }, f.bundle);
}
async function apply(f: Fixture, payload: RolePayload): Promise<RoleReceipt> {
  const binding = payload.transition.body.binding, securityHead = await digestObject(payload.transition);
  f.history = { ...f.history, transitions: [...f.history.transitions, payload.transition], expected: { securityHead, securityVersion: binding.nextSecurityVersion } };
  f.state = await verifySecurityHistory(f.history);
  return { version: 1, workspaceId: f.workspaceId, operationId: binding.operationId, roleId: binding.roleId, roleRevision: binding.nextRevision,
    securityVersion: binding.nextSecurityVersion, securityHead, requestHash: await digestObject(payload), committedAt: new Date().toISOString(), transition: payload.transition };
}
function pageFor(f: Fixture, labels: RolePayload['label'][]): RoleList {
  return { workspaceId: f.workspaceId, current: f.history.expected, nextRoleId: null, materials: f.materials,
    roles: Object.values(f.state.roles).sort((a, b) => a.id < b.id ? -1 : 1).map((role) => ({ ...role, label: labels.find((label) => label.id === role.label?.id) ?? null })) };
}
function recordFor(f: Fixture, payload: RolePayload): StoredRoleOperation {
  return { version: 1, origin, workspaceId: f.workspaceId, accountId: f.accountId, deviceId: f.deviceId, operationId: payload.transition.body.binding.operationId, payload };
}

test('CP06 roles client: authentic encrypted names round-trip across create, update and retirement without altering grant snapshots', async () => {
  const f = await fixture(), snapshot = canonicalJson(f.state.profiles), first = await prepare(f); await apply(f, first);
  assert.equal(canonicalJson(first).includes(privateName), false);
  const listed = await readRoleLabels({ request: { workspaceId: f.workspaceId, limit: 50 }, page: pageFor(f, [first.label]), history: f.history,
    accountId: f.accountId, deviceId: f.deviceId }, f.bundle);
  assert.equal(listed.roles.find((role) => role.id === first.transition.body.role.id)?.displayName, privateName);
  const updated = await prepare(f, contextFor(f, 'update', first.transition.body.role.id, randomUUID(), first.label), 'Private coordinators renamed'); await apply(f, updated);
  const retired = await prepare(f, contextFor(f, 'retire', first.transition.body.role.id, randomUUID(), updated.label)); await apply(f, retired);
  assert.notEqual(updated.label.envelope.ciphertext, retired.label.envelope.ciphertext);
  const read = await readRoleLabels({ request: { workspaceId: f.workspaceId, limit: 50 }, page: pageFor(f, [retired.label]), history: f.history,
    accountId: f.accountId, deviceId: f.deviceId }, f.bundle);
  assert.deepEqual(read.roles.find((role) => role.id === first.transition.body.role.id), { id: first.transition.body.role.id, template: 'custom', revision: '3', state: 'retired',
    permissions: ['read_project', 'comment'], displayName: 'Private coordinators renamed' });
  assert.equal(canonicalJson(f.state.profiles), snapshot);
});

test('CP06 roles client: untrusted context, builtin mutation, altered ciphertext and incomplete role listings fail closed', async () => {
  const f = await fixture(), context = contextFor(f), changed = structuredClone(context); changed.binding.authorizer.credentialGeneration = '2';
  await assert.rejects(prepare(f, changed));
  const builtin = structuredClone(context); builtin.binding.roleId = f.history.genesis.body.roles.member; builtin.labelHeader = roleLabelHeader(builtin.binding);
  await assert.rejects(prepare(f, builtin));
  const payload = await prepare(f, context); await apply(f, payload);
  const page = pageFor(f, [payload.label]), altered = structuredClone(page), custom = altered.roles.find((role) => role.template === 'custom')!;
  const bytes = base64urlDecode(custom.label!.envelope.ciphertext); bytes[0] = bytes[0]! ^ 1; custom.label!.envelope.ciphertext = base64urlEncode(bytes);
  const input = { request: { workspaceId: f.workspaceId, limit: 50 }, page: altered, history: f.history, accountId: f.accountId, deviceId: f.deviceId };
  await assert.rejects(readRoleLabels(input, f.bundle));
  await assert.rejects(readRoleLabels({ ...input, page: { ...page, roles: page.roles.slice(1) } }, f.bundle));
  await assert.rejects(prepare(f, context), 'An authentic old context cannot authorize another change after the trusted head advances');
});

test('CP06 roles storage: immutable encrypted drafts survive reopen; Forget removes scoped corrupt ciphertext', async () => {
  const f = await fixture(), payload = await prepare(f), record = recordFor(f, payload), factory = new IDBFactory(), databaseName = randomUUID();
  let store = await IndexedRolesStore.open(origin, databaseName, factory);
  await store.put(record); await store.put(record); assert.equal(canonicalJson(await store.get(f.workspaceId, record.operationId)).includes(privateName), false);
  await assert.rejects(store.put({ ...record, payload: { ...payload, label: { ...payload.label, id: randomUUID() } } }), (error: unknown) => error instanceof RolesClientError && error.code === 'CONFLICT');
  store.close(); store = await IndexedRolesStore.open(origin, databaseName, factory);
  assert.deepEqual(await store.get(f.workspaceId, record.operationId), record);
  const db = await new Promise<IDBDatabase>((resolve, reject) => { const request = factory.open(databaseName, 1); request.onsuccess = () => resolve(request.result); request.onerror = reject; });
  await new Promise<void>((resolve, reject) => { const tx = db.transaction('operations', 'readwrite');
    tx.objectStore('operations').put({ ...record, payload: 'corrupt' }, `${origin}:${f.workspaceId}:${record.operationId}`);
    tx.objectStore('operations').put({ invalid: true }, 'unrelated'); tx.oncomplete = () => resolve(); tx.onabort = reject; }); db.close();
  await store.forgetDevice({ workspaceId: f.workspaceId, accountId: f.accountId, deviceId: f.deviceId });
  assert.equal(await store.get(f.workspaceId, record.operationId), undefined); store.close();
});

function mockAuth(f: Fixture) {
  return { origin, current: () => ({ localAccess: 'unlocked', session: { workspaceId: f.workspaceId, accountId: f.accountId, deviceId: f.deviceId,
    credentialGeneration: '1', sessionGeneration: '1', dataGeneration: '1' } }),
  worker: { prepareRoleChange: (input: Parameters<typeof prepareRoleChange>[0]) => prepareRoleChange(input, f.bundle),
    readRoleLabels: (input: Parameters<typeof readRoleLabels>[0]) => readRoleLabels(input, f.bundle) } } as unknown as AuthController;
}
test('CP06 roles controller: lost staging and commit responses replay the identical durable operation after restart', async () => {
  const f = await fixture(), factory = new IDBFactory(), name = randomUUID(), pins = await IndexedPairingStore.open(origin, randomUUID(), factory);
  await pins.recordVerifiedHistory(f.history); let store = await IndexedRolesStore.open(origin, name, factory);
  let payload: RolePayload | undefined, receipt: RoleReceipt | undefined, stages = 0, commits = 0;
  const view = async (): Promise<RoleView> => receipt ? { state: 'completed', receipt, requestHash: receipt.requestHash } :
    payload ? { state: 'staged', receipt: null, requestHash: await digestObject(payload) } : { state: 'absent', receipt: null, requestHash: null };
  const transport: RolesTransport = { origin,
    context: async (request) => contextFor(f, request.action, request.roleId, request.operationId),
    status: view, history: async () => ({ genesis: f.history.genesis, transitions: f.history.transitions, anchor: f.history.expected, current: f.history.expected }),
    stage: async (value) => { stages++; payload = value; throw new Error('Lost stage reply'); },
    finalize: async () => { commits++; receipt = await apply(f, payload!); throw new Error('Lost commit reply'); },
    list: async () => pageFor(f, payload ? [payload.label] : []) };
  const operationId = randomUUID(), roleId = randomUUID(); let controller = new RolesController(mockAuth(f), transport, store, pins);
  await assert.rejects(controller.create({ operationId, roleId, displayName: privateName, permissions: ['read_project', 'comment'] }), /Lost stage reply/);
  assert.deepEqual(await controller.pending(), [{ operationId, roleId, action: 'create' }]); store.close(); store = await IndexedRolesStore.open(origin, name, factory);
  controller = new RolesController(mockAuth(f), transport, store, pins);
  await assert.rejects(controller.resume(operationId), /Lost commit reply/);
  const result = await controller.resume(operationId); assert.equal(result.state, 'completed'); assert.equal(result.receipt.roleRevision, '1');
  assert.equal(stages, 1); assert.equal(commits, 1); assert.equal((await controller.list()).roles.find((role) => role.id === roleId)?.displayName, privateName);
  const original = receipt!; receipt = { ...original, requestHash: '0'.repeat(64) }; await assert.rejects(controller.resume(operationId)); receipt = original;
  store.close(); pins.close();
});

test('CP06 roles controller: logout/Forget invalidates late preparation before it can create a local replay record', async () => {
  const f = await fixture(), factory = new IDBFactory(), store = await IndexedRolesStore.open(origin, randomUUID(), factory), pins = await IndexedPairingStore.open(origin, randomUUID(), factory);
  await pins.recordVerifiedHistory(f.history);
  let resolveContext!: (context: RoleContext) => void, contextRequested!: () => void;
  const started = new Promise<void>((resolve) => { contextRequested = resolve; });
  const unexpected = async (): Promise<never> => { throw new Error('Unexpected transport call after cancellation'); };
  const transport: RolesTransport = { origin, context: () => { contextRequested(); return new Promise<RoleContext>((resolve) => { resolveContext = resolve; }); },
    stage: unexpected, finalize: unexpected, status: unexpected, history: unexpected, list: unexpected };
  const controller = new RolesController(mockAuth(f), transport, store, pins), context = contextFor(f), pending = controller.create({
    operationId: context.binding.operationId, roleId: context.binding.roleId, displayName: privateName, permissions: ['read_project'] });
  const rejected = assert.rejects(pending, (error: unknown) => error instanceof RolesClientError && error.code === 'CANCELLED');
  await started; controller.clear(); resolveContext(context); await rejected;
  assert.deepEqual(await store.list(f.workspaceId), []); store.close(); pins.close();
});


test('CP06 roles transport: history sends only the public reference and page cursor even when passed a richer context request', async () => {
  const f = await fixture(), request = requestFor(contextFor(f)); let requests = 0;
  const transport = new HttpRolesTransport(origin, () => base64urlEncode(new Uint8Array(32)), async (url, options) => {
    requests++; assert.equal(url, `${origin}/v1/auth/roles/history`);
    assert.deepEqual(JSON.parse(String(options?.body)), { workspaceId: f.workspaceId, operationId: request.operationId });
    const response = new Response(JSON.stringify({ workspaceId: f.workspaceId, operationId: request.operationId, mode: 'current',
      anchor: f.history.expected, current: f.history.expected, afterVersion: '0', genesis: f.history.genesis, transitions: [], nextAfterVersion: null }),
    { status: 200, headers: { 'content-type': 'application/json' } });
    Object.defineProperty(response, 'url', { value: String(url) });
    return response;
  });
  const history = await transport.history(request); assert.equal(requests, 1); assert.deepEqual(history.anchor, f.history.expected);
});
