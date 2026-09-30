import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import test from 'node:test';
import { closingSettings } from '../src/shared/closing-settings.js';
import { base64urlDecode, digestObject, signObject } from '../src/shared/crypto.js';
import { planningMutation, readPlanningClosingSettings, validatePlanningPayload, verifyPlanningContext, clearPlanningReplayCache } from '../src/shared/planning-api.js';
import { planningSecurityResolver, preparePlanning } from '../src/client/planning-crypto.js';
import { planningClientFixture } from './planning-client-fixture.js';

const stamp = (workspaceId: string) => ({ workspaceId, revision: '0', head: 'a'.repeat(64), initialDigest: 'b'.repeat(64), timezone: 'Europe/London' });

test('CP10 closure settings: strict independent schema allows initial revision zero and rejects malformed or unknown zones', () => {
  const value = stamp(randomUUID()); assert.deepEqual(closingSettings.parse(value), value);
  for (const patch of [{ timezone: 'not/a-zone' }, { timezone: '' }, { revision: '-1' }, { head: 'bad' }, { workspaceId: 'not-an-id' }, { unknown: true }])
    assert.equal(closingSettings.safeParse({ ...value, ...patch }).success, false);
});

test('CP10 closure settings: genuine signatures cannot attach closure metadata to a nonclosure, live or historical', async () => {
  const f = await planningClientFixture({ version: 2 }), before = await f.input(), valid = await preparePlanning({ ...before, command: { action: 'start_project' } }, f.f.owner.bundle),
    invalid = structuredClone(valid), key = base64urlDecode(f.f.owner.bundle.signingPrivateKey);
  if (invalid.mutation.body.purpose !== 'ukda.planning-mutation.v2') throw new Error('Expected v2');
  invalid.mutation.body.closingSettings = stamp(f.f.workspaceId);
  try { invalid.mutation = await signObject(invalid.mutation.body, key); } finally { key.fill(0); }
  assert.equal(planningMutation.safeParse(invalid.mutation).success, true, 'Syntactic validity never implies semantic permission');
  await assert.rejects(validatePlanningPayload(invalid, before.context.binding, before.context.graph, before.context.records), /Invalid closing settings/);
  await f.apply(valid);
  const historical = await f.context(); historical.history[0] = invalid.mutation; historical.binding.beforeHead = await digestObject(invalid.mutation);
  await assert.rejects(verifyPlanningContext(historical, planningSecurityResolver(f.f.history, f.f.state)), /Invalid historical closing settings/);
});

test('CP10 closure settings: real stamped closure binds its operation while graph and snapshot structures remain unchanged', async () => {
  const f = await planningClientFixture({ version: 2 }), before = await f.input(), payload = await preparePlanning({ ...before,
    command: { action: 'cancel_project' }, outcome: 'Preserve the actual closing timezone' }, f.f.owner.bundle);
  if (payload.mutation.body.purpose !== 'ukda.planning-mutation.v2') throw new Error('Expected v2');
  const expected = payload.mutation.body.closingSettings!;
  assert.ok(expected); assert.equal(expected.workspaceId, f.f.workspaceId); assert.equal(expected.timezone, 'Europe/London'); assert.equal(expected.revision, '0');
  const valid = await validatePlanningPayload(payload, before.context.binding, before.context.graph, before.context.records);
  assert.ok(valid.result.snapshot); assert.equal(Object.hasOwn(valid.result.snapshot, 'closingSettings'), false);
  assert.equal(Object.hasOwn(valid.result.state.project, 'closingSettings'), false);
  await f.apply(payload);
  const verified = await verifyPlanningContext(await f.context(), planningSecurityResolver(f.f.history, f.f.state));
  assert.deepEqual(readPlanningClosingSettings(verified, payload.mutation.body.binding.operationId), expected);
  assert.equal(readPlanningClosingSettings(verified, randomUUID()), null);
  const foreign = structuredClone(payload), key = base64urlDecode(f.f.owner.bundle.signingPrivateKey);
  if (foreign.mutation.body.purpose !== 'ukda.planning-mutation.v2') throw new Error('Expected v2');
  foreign.mutation.body.closingSettings = { ...expected, workspaceId: randomUUID() };
  try { foreign.mutation = await signObject(foreign.mutation.body, key); } finally { key.fill(0); }
  await assert.rejects(validatePlanningPayload(foreign, before.context.binding, before.context.graph, before.context.records), /Invalid closing settings/);
  const historical = structuredClone(verified); historical.history[0] = foreign.mutation; historical.binding.beforeHead = await digestObject(foreign.mutation);
  await assert.rejects(verifyPlanningContext(historical, planningSecurityResolver(f.f.history, f.f.state)), /Changed verified planning prefix/);
  clearPlanningReplayCache();
  await assert.rejects(verifyPlanningContext(historical, planningSecurityResolver(f.f.history, f.f.state)), /Invalid historical closing settings/);
});

test('CP10 closure settings: v1 cannot gain new fields and unstamped legacy closures remain explicitly unrecorded', async () => {
  const f = await planningClientFixture({ version: 1 }), payload = await preparePlanning({ ...await f.input(), command: { action: 'cancel_project' }, outcome: 'Legacy outcome' }, f.f.owner.bundle);
  const originalDigest = await digestObject(payload.mutation);
  assert.equal(planningMutation.safeParse({ ...payload.mutation, body: { ...payload.mutation.body, closingSettings: stamp(f.f.workspaceId) } }).success, false);
  await f.apply(payload);
  const verified = await verifyPlanningContext(await f.context(), planningSecurityResolver(f.f.history, f.f.state));
  assert.equal(await digestObject(verified.history[0]), originalDigest);
  assert.equal(Object.hasOwn(verified.history[0]!.body, 'closingSettings'), false);
  assert.equal(readPlanningClosingSettings(verified, payload.mutation.body.binding.operationId), null);
});
