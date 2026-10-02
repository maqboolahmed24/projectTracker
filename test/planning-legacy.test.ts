import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { digestObject } from '../src/shared/crypto.js';
import { verifyPlanningContext, type PlanningSecurityResolver } from '../src/shared/planning-api.js';
import { verifySecurityHistory, type SecurityHistoryInput } from '../src/shared/security-history.js';

async function legacyFixture() {
  const fixture = JSON.parse(await readFile('test/fixtures/planning-v1.json', 'utf8'));
  const history = fixture.history as SecurityHistoryInput;
  const securityAt: PlanningSecurityResolver = async (version, suppliedHead) => {
    const count = Number(BigInt(version) - 1n);
    const transitions = history.transitions.slice(0, count);
    const securityHead = await digestObject(count === 0 ? history.genesis : transitions.at(-1));
    if (suppliedHead !== undefined) assert.equal(suppliedHead, securityHead);
    return verifySecurityHistory({ ...history, transitions, expected: { securityVersion: version, securityHead } });
  };
  return { fixture, securityAt };
}

test('CP08 compatibility: original signed v1 task history and closing snapshots remain byte-for-byte verifiable', async () => {
  const { fixture, securityAt } = await legacyFixture();
  assert.equal(fixture.sourceSha256, '4af6dfa04fbfbb9c41c96cde80b77d47a42352965fabb5b92000304a218e0d66');
  const context = await verifyPlanningContext(fixture.context, securityAt);
  assert.equal(context.history.length, 6);
  assert.equal(context.graph.snapshots.length, 2);
  assert.equal(context.graph.tasks[0]!.state, 'cancelled');
  assert.equal(context.graph.project.state, 'active');
  assert.deepEqual(context.graph, fixture.context.graph);
  assert.equal(await digestObject(context.graph), fixture.originalGraphDigest);
  assert.deepEqual(await Promise.all(context.history.map(digestObject)), fixture.originalOperationDigests);
  assert.equal(Object.hasOwn(context.graph.tasks[0]!, 'contentRevision'), false);
});

test('CP08 compatibility: retroactive workflow defaults or altered legacy snapshots invalidate original signatures', async () => {
  const { fixture, securityAt } = await legacyFixture();
  const injected = structuredClone(fixture.context);
  injected.graph.tasks[0].contentRevision = '1';
  await assert.rejects(verifyPlanningContext(injected, securityAt));
  const changedSnapshot = structuredClone(fixture.context);
  changedSnapshot.graph.snapshots[1].tasks[0].state = 'done';
  await assert.rejects(verifyPlanningContext(changedSnapshot, securityAt));
});
