import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { IDBFactory } from 'fake-indexeddb';
import { RememberedProfiles } from '../src/client/remembered-profiles.js';
import type { AuthState } from '../src/client/auth-controller.js';
import type { WorkspaceDirectory } from '../src/client/directory-crypto.js';
import { rememberVerifiedProfile } from '../frontend/shared/remembered-profile.js';

async function fixture() {
  const workspaceId = randomUUID(), accountId = randomUUID(), deviceId = randomUUID();
  const cards = await RememberedProfiles.open('https://ukda.example', randomUUID(), new IDBFactory());
  const state: AuthState = { localAccess: 'unlocked', session: { workspaceId, accountId, deviceId,
    sessionId: randomUUID(), accessLevel: 'device_approved', credentialGeneration: '1', sessionGeneration: '1', dataGeneration: '1',
    csrfToken: 'A'.repeat(43), authenticatedAt: new Date().toISOString(), idleExpiresAt: new Date().toISOString(), absoluteExpiresAt: new Date().toISOString() } };
  let current: AuthState | undefined = state;
  const client = { auth: { current: () => current }, remembered: cards } as Parameters<typeof rememberVerifiedProfile>[0];
  const person = { accountId, displayName: 'Saved person', avatar: { shapeId: 'shape-07', colourId: 'coral' },
    state: 'active', owner: true, roleId: randomUUID(), roleRevision: '1', projectIds: [] } satisfies WorkspaceDirectory['people'][number];
  const directory: WorkspaceDirectory = { workspaceId, accountId, deviceId, workspaceName: 'Private workspace', isOwner: true,
    genesisFingerprint: 'a'.repeat(64), people: [{ ...person, accountId: randomUUID(), displayName: 'Other private person' }, person],
    projectIds: [], permissions: [], devices: [{ id: deviceId, accountId, active: true, current: true }], lifecycle: 'active', deletion: null,
    restoreQuarantine: false, activeRestore: null, licenceState: 'active', entitlementState: 'activated', writeSchema: 1, activeUpgrade: null };
  return { cards, client, state, directory, setCurrent(value: AuthState | undefined) { current = value; } };
}

test('verified directory refresh upgrades only the current remembered profile and keeps the chosen avatar after logout', async () => {
  const f = await fixture();
  try {
    await f.cards.remember({ workspaceId: f.directory.workspaceId, accountId: f.directory.accountId, deviceId: f.directory.deviceId, displayName: 'Legacy name' });
    await rememberVerifiedProfile(f.client, f.directory, f.state.session.sessionId, () => true);
    f.setCurrent(undefined);
    const [saved] = await f.cards.list();
    assert.equal((await f.cards.list()).length, 1);
    assert.equal(saved!.displayName, 'Saved person');
    assert.deepEqual(saved!.avatar, { shapeId: 'shape-07', colourId: 'coral' });
  } finally { f.cards.close(); }
});

test('directory refresh cannot recreate a forgotten card after logout, session change or navigation epoch change', async () => {
  const f = await fixture();
  try {
    await rememberVerifiedProfile(f.client, f.directory, f.state.session.sessionId, () => true);
    f.setCurrent(undefined);
    await f.cards.remove({ workspaceId: f.directory.workspaceId, accountId: f.directory.accountId, deviceId: f.directory.deviceId });
    await rememberVerifiedProfile(f.client, f.directory, f.state.session.sessionId, () => true);
    f.setCurrent({ ...f.state, session: { ...f.state.session, sessionId: randomUUID() } });
    await rememberVerifiedProfile(f.client, f.directory, f.state.session.sessionId, () => true);
    f.setCurrent(f.state);
    await rememberVerifiedProfile(f.client, f.directory, f.state.session.sessionId, () => false);
    assert.deepEqual(await f.cards.list(), []);
  } finally { f.cards.close(); }
});

test('directory refresh ignores locked, quarantined, mismatched or inactive identities', async () => {
  const f = await fixture();
  try {
    f.setCurrent({ ...f.state, localAccess: 'pairing_required' });
    await rememberVerifiedProfile(f.client, f.directory, f.state.session.sessionId, () => true);
    f.setCurrent(f.state);
    await rememberVerifiedProfile(f.client, f.directory, undefined, () => true);
    for (const change of [{ restoreQuarantine: true }, { workspaceId: randomUUID() }, { accountId: randomUUID() }, { deviceId: randomUUID() },
      { people: f.directory.people.filter(person => person.accountId !== f.directory.accountId) },
      { people: f.directory.people.map(person => ({ ...person, state: 'suspended' as const })) }]) {
      await rememberVerifiedProfile(f.client, { ...f.directory, ...change }, f.state.session.sessionId, () => true);
    }
    assert.deepEqual(await f.cards.list(), []);
  } finally { f.cards.close(); }
});
