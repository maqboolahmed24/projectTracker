import type { ClientRuntime } from '../../src/client/runtime.js';
import type { WorkspaceDirectory } from '../../src/client/directory-crypto.js';

/** Cache only the current verified profile, never another member or a stale read. */
export async function rememberVerifiedProfile(
  client: Pick<ClientRuntime, 'auth' | 'remembered'>,
  directory: WorkspaceDirectory,
  sessionId: string | undefined,
  isCurrent: () => boolean,
): Promise<void> {
  const current = client.auth.current();
  if (!isCurrent() || !sessionId || current?.localAccess !== 'unlocked' || current.session.sessionId !== sessionId ||
    directory.restoreQuarantine || directory.workspaceId !== current.session.workspaceId ||
    directory.accountId !== current.session.accountId || directory.deviceId !== current.session.deviceId) return;
  const profile = directory.people.find(person => person.accountId === current.session.accountId && person.state === 'active');
  if (!profile || !current.session.deviceId) return;
  // No await between the live-session fence and queuing the local transaction.
  await client.remembered.remember({ workspaceId: directory.workspaceId, accountId: directory.accountId,
    deviceId: current.session.deviceId, displayName: profile.displayName, avatar: profile.avatar });
}
