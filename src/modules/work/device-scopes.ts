import type { Databases } from '../../db.js';
import { AppError } from '../../errors.js';
import { tenantTransaction, type DataPrincipal } from '../../persistence.js';
import { intersectDeviceScopes, PersonalScopeError, readPersonalScopes } from '../identity/personal-scopes.js';

export type WorkDevicePrincipal = DataPrincipal & { deviceId: string | null };

/** Call inside dataTransaction's shared workspace fence, after current-session validation. */
export async function readWorkDeviceScopes(databases: Databases, principal: WorkDevicePrincipal, now = new Date()) {
  if (!principal.deviceId) throw new AppError('DEVICE_APPROVAL_REQUIRED', 'Approve this device before reading project content', 403);
  try {
    return await tenantTransaction(databases.control, principal.workspaceId, undefined, async (control) => {
      const profile = (await control.query<{ is_owner: boolean }>(
        "SELECT is_owner FROM security.profiles WHERE workspace_id=$1 AND profile_id=$2 AND state='active'",
        [principal.workspaceId, principal.profileId])).rows[0];
      if (!profile) throw new PersonalScopeError();
      const personal = await readPersonalScopes(control, principal.workspaceId, principal.profileId, profile.is_owner, now);
      return intersectDeviceScopes(control, principal.workspaceId, principal.profileId, principal.deviceId!, personal, now);
    });
  } catch (error) {
    if (error instanceof PersonalScopeError) throw new AppError('FORBIDDEN', 'Current device access is unavailable', 403);
    throw error;
  }
}
