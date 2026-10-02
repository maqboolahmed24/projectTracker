import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { transaction } from '../src/db.js';
import { EntitlementOperations } from '../src/modules/identity/entitlements.js';
import { projectAuthoritativeWorkspace, withSecurityFence } from '../src/modules/identity/projection.js';
import { readOwnerCustodyKeyMaterial } from '../src/client/pairing.js';
import { base64urlDecode, base64urlEncode, digestObject, encryptContent, randomKey, sealRecipient, signObject } from '../src/shared/crypto.js';
import type { PairingMaterial } from '../src/shared/pairing.js';
import { verifySecurityHistory, type SecurityHistoryInput } from '../src/shared/security-history.js';
import { createScopeProvisionBinding, deriveScopeProvisionPlan, scopeProvisionCustodyHeader, scopeProvisionRecipientHeader,
  scopeProvisionTranscriptDigest, validateScopeProvisionPayload, type ScopeProvisionPayload } from '../src/shared/scope-provision.js';
import { origin, type passwordFixture } from './password-change-fixture.js';

type Fixture = Pick<Awaited<ReturnType<typeof passwordFixture>>,
  'workspaceId' | 'accountId' | 'deviceId' | 'originalBundle' | 'databases' | 'admin' | 'secrets' | 'sessions' | 'auth'> & { origin?: string };

/**
 * CP06 test setup: cryptographically provision an ordinary project scope using
 * the real shared contract and history replay. Only the application project row
 * is a domain fixture; this does not claim a CP07 project-creation HTTP journey.
 */
export async function provisionProjectScope(f: Fixture, input: { projectId?: string; selected?: { accountId: string; roleId: string }[] } = {}) {
  const projectId = input.projectId ?? randomUUID(), operationId = randomUUID();
  const trustedServiceKeys = { [f.secrets.keyId]: await new EntitlementOperations(f.databases, f.secrets).publicSigningKey() };
  return withSecurityFence(f.databases, f.workspaceId, async (lockedApp) => {
    const result = await transaction(f.databases.control, async (c) => {
      await c.query("SET LOCAL synchronous_commit='on'");
      await c.query("SELECT set_config('ukda.workspace_id',$1,true)", [f.workspaceId]);
      const workspace = (await c.query('SELECT * FROM security.workspaces WHERE workspace_id=$1 FOR UPDATE', [f.workspaceId])).rows[0];
      const auth = f.auth(), actor = await f.sessions.resolveCurrent(c, auth.cookieValue, { csrfToken: auth.csrfToken, approved: true, recent: true });
      assert.equal(actor.accountId, f.accountId); assert.equal(actor.deviceId, f.deviceId);
      const objects = (await c.query<PairingMaterial>('SELECT object_id AS id,object_hash AS digest,object_kind AS kind,versioned_object AS value FROM security.staged_objects WHERE workspace_id=$1 AND state=\'committed\'', [f.workspaceId])).rows;
      const genesis = objects.find((o) => o.id === workspace.genesis_object_id)!;
      const transitions = (await c.query('SELECT signed_transition FROM security.security_transitions WHERE workspace_id=$1 AND sequence>1 ORDER BY sequence', [f.workspaceId])).rows.map((r) => r.signed_transition);
      const historyInput: SecurityHistoryInput = { workspaceId: f.workspaceId, origin: f.origin ?? origin, genesisFingerprint: genesis.digest,
        genesis: genesis.value as SecurityHistoryInput['genesis'], transitions, trustedServiceKeys,
        expected: { securityHead: workspace.security_head, securityVersion: workspace.security_version } };
      const history = await verifySecurityHistory(historyInput), profile = history.profiles[f.accountId]!, device = history.devices[f.deviceId]!;
      const now = new Date(), binding = createScopeProvisionBinding({ workspaceId: f.workspaceId, operationId, projectId, selected: input.selected ?? [] }, history,
        { accountId: f.accountId, device: { id: f.deviceId, keyGeneration: device.keyGeneration, signingPublicKey: device.signingPublicKey, recipientPublicKey: device.recipientPublicKey },
          credentialGeneration: profile.credentialGeneration, sessionGeneration: profile.sessionGeneration },
        { issuedAt: now.toISOString(), expiresAt: new Date(now.getTime() + 600000).toISOString() });
      const plan = deriveScopeProvisionPlan(binding, history), held = await readOwnerCustodyKeyMaterial({ accountId: f.accountId, deviceId: f.deviceId, history, materials: objects }, f.originalBundle);
      const projectKey = await randomKey(), custodyKey = await randomKey(), signingKey = base64urlDecode(f.originalBundle.signingPrivateKey);
      const manifest = { ...held.manifest, custodyEpoch: plan.nextCustodyEpoch,
        projectKeys: [...held.manifest.projectKeys, { projectId, keys: [{ epoch: '1', key: base64urlEncode(projectKey) }] }].sort((a, b) => a.projectId.localeCompare(b.projectId)) };
      const custodyId = randomUUID(), custody = { id: custodyId, envelope: await encryptContent(scopeProvisionCustodyHeader(binding, plan, custodyId), manifest, custodyKey, signingKey) };
      const custodyRef = { id: custodyId, digest: await digestObject(custody.envelope), revision: plan.nextCustodyEpoch };
      const deliveries = await Promise.all(plan.recipients.map(async (recipient) => {
        const content = recipient.scope.mode === 'custody'
          ? { version: 1, mode: 'custody', custodyEpoch: plan.nextCustodyEpoch, custodyKey: base64urlEncode(custodyKey), manifest: { id: custodyRef.id, digest: custodyRef.digest } }
          : { version: 1, mode: 'content', scope: 'project', scopeId: projectId, keyEpoch: '1', keys: [{ epoch: '1', key: base64urlEncode(projectKey) }] };
        return { id: randomUUID(), recipient, envelope: await sealRecipient(await scopeProvisionRecipientHeader(binding, plan, recipient), content, signingKey) };
      }));
      const transition = await signObject({ version: 1 as const, purpose: 'ukda.project-scope-provision.v1' as const, binding, plan,
        transcriptDigest: await scopeProvisionTranscriptDigest(binding, plan), custody: custodyRef,
        deliveries: await Promise.all(deliveries.map(async ({ id, recipient, envelope }) => ({ id, recipient, digest: await digestObject(envelope) }))) }, signingKey);
      const payload: ScopeProvisionPayload = { transition, custody, deliveries: deliveries.map(({ id, envelope }) => ({ id, envelope })) };
      await validateScopeProvisionPayload(payload, binding, history);
      const head = await digestObject(transition), version = String(BigInt(history.securityVersion) + 1n);
      const state = await verifySecurityHistory({ ...historyInput, transitions: [...transitions, transition], expected: { securityHead: head, securityVersion: version } });
      for (const object of [{ id: operationId, kind: 'signed_grant', value: transition }, { id: custody.id, kind: 'custody_manifest', value: custody.envelope },
        ...payload.deliveries.map((d) => ({ id: d.id, kind: 'key_envelope', value: d.envelope }))]) {
        await c.query(`INSERT INTO security.staged_objects(workspace_id,object_id,object_kind,object_hash,versioned_object,staged_operation_id,state,committed_security_version)
          VALUES($1,$2,$3,$4,$5,$6,'committed',$7)`, [f.workspaceId, object.id, object.kind, await digestObject(object.value), object.value, operationId, version]);
      }
      await c.query(`INSERT INTO security.security_transitions(workspace_id,sequence,operation_id,previous_head,head,action,actor_kind,actor_profile_id,actor_device_id,signed_transition)
        VALUES($1,$2,$3,$4,$5,'project.scope_provision','device',$6,$7,$8)`, [f.workspaceId, version, operationId, history.securityHead, head, f.accountId, f.deviceId, transition]);
      for (const scope of Object.values(state.scopeHeads)) await c.query(`INSERT INTO security.scope_heads(workspace_id,scope_kind,scope_id,key_epoch,recovery_manifest_object_id,security_version)
        VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(workspace_id,scope_kind,scope_id) DO UPDATE SET key_epoch=EXCLUDED.key_epoch,recovery_manifest_object_id=EXCLUDED.recovery_manifest_object_id,security_version=EXCLUDED.security_version`,
      [f.workspaceId, scope.scope, scope.scopeId, scope.keyEpoch, custody.id, version]);
      await c.query("UPDATE security.grants SET state='revoked',revoked_at=$2 WHERE workspace_id=$1 AND state<>'revoked'", [f.workspaceId, now]);
      for (const person of Object.values(state.profiles).filter((p) => p.active)) {
        for (const scope of person.scopes) {
          const role = person.projectRoles[scope.scopeId];
          await c.query(`INSERT INTO security.grants(workspace_id,grant_id,profile_id,grant_kind,scope_kind,scope_id,generation,permissions,state,signed_grant_object_id,key_manifest_object_id,key_epoch,role_id,role_revision,security_version,created_at,activated_at,expires_at)
            VALUES($1,$2,$3,$4,$5,$6,$7,$8,'active',$9,$10,$11,$12,$13,$14,$15,$15,$16)`,
          [f.workspaceId, randomUUID(), person.accountId, scope.scope === 'project' ? 'project' : person.owner ? 'owner' : 'membership', scope.scope, scope.scope === 'workspace' ? null : scope.scopeId,
            person.sessionGeneration, scope.permissions, operationId, scope.manifests[0]!.id, scope.keyEpoch, scope.scope === 'project' ? role!.id : null, scope.scope === 'project' ? role!.revision : null, version, now, scope.expiresAt]);
        }
      }
      for (const currentDevice of Object.values(state.devices).filter((d) => d.active && state.profiles[d.accountId]?.active)) {
        for (const scope of currentDevice.scopes) await c.query(`INSERT INTO security.grants(workspace_id,grant_id,profile_id,device_id,grant_kind,scope_kind,scope_id,generation,permissions,state,signed_grant_object_id,key_manifest_object_id,key_epoch,security_version,created_at,activated_at,expires_at)
          VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'active',$10,$11,$12,$13,$14,$14,$15)`,
        [f.workspaceId, randomUUID(), currentDevice.accountId, currentDevice.id, scope.scope === 'project' ? 'project' : 'device', scope.scope, scope.scope === 'workspace' ? null : scope.scopeId,
          currentDevice.keyGeneration, scope.permissions, operationId, scope.manifests[0]!.id, scope.keyEpoch, version, now, scope.expiresAt]);
      }
      for (const authority of Object.values(state.recoveryAuthorities).filter((r) => r.active)) await c.query(`UPDATE security.recovery_authorities SET custody_envelope_object_id=$4,custody_epoch=$5
        WHERE workspace_id=$1 AND profile_id=$2 AND generation=$3`, [f.workspaceId, authority.accountId, authority.generation, authority.custodyEnvelope.id, authority.custodyEpoch]);
      await c.query('UPDATE security.workspaces SET security_head=$2,security_version=$3,custody_epoch=$4,current_custody_manifest_object_id=$5,updated_at=$6 WHERE workspace_id=$1',
        [f.workspaceId, head, version, state.custodyEpoch, custody.id, now]);
      return { projectId, projectKey, binding, transition, state, custody, manifest };
    });
    await f.admin.application.query("INSERT INTO app.projects(workspace_id,id,encrypted_envelope) VALUES($1,$2,'{}')", [f.workspaceId, projectId]);
    assert.equal((await projectAuthoritativeWorkspace(f.databases, f.workspaceId, lockedApp)).state, 'ready');
    return result;
  });
}
