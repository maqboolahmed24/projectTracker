import { canonicalJson, base64urlDecode, base64urlEncode, decryptContent, digestObject, encryptContent, randomKey, sealRecipient, signObject } from '../shared/crypto.js';
import { projectCreateContext, projectCreateHeader, projectCreatePayload, projectCreateRequest, projectPrivateData, validateProjectCreatePayload,
  type ProjectCreateContext, type ProjectCreatePayload, type ProjectCreateRequest } from '../shared/project-create.js';
import { deriveScopeProvisionPlan, scopeProvisionCustodyHeader, scopeProvisionRecipientHeader, scopeProvisionTranscriptDigest } from '../shared/scope-provision.js';
import { verifySecurityHistory, type SecurityHistoryInput } from '../shared/security-history.js';
import type { DeviceBundle } from './device-store.js';
import { retainedCustodyManifest } from './access-change-crypto.js';
import { readOwnerCustodyKeyMaterial } from './pairing.js';

export class ProjectCreateClientError extends Error {
  constructor(readonly code: 'INVALID_PROJECT' | 'INCOMPLETE_KEYS' | 'TRUST_REQUIRED' | 'CONFLICT' | 'EXPIRED' | 'NOT_FOUND' | 'CANCELLED' | 'STORAGE') {
    super(`Project creation failed (${code})`); this.name = 'ProjectCreateClientError';
  }
}
const same = (a: unknown, b: unknown) => canonicalJson(a) === canonicalJson(b);
const copy = <T>(value: T): T => JSON.parse(canonicalJson(value)) as T;
function invalid(): never { throw new ProjectCreateClientError('INVALID_PROJECT'); }
export interface PrepareProjectCreateInput { request: ProjectCreateRequest; context: ProjectCreateContext; history: SecurityHistoryInput; name: string }
/** Runs inside the authentication Worker. Only signed ciphertext crosses the Worker response boundary. */
export async function prepareProjectCreate(value: PrepareProjectCreateInput, bundle: DeviceBundle): Promise<ProjectCreatePayload> {
  const input = copy(value), context = projectCreateContext.parse(input.context), binding = context.binding,
    request = projectCreateRequest.parse(input.request), privateData = projectPrivateData.parse({ name: input.name }), state = await verifySecurityHistory(input.history);
  if (!same(request, { workspaceId: binding.workspaceId, operationId: binding.operationId, projectId: binding.projectId }) || binding.selected.length ||
    Date.parse(binding.expiresAt) <= Date.now() || Date.parse(binding.issuedAt) > Date.now() + 30_000 ||
    bundle.signingPublicKey !== binding.authorizer.device.signingPublicKey || bundle.recipientPublicKey !== binding.authorizer.device.recipientPublicKey) invalid();
  const plan = deriveScopeProvisionPlan(binding, state); if (!same(plan, context.plan)) invalid();
  if (plan.recipients.some((recipient) => recipient.scope.expiresAt !== null && Date.parse(recipient.scope.expiresAt) <= Date.now())) throw new ProjectCreateClientError('EXPIRED');
  const held = await readOwnerCustodyKeyMaterial({ accountId: binding.authorizer.accountId, deviceId: binding.authorizer.device.id,
    history: state, materials: context.materials }, bundle);
  if (!same(held.payload.manifest, { id: state.custodyManifest.id, digest: state.custodyManifest.digest })) invalid();
  const previous = retainedCustodyManifest.parse(held.manifest);
  if (previous.custodyEpoch !== state.custodyEpoch || previous.projectKeys.some((entry) => entry.projectId === request.projectId)) invalid();
  for (const head of Object.values(state.scopeHeads)) {
    const keys = head.scope === 'workspace' ? previous.workspaceKeys : previous.projectKeys.find((entry) => entry.projectId === head.scopeId)?.keys;
    if (!keys || !keys.some((entry) => entry.epoch === head.keyEpoch) || keys.some((entry) => BigInt(entry.epoch) > BigInt(head.keyEpoch))) throw new ProjectCreateClientError('INCOMPLETE_KEYS');
  }
  const projectKey = await randomKey(), custodyKey = await randomKey(), signing = base64urlDecode(bundle.signingPrivateKey, 64), publicKey = base64urlDecode(bundle.signingPublicKey, 32);
  try {
    const manifest = retainedCustodyManifest.parse({ ...previous, custodyEpoch: plan.nextCustodyEpoch,
      projectKeys: [...previous.projectKeys, { projectId: request.projectId, keys: [{ epoch: '1', key: base64urlEncode(projectKey) }] }].sort((a, b) => a.projectId.localeCompare(b.projectId, 'en')) });
    const custodyId = crypto.randomUUID(), custodyHeader = scopeProvisionCustodyHeader(binding, plan, custodyId), projectHeader = projectCreateHeader(binding),
      custody = { id: custodyId, envelope: await encryptContent(custodyHeader, manifest, custodyKey, signing) },
      project = { id: request.projectId, envelope: await encryptContent(projectHeader, privateData, projectKey, signing) };
    if (!same(await decryptContent(custody.envelope, custodyKey, publicKey, custodyHeader), manifest) ||
      !same(await decryptContent(project.envelope, projectKey, publicKey, projectHeader), privateData)) invalid();
    const custodyReference = { id: custodyId, digest: await digestObject(custody.envelope), revision: plan.nextCustodyEpoch },
      deliveries: ProjectCreatePayload['deliveries'] = [], descriptors: ProjectCreatePayload['transition']['body']['deliveries'] = [];
    for (const recipient of plan.recipients) {
      const scope = recipient.scope;
      if (scope.expiresAt !== null && Date.parse(scope.expiresAt) <= Date.now()) throw new ProjectCreateClientError('EXPIRED');
      if (scope.mode !== 'custody' && (scope.scope !== 'project' || scope.scopeId !== request.projectId || scope.keyEpoch !== '1')) invalid();
      const plaintext = scope.mode === 'custody' ? { version: 1, mode: 'custody', custodyEpoch: plan.nextCustodyEpoch,
        custodyKey: base64urlEncode(custodyKey), manifest: { id: custodyReference.id, digest: custodyReference.digest } } :
        { version: 1, mode: 'content', scope: 'project', scopeId: request.projectId, keyEpoch: '1', keys: [{ epoch: '1', key: base64urlEncode(projectKey) }] };
      const id = crypto.randomUUID(), envelope = await sealRecipient(await scopeProvisionRecipientHeader(binding, plan, recipient), plaintext, signing);
      deliveries.push({ id, envelope }); descriptors.push({ id, digest: await digestObject(envelope), recipient });
    }
    const transition = await signObject({ version: 1 as const, purpose: 'ukda.project-scope-provision.v1' as const, binding, plan,
      transcriptDigest: await scopeProvisionTranscriptDigest(binding, plan), custody: custodyReference,
      project: { id: project.id, digest: await digestObject(project.envelope), revision: '1' }, deliveries: descriptors }, signing);
    return (await validateProjectCreatePayload(projectCreatePayload.parse({ transition, custody, project, deliveries }), binding, state)).payload;
  } finally { projectKey.fill(0); custodyKey.fill(0); signing.fill(0); }
}
