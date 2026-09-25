import { z } from 'zod';
import type { DeviceChallenge, DeviceProof } from '../shared/auth.js';
import type { DeviceContext, DeviceWrapper } from './device-store.js';
import type * as opaqueHelpers from './opaque.js';
import type { PreparePasswordChangeInput, VerifyPasswordChangeWrapperInput } from './password-change.js';
import type { PasswordChangePayload } from '../shared/password-change.js';
import type * as pairingHelpers from './pairing.js';
import type * as recoveryHelpers from './recovery-controller.js';
import type * as enrolmentHelpers from './enrolment-controller.js';
import type * as rolesHelpers from './roles-controller.js';
import type * as accessHelpers from './access-change-crypto.js';

export type DeviceProofContext = Omit<DeviceChallenge, 'version' | 'purpose' | 'ceremonyId' | 'nonce' | 'issuedAt' | 'expiresAt'>;
export interface UnlockDeviceInput { context: DeviceContext; wrapper: DeviceWrapper; exportKey: string; proofContext: DeviceProofContext }
export type WorkerLoginResult = Omit<Awaited<ReturnType<typeof opaqueHelpers.finishLogin>>, 'sessionKey'>;
export interface AuthWorkerMethods {
  capabilities: { input: { origin: string }; output: { webAssembly: true; webCrypto: true; indexedDB: true } };
  startRegistration: { input: { password: string }; output: Awaited<ReturnType<typeof opaqueHelpers.startRegistration>> };
  finishRegistration: { input: Parameters<typeof opaqueHelpers.finishRegistration>[0]; output: Awaited<ReturnType<typeof opaqueHelpers.finishRegistration>> };
  startLogin: { input: { password: string }; output: Awaited<ReturnType<typeof opaqueHelpers.startLogin>> };
  finishLogin: { input: Parameters<typeof opaqueHelpers.finishLogin>[0]; output: WorkerLoginResult };
  unlockDevice: { input: UnlockDeviceInput; output: { deviceId: string; signingPublicKey: string; recipientPublicKey: string } };
  deviceProof: { input: { challenge: DeviceChallenge }; output: DeviceProof };
  preparePasswordChange: { input: PreparePasswordChangeInput; output: { payload: PasswordChangePayload; wrapper: DeviceWrapper } };
  verifyPasswordChangeWrapper: { input: VerifyPasswordChangeWrapperInput; output: { verified: true } };
  createPairingDevice: { input: pairingHelpers.PairingDeviceInput; output: Awaited<ReturnType<typeof pairingHelpers.createPairingDevice>> };
  verifyPairingDevice: { input: pairingHelpers.PairingDeviceInput & { wrapper: DeviceWrapper }; output: Awaited<ReturnType<typeof pairingHelpers.verifyPairingDevice>> };
  confirmPairingRecipient: { input: pairingHelpers.PairingRecipientInput; output: Awaited<ReturnType<typeof pairingHelpers.confirmPairingRecipient>> };
  confirmPairingApprover: { input: pairingHelpers.PairingApproverInput; output: Awaited<ReturnType<typeof pairingHelpers.confirmPairingApprover>> };
  preparePairingApproval: { input: pairingHelpers.PreparePairingApprovalInput; output: Awaited<ReturnType<typeof pairingHelpers.preparePairingApproval>> };
  verifyPairingDelivery: { input: pairingHelpers.VerifyPairingDeliveryInput; output: Awaited<ReturnType<typeof pairingHelpers.verifyPairingDelivery>> };
  proveOwnerPhrase: { input: recoveryHelpers.ProveOwnerPhraseInput; output: Awaited<ReturnType<typeof recoveryHelpers.proveOwnerPhrase>> };
  prepareRecoveryDraft: { input: recoveryHelpers.PrepareRecoveryDraftInput; output: Awaited<ReturnType<typeof recoveryHelpers.prepareRecoveryDraft>> };
  verifyRecoveryDraftWrapper: { input: recoveryHelpers.VerifyRecoveryDraftWrapperInput; output: Awaited<ReturnType<typeof recoveryHelpers.verifyRecoveryDraftWrapper>> };
  confirmRecoveryRecipient: { input: recoveryHelpers.ConfirmRecoveryRecipientInput; output: Awaited<ReturnType<typeof recoveryHelpers.confirmRecoveryRecipient>> };
  preparePhraseRecoveryApproval: { input: recoveryHelpers.PreparePhraseRecoveryApprovalInput; output: Awaited<ReturnType<typeof recoveryHelpers.preparePhraseRecoveryApproval>> };
  prepareOwnerRecoveryApproval: { input: recoveryHelpers.PrepareRecoveryApprovalInput; output: Awaited<ReturnType<typeof recoveryHelpers.prepareOwnerRecoveryApproval>> };
  verifyRecoveryDelivery: { input: recoveryHelpers.VerifyRecoveryDeliveryInput; output: Awaited<ReturnType<typeof recoveryHelpers.verifyRecoveryDelivery>> };
  prepareJoinInvitation: { input: enrolmentHelpers.PrepareJoinInvitationInput; output: Awaited<ReturnType<typeof enrolmentHelpers.prepareJoinInvitation>> };
  prepareEnrolmentDraft: { input: enrolmentHelpers.PrepareEnrolmentDraftInput; output: Awaited<ReturnType<typeof enrolmentHelpers.prepareEnrolmentDraft>> };
  verifyEnrolmentDraft: { input: enrolmentHelpers.VerifyEnrolmentDraftInput; output: Awaited<ReturnType<typeof enrolmentHelpers.verifyEnrolmentDraft>> };
  confirmEnrolmentTarget: { input: enrolmentHelpers.VerifyEnrolmentDraftInput & { fingerprint: string }; output: Awaited<ReturnType<typeof enrolmentHelpers.confirmEnrolmentTarget>> };
  prepareEnrolmentApproval: { input: enrolmentHelpers.PrepareEnrolmentApprovalInput; output: Awaited<ReturnType<typeof enrolmentHelpers.prepareEnrolmentApproval>> };
  verifyEnrolmentDelivery: { input: enrolmentHelpers.VerifyEnrolmentDeliveryInput; output: Awaited<ReturnType<typeof enrolmentHelpers.verifyEnrolmentDelivery>> };
  prepareRoleChange: { input: rolesHelpers.PrepareRoleChangeInput; output: Awaited<ReturnType<typeof rolesHelpers.prepareRoleChange>> };
  readRoleLabels: { input: rolesHelpers.ReadRolesInput; output: Awaited<ReturnType<typeof rolesHelpers.readRoleLabels>> };
  prepareAccessChange: { input: accessHelpers.PrepareAccessChangeInput; output: Awaited<ReturnType<typeof accessHelpers.prepareAccessChange>> };
  refreshAccessKeys: { input: accessHelpers.RefreshAccessKeysInput; output: Awaited<ReturnType<typeof accessHelpers.refreshAccessKeys>> };
  clear: { input: Record<string, never>; output: { cleared: true } };
}
export type AuthWorkerMethod = keyof AuthWorkerMethods;
export const workerErrorCode = z.enum(['UNSUPPORTED', 'INVALID_REQUEST', 'PASSWORD_POLICY', 'CONFIGURATION', 'AUTHENTICATION',
  'SERVER_KEY', 'LOCKED', 'CONTEXT_MISMATCH', 'CHALLENGE_EXPIRED', 'INCOMPLETE_KEYS', 'FINGERPRINT_MISMATCH', 'CANCELLED', 'LOGGED_OUT', 'CLOSED', 'INTERNAL']);
export type AuthWorkerErrorCode = z.infer<typeof workerErrorCode>;
export class AuthWorkerError extends Error {
  constructor(readonly code: AuthWorkerErrorCode) { super(`Authentication worker failed (${code})`); this.name = 'AuthWorkerError'; }
}
export const workerRequest = z.strictObject({ version: z.literal(1), id: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
  method: z.enum(['capabilities', 'startRegistration', 'finishRegistration', 'startLogin', 'finishLogin', 'unlockDevice', 'deviceProof', 'preparePasswordChange', 'verifyPasswordChangeWrapper', 'createPairingDevice', 'verifyPairingDevice', 'confirmPairingRecipient', 'confirmPairingApprover', 'preparePairingApproval', 'verifyPairingDelivery', 'proveOwnerPhrase', 'prepareRecoveryDraft', 'verifyRecoveryDraftWrapper', 'confirmRecoveryRecipient', 'preparePhraseRecoveryApproval', 'prepareOwnerRecoveryApproval', 'verifyRecoveryDelivery', 'prepareJoinInvitation', 'prepareEnrolmentDraft', 'verifyEnrolmentDraft', 'confirmEnrolmentTarget', 'prepareEnrolmentApproval', 'verifyEnrolmentDelivery', 'prepareRoleChange', 'readRoleLabels', 'prepareAccessChange', 'refreshAccessKeys', 'clear']), input: z.unknown() });
export const workerResponse = z.discriminatedUnion('ok', [
  z.strictObject({ version: z.literal(1), id: z.number().int().positive(), ok: z.literal(true), result: z.unknown() }),
  z.strictObject({ version: z.literal(1), id: z.number().int().positive(), ok: z.literal(false), code: workerErrorCode }),
]);

export interface AuthWorkerScope {
  addEventListener(type: 'message', listener: (event: MessageEvent<unknown>) => void): void;
  postMessage(message: unknown): void;
}
export interface AuthWorkerEnvironment {
  origin: string; crypto: Crypto | undefined; webAssembly: typeof WebAssembly | undefined; indexedDB: IDBFactory | undefined;
  now?: () => number;
}
function supportedOrigin(value: string): boolean {
  try {
    const url = new URL(value);
    return url.origin === value && (url.protocol === 'https:' || (url.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)));
  } catch { return false; }
}

async function checkIndexedDB(factory: IDBFactory, name: string): Promise<void> {
  let database: IDBDatabase | undefined;
  try {
    database = await new Promise<IDBDatabase>((resolve, reject) => {
      let settled = false; const request = factory.open(name, 1);
      const fail = () => { settled = true; reject(new AuthWorkerError('UNSUPPORTED')); };
      request.onblocked = fail; request.onerror = fail;
      request.onupgradeneeded = () => {
        try { request.result.createObjectStore('probe'); } catch { request.transaction?.abort(); fail(); }
      };
      request.onsuccess = () => { if (settled) request.result.close(); else resolve(request.result); };
    });
    await new Promise<void>((resolve, reject) => {
      const transaction = database!.transaction('probe', 'readwrite');
      const store = transaction.objectStore('probe'); let verified = false;
      store.put('capability-check', 'probe');
      const read = store.get('probe'); read.onsuccess = () => { verified = read.result === 'capability-check'; };
      transaction.onabort = () => reject(new AuthWorkerError('UNSUPPORTED'));
      transaction.oncomplete = () => verified ? resolve() : reject(new AuthWorkerError('UNSUPPORTED'));
    });
  } finally {
    database?.close();
    await new Promise<void>((resolve, reject) => {
      const request = factory.deleteDatabase(name);
      request.onsuccess = () => resolve(); request.onerror = request.onblocked = () => reject(new AuthWorkerError('UNSUPPORTED'));
    });
  }
}
/** Probe actual operations; missing or broken facilities never select weaker cryptography. */
export async function checkAuthWorkerCapabilities(environment: AuthWorkerEnvironment): Promise<void> {
  try {
    if (!supportedOrigin(environment.origin) || !environment.crypto?.subtle || !environment.crypto.getRandomValues ||
      !environment.webAssembly?.compile || !environment.webAssembly.instantiate || !environment.indexedDB) throw new Error();
    const nonce = environment.crypto.getRandomValues(new Uint8Array(16));
    const hash = await environment.crypto.subtle.digest('SHA-256', nonce);
    if (hash.byteLength !== 32) throw new Error();
    const module = await environment.webAssembly.compile(Uint8Array.of(0, 97, 115, 109, 1, 0, 0, 0));
    await environment.webAssembly.instantiate(module);
    await checkIndexedDB(environment.indexedDB, `ukda-capability-${Array.from(nonce, (byte) => byte.toString(16).padStart(2, '0')).join('')}`);
    nonce.fill(0);
  } catch { throw new AuthWorkerError('UNSUPPORTED'); }
}

type CachedDevice = { context: DeviceProofContext; signing: Uint8Array; recipient: Uint8Array };
/**
 * Install only inside a dedicated Worker. Dynamic imports follow capability checks,
 * so lack of WebAssembly cannot silently move password work to the main thread.
 * Password/OPAQUE strings are never stored; returned export keys are ephemeral and
 * their caller must release references after wrapping/unlocking and on logout.
 */
export function installAuthWorker(scope: AuthWorkerScope, environment: AuthWorkerEnvironment): { clear(): void } {
  let initialization: Promise<void> | undefined;
  let epoch = 0;
  let cached: CachedDevice | undefined;
  function clear() { epoch++; cached?.signing.fill(0); cached?.recipient.fill(0); cached = undefined; }
  function initialize() {
    initialization ??= (async () => {
      await checkAuthWorkerCapabilities(environment);
      try {
        const [opaque, crypto] = await Promise.all([import('@serenity-kit/opaque'), import('../shared/crypto.js')]);
        await Promise.all([opaque.ready, crypto.ready]);
      } catch { throw new AuthWorkerError('UNSUPPORTED'); }
    })();
    return initialization;
  }
  async function execute(method: AuthWorkerMethod, input: unknown, startedEpoch: number): Promise<unknown> {
    if (method === 'capabilities') {
      const requested = z.strictObject({ origin: z.string() }).parse(input);
      if (requested.origin !== environment.origin) throw new AuthWorkerError('CONTEXT_MISMATCH');
      await initialize();
      return { webAssembly: true, webCrypto: true, indexedDB: true };
    }
    await initialize();
    if (epoch !== startedEpoch) throw new AuthWorkerError('CANCELLED');
    if (method === 'startRegistration' || method === 'startLogin') {
      const accepted = z.strictObject({ password: z.string().max(2048) }).parse(input);
      const helpers = await import('./opaque.js');
      return method === 'startRegistration' ? helpers.startRegistration(accepted.password) : helpers.startLogin(accepted.password);
    }
    if (method === 'finishRegistration' || method === 'finishLogin') {
      const helpers = await import('./opaque.js');
      const { binary } = await import('../shared/contracts.js');
      const configuration = z.strictObject({ configId: z.literal(helpers.OPAQUE_CONFIG_ID), setupId: z.string().min(1).max(128),
        serverStaticPublicKey: binary(32), identifiers: z.strictObject({ client: z.string().max(256), server: z.string().max(256) }),
        keyStretching: z.literal(helpers.OPAQUE_KEY_STRETCHING) });
      const base = z.strictObject({ password: z.string().max(2048), configuration });
      if (method === 'finishRegistration') {
        const accepted = base.extend({ clientRegistrationState: binary(1, 4096), registrationResponse: binary(1, 4096) }).parse(input);
        return helpers.finishRegistration(accepted);
      }
      const accepted = base.extend({ clientLoginState: binary(1, 4096), loginResponse: binary(1, 4096) }).parse(input);
      const { sessionKey: _sessionKey, ...result } = await helpers.finishLogin(accepted);
      // The OPAQUE shared session key is not the application's cookie; it is not needed outside this Worker.
      return result;
    }
    const crypto = await import('../shared/crypto.js');
    const auth = await import('../shared/auth.js');
    // Challenge time refinements apply only to a complete challenge, not its pinned authority context.
    const { version: _versionSchema, purpose: _purposeSchema, ceremonyId: _ceremonySchema, nonce: _nonceSchema,
      issuedAt: _issuedSchema, expiresAt: _expiresSchema, ...authorityShape } = auth.deviceChallenge.shape;
    const contextSchema = z.strictObject(authorityShape);
    if (method === 'preparePasswordChange' || method === 'verifyPasswordChangeWrapper') {
      const helpers = await import('./password-change.js');
      if (method === 'verifyPasswordChangeWrapper') {
        const accepted = helpers.verifyPasswordChangeWrapperInput.parse(input);
        if (accepted.binding.origin !== environment.origin) throw new AuthWorkerError('CONTEXT_MISMATCH');
        return helpers.verifyPasswordChangeWrapper(accepted);
      }
      const accepted = helpers.preparePasswordChangeInput.parse(input);
      if (!cached) throw new AuthWorkerError('LOCKED');
      const binding = accepted.binding, context = cached.context;
      if (binding.origin !== environment.origin || binding.workspaceId !== context.workspaceId ||
        binding.accountId !== context.accountId || binding.deviceId !== context.deviceId ||
        binding.credentialGeneration !== context.credentialGeneration || binding.keyGeneration !== context.keyGeneration ||
        binding.signingPublicKey !== context.signingPublicKey || binding.recipientPublicKey !== context.recipientPublicKey) {
        throw new AuthWorkerError('CONTEXT_MISMATCH');
      }
      const now = environment.now?.() ?? Date.now();
      if (Date.parse(binding.expiresAt) <= now || Date.parse(binding.issuedAt) > now + 30000) throw new AuthWorkerError('CHALLENGE_EXPIRED');
      return helpers.preparePasswordChange(accepted, {
        signingPrivateKey: crypto.base64urlEncode(cached.signing), recipientPrivateKey: crypto.base64urlEncode(cached.recipient),
        signingPublicKey: context.signingPublicKey, recipientPublicKey: context.recipientPublicKey,
      });
    }
    if (['createPairingDevice', 'verifyPairingDevice', 'confirmPairingRecipient', 'confirmPairingApprover', 'preparePairingApproval', 'verifyPairingDelivery'].includes(method)) {
      const helpers = await import('./pairing.js');
      if (method === 'createPairingDevice') return helpers.createPairingDevice(helpers.pairingDeviceInput.parse(input));
      if (method === 'verifyPairingDevice') {
        const { deviceWrapper } = await import('./device-store.js');
        return helpers.verifyPairingDevice(helpers.pairingDeviceInput.extend({ wrapper: deviceWrapper }).parse(input));
      }
      if (method === 'confirmPairingRecipient') {
        const accepted = helpers.pairingRecipientInput.parse(input);
        if (accepted.transcript.origin !== environment.origin) throw new AuthWorkerError('CONTEXT_MISMATCH');
        return helpers.confirmPairingRecipient(accepted);
      }
      if (!cached) throw new AuthWorkerError('LOCKED');
      const accepted = input as pairingHelpers.PairingApproverInput | pairingHelpers.VerifyPairingDeliveryInput;
      const transcript = 'transcript' in accepted ? accepted.transcript : accepted.delivery?.receipt.grant.body.transcript;
      const { pairingTranscript } = await import('../shared/pairing.js');
      const binding = pairingTranscript.parse(transcript), context = cached.context;
      const recipient = method === 'verifyPairingDelivery';
      const device = recipient ? binding.device : binding.approverDevice;
      const latest = await (await import('../shared/security-history.js')).verifySecurityHistory(accepted.history);
      const authority = latest;
      if (binding.origin !== environment.origin || binding.workspaceId !== context.workspaceId ||
        (recipient ? binding.accountId : binding.approverAccountId) !== context.accountId || device.id !== context.deviceId ||
        device.keyGeneration !== context.keyGeneration || device.signingPublicKey !== context.signingPublicKey || device.recipientPublicKey !== context.recipientPublicKey ||
        (recipient ? binding.credentialGeneration : binding.approverCredentialGeneration) !== context.credentialGeneration ||
        (recipient ? binding.sessionGeneration : binding.approverSessionGeneration) !== context.sessionGeneration ||
        authority.dataGeneration !== context.dataGeneration || authority.custodyEpoch !== context.custodyEpoch ||
        (authority.ownershipVersion !== context.ownershipVersion && (recipient || BigInt(authority.ownershipVersion) < BigInt(context.ownershipVersion))) ||
        (recipient && (latest.securityHead !== context.securityHead || latest.securityVersion !== context.securityVersion))) {
        throw new AuthWorkerError('CONTEXT_MISMATCH');
      }
      const bundle = { signingPrivateKey: crypto.base64urlEncode(cached.signing), recipientPrivateKey: crypto.base64urlEncode(cached.recipient),
        signingPublicKey: context.signingPublicKey, recipientPublicKey: context.recipientPublicKey };
      if (method === 'confirmPairingApprover') return helpers.confirmPairingApprover(input as pairingHelpers.PairingApproverInput, bundle);
      if (method === 'preparePairingApproval') return helpers.preparePairingApproval(input as pairingHelpers.PreparePairingApprovalInput, bundle);
      return helpers.verifyPairingDelivery(input as pairingHelpers.VerifyPairingDeliveryInput, bundle);
    }
    if (['proveOwnerPhrase', 'prepareRecoveryDraft', 'verifyRecoveryDraftWrapper', 'confirmRecoveryRecipient', 'preparePhraseRecoveryApproval', 'prepareOwnerRecoveryApproval', 'verifyRecoveryDelivery'].includes(method)) {
      const helpers = await import('./recovery-controller.js');
      const contracts = await import('../shared/recovery.js');
      const accepted = input as recoveryHelpers.PrepareRecoveryDraftInput & recoveryHelpers.PreparePhraseRecoveryApprovalInput & recoveryHelpers.VerifyRecoveryDeliveryInput & recoveryHelpers.ProveOwnerPhraseInput;
      const transcript = accepted.draft?.transcript ?? accepted.delivery?.receipt.transition.body.transcript;
      const binding = contracts.recoveryBinding.parse(accepted.binding ?? accepted.challenge?.binding ?? transcript?.binding);
      if (binding.origin !== environment.origin) throw new AuthWorkerError('CONTEXT_MISMATCH');
      if (method === 'proveOwnerPhrase') return helpers.proveOwnerPhrase(accepted);
      if (method === 'prepareRecoveryDraft') return helpers.prepareRecoveryDraft(accepted);
      if (method === 'verifyRecoveryDraftWrapper') return helpers.verifyRecoveryDraftWrapper(accepted);
      if (method === 'confirmRecoveryRecipient') return helpers.confirmRecoveryRecipient(accepted);
      if (method === 'preparePhraseRecoveryApproval') return helpers.preparePhraseRecoveryApproval(accepted);
      if (!cached) throw new AuthWorkerError('LOCKED');
      const context = cached.context, recipient = method === 'verifyRecoveryDelivery';
      const authority = binding.authorizer;
      if (!recipient && authority.kind !== 'owner_reset') throw new AuthWorkerError('CONTEXT_MISMATCH');
      const device = recipient ? transcript!.device : authority.kind === 'owner_reset' ? authority.device : undefined;
      const latest = await (await import('../shared/security-history.js')).verifySecurityHistory(accepted.history);
      if (!device || binding.workspaceId !== context.workspaceId || device.id !== context.deviceId || device.keyGeneration !== context.keyGeneration ||
        device.signingPublicKey !== context.signingPublicKey || device.recipientPublicKey !== context.recipientPublicKey ||
        (recipient ? binding.accountId : authority.accountId) !== context.accountId ||
        (recipient ? binding.nextCredentialGeneration : authority.kind === 'owner_reset' ? authority.credentialGeneration : '') !== context.credentialGeneration ||
        (recipient ? binding.nextSessionGeneration : authority.kind === 'owner_reset' ? authority.sessionGeneration : '') !== context.sessionGeneration ||
        latest.dataGeneration !== context.dataGeneration || latest.custodyEpoch !== context.custodyEpoch ||
        (latest.ownershipVersion !== context.ownershipVersion && (recipient || BigInt(latest.ownershipVersion) < BigInt(context.ownershipVersion))) ||
        (recipient && (latest.securityHead !== context.securityHead || latest.securityVersion !== context.securityVersion))) throw new AuthWorkerError('CONTEXT_MISMATCH');
      const bundle = { signingPrivateKey: crypto.base64urlEncode(cached.signing), recipientPrivateKey: crypto.base64urlEncode(cached.recipient),
        signingPublicKey: context.signingPublicKey, recipientPublicKey: context.recipientPublicKey };
      return recipient ? helpers.verifyRecoveryDelivery(accepted, bundle) : helpers.prepareOwnerRecoveryApproval(accepted, bundle);
    }
    if (['prepareJoinInvitation', 'prepareEnrolmentDraft', 'verifyEnrolmentDraft', 'confirmEnrolmentTarget', 'prepareEnrolmentApproval', 'verifyEnrolmentDelivery'].includes(method)) {
      const helpers = await import('./enrolment-controller.js');
      const accepted = input as enrolmentHelpers.PrepareJoinInvitationInput & enrolmentHelpers.PrepareEnrolmentDraftInput &
        enrolmentHelpers.VerifyEnrolmentDraftInput & enrolmentHelpers.PrepareEnrolmentApprovalInput & enrolmentHelpers.VerifyEnrolmentDeliveryInput & { fingerprint: string };
      if (accepted.history?.origin !== environment.origin) throw new AuthWorkerError('CONTEXT_MISMATCH');
      const needsCachedDevice = method === 'prepareJoinInvitation' || method === 'prepareEnrolmentApproval' || method === 'verifyEnrolmentDelivery' ||
        (method === 'prepareEnrolmentDraft' && accepted.mode === 'promotion');
      let bundle: import('./device-store.js').DeviceBundle | undefined;
      if (needsCachedDevice) {
        if (!cached) throw new AuthWorkerError('LOCKED');
        const state = await (await import('../shared/security-history.js')).verifySecurityHistory(accepted.history), context = cached.context,
          profile = state.profiles[context.accountId], device = state.devices[context.deviceId];
        if (state.workspaceId !== context.workspaceId || !profile?.active || !device?.active || device.accountId !== context.accountId ||
          device.keyGeneration !== context.keyGeneration || device.signingPublicKey !== context.signingPublicKey || device.recipientPublicKey !== context.recipientPublicKey ||
          profile.credentialGeneration !== context.credentialGeneration || profile.sessionGeneration !== context.sessionGeneration ||
          state.dataGeneration !== context.dataGeneration || state.custodyEpoch !== context.custodyEpoch ||
          (state.ownershipVersion !== context.ownershipVersion && (method === 'verifyEnrolmentDelivery' || BigInt(state.ownershipVersion) < BigInt(context.ownershipVersion))) ||
          (method === 'verifyEnrolmentDelivery' && (state.securityHead !== context.securityHead || state.securityVersion !== context.securityVersion))) throw new AuthWorkerError('CONTEXT_MISMATCH');
        bundle = { signingPrivateKey: crypto.base64urlEncode(cached.signing), recipientPrivateKey: crypto.base64urlEncode(cached.recipient),
          signingPublicKey: context.signingPublicKey, recipientPublicKey: context.recipientPublicKey };
        if (method === 'prepareEnrolmentDraft' && accepted.mode === 'promotion' &&
          (accepted.input.binding.accountId !== context.accountId || accepted.input.deviceId !== context.deviceId)) throw new AuthWorkerError('CONTEXT_MISMATCH');
      }
      if (method === 'prepareJoinInvitation') return helpers.prepareJoinInvitation(accepted, bundle!);
      if (method === 'prepareEnrolmentDraft') return helpers.prepareEnrolmentDraft(accepted);
      if (method === 'verifyEnrolmentDraft') return helpers.verifyEnrolmentDraft(accepted);
      if (method === 'confirmEnrolmentTarget') return helpers.confirmEnrolmentTarget(accepted);
      if (method === 'prepareEnrolmentApproval') return helpers.prepareEnrolmentApproval(accepted, bundle!);
      return helpers.verifyEnrolmentDelivery(accepted, bundle!);
    }
    if (method === 'prepareRoleChange' || method === 'readRoleLabels') {
      if (!cached) throw new AuthWorkerError('LOCKED');
      const helpers = await import('./roles-controller.js');
      const accepted = input as rolesHelpers.PrepareRoleChangeInput & rolesHelpers.ReadRolesInput;
      if (accepted.history?.origin !== environment.origin) throw new AuthWorkerError('CONTEXT_MISMATCH');
      const state = await (await import('../shared/security-history.js')).verifySecurityHistory(accepted.history), context = cached.context,
        profile = state.profiles[context.accountId], device = state.devices[context.deviceId];
      if (state.workspaceId !== context.workspaceId || !profile?.active || !profile.owner || !device?.active || device.accountId !== context.accountId ||
        device.keyGeneration !== context.keyGeneration || device.signingPublicKey !== context.signingPublicKey || device.recipientPublicKey !== context.recipientPublicKey ||
        profile.credentialGeneration !== context.credentialGeneration || profile.sessionGeneration !== context.sessionGeneration ||
        state.dataGeneration !== context.dataGeneration || state.custodyEpoch !== context.custodyEpoch ||
        BigInt(state.ownershipVersion) < BigInt(context.ownershipVersion) || BigInt(state.securityVersion) < BigInt(context.securityVersion) ||
        (state.securityVersion === context.securityVersion && state.securityHead !== context.securityHead) ||
        (method === 'prepareRoleChange' ? accepted.context.binding.authorizer.accountId !== context.accountId ||
          accepted.context.binding.authorizer.device.id !== context.deviceId : accepted.accountId !== context.accountId || accepted.deviceId !== context.deviceId)) throw new AuthWorkerError('CONTEXT_MISMATCH');
      const bundle = { signingPrivateKey: crypto.base64urlEncode(cached.signing), recipientPrivateKey: crypto.base64urlEncode(cached.recipient),
        signingPublicKey: context.signingPublicKey, recipientPublicKey: context.recipientPublicKey };
      return method === 'prepareRoleChange' ? helpers.prepareRoleChange(accepted, bundle) : helpers.readRoleLabels(accepted, bundle);
    }
    if (method === 'prepareAccessChange' || method === 'refreshAccessKeys') {
      if (!cached) throw new AuthWorkerError('LOCKED');
      const helpers = await import('./access-change-crypto.js');
      const accepted = input as accessHelpers.PrepareAccessChangeInput & accessHelpers.RefreshAccessKeysInput;
      if (accepted.history?.origin !== environment.origin) throw new AuthWorkerError('CONTEXT_MISMATCH');
      const state = await (await import('../shared/security-history.js')).verifySecurityHistory(accepted.history), context = cached.context,
        profile = state.profiles[context.accountId], device = state.devices[context.deviceId], refreshing = method === 'refreshAccessKeys';
      if (state.workspaceId !== context.workspaceId || !profile?.active || !device?.active || device.accountId !== context.accountId ||
        device.keyGeneration !== context.keyGeneration || device.signingPublicKey !== context.signingPublicKey || device.recipientPublicKey !== context.recipientPublicKey ||
        profile.credentialGeneration !== context.credentialGeneration || profile.sessionGeneration !== context.sessionGeneration || state.dataGeneration !== context.dataGeneration ||
        BigInt(state.securityVersion) < BigInt(context.securityVersion) || (state.securityVersion === context.securityVersion && state.securityHead !== context.securityHead) ||
        BigInt(state.ownershipVersion) < BigInt(context.ownershipVersion) || BigInt(state.custodyEpoch) < BigInt(context.custodyEpoch) ||
        (!refreshing && (!profile.owner || state.custodyEpoch !== context.custodyEpoch || accepted.context.binding.authorizer.accountId !== context.accountId ||
          accepted.context.binding.authorizer.device.id !== context.deviceId)) ||
        (refreshing && (accepted.delivery.accountId !== context.accountId || accepted.delivery.deviceId !== context.deviceId))) throw new AuthWorkerError('CONTEXT_MISMATCH');
      const bundle = { signingPrivateKey: crypto.base64urlEncode(cached.signing), recipientPrivateKey: crypto.base64urlEncode(cached.recipient),
        signingPublicKey: context.signingPublicKey, recipientPublicKey: context.recipientPublicKey };
      if (!refreshing) return helpers.prepareAccessChange(accepted, bundle);
      const result = await helpers.refreshAccessKeys(accepted, bundle);
      if (!cached || epoch !== startedEpoch) throw new AuthWorkerError('CANCELLED');
      // Advance public key-epoch pins only after actual current ciphertext decryption.
      // Grant identity is not invented; a future device challenge still needs its exact authoritative context.
      cached.context = { ...context, securityHead: state.securityHead, securityVersion: state.securityVersion,
        custodyEpoch: state.custodyEpoch, ownershipVersion: state.ownershipVersion };
      return result;
    }
    if (method === 'unlockDevice') {
      const { deviceContext, deviceWrapper, unwrapDeviceBundle } = await import('./device-store.js');
      const accepted = z.strictObject({ context: deviceContext, wrapper: deviceWrapper,
        exportKey: z.string().max(2048), proofContext: contextSchema }).parse(input);
      const context = accepted.proofContext;
      if (context.origin !== environment.origin || context.workspaceId !== accepted.context.workspaceId ||
        context.accountId !== accepted.context.accountId || context.deviceId !== accepted.context.deviceId ||
        context.credentialGeneration !== accepted.context.credentialGeneration) throw new AuthWorkerError('CONTEXT_MISMATCH');
      const bundle = await unwrapDeviceBundle(accepted.context, accepted.wrapper, accepted.exportKey);
      if (bundle.signingPublicKey !== context.signingPublicKey || bundle.recipientPublicKey !== context.recipientPublicKey) throw new AuthWorkerError('CONTEXT_MISMATCH');
      const signing = crypto.base64urlDecode(bundle.signingPrivateKey, 64);
      const recipient = crypto.base64urlDecode(bundle.recipientPrivateKey, 32);
      if (epoch !== startedEpoch) { signing.fill(0); recipient.fill(0); throw new AuthWorkerError('CANCELLED'); }
      cached = { context, signing, recipient };
      return { deviceId: context.deviceId, signingPublicKey: context.signingPublicKey, recipientPublicKey: context.recipientPublicKey };
    }
    if (method === 'deviceProof') {
      const { challenge } = z.strictObject({ challenge: auth.deviceChallenge }).parse(input);
      if (!cached) throw new AuthWorkerError('LOCKED');
      const { version: _version, purpose: _purpose, ceremonyId: _ceremonyId, nonce: _nonce, issuedAt, expiresAt, ...context } = challenge;
      if (crypto.canonicalJson(context) !== crypto.canonicalJson(cached.context)) throw new AuthWorkerError('CONTEXT_MISMATCH');
      const issued = Date.parse(issuedAt); const expires = Date.parse(expiresAt); const now = environment.now?.() ?? Date.now();
      if (!(issued < expires) || expires <= now || expires - issued > 120_000 || issued > now + 30_000) throw new AuthWorkerError('CHALLENGE_EXPIRED');
      return crypto.signObject(challenge, cached.signing);
    }
    throw new AuthWorkerError('INVALID_REQUEST');
  }
  scope.addEventListener('message', (event) => {
    const parsed = workerRequest.safeParse(event.data);
    if (!parsed.success) return;
    const { id, method, input } = parsed.data;
    if (method === 'clear') {
      clear(); scope.postMessage({ version: 1, id, ok: true, result: { cleared: true } }); return;
    }
    // Selecting another device invalidates all pending work against the previous key cache.
    if (method === 'unlockDevice') clear();
    const startedEpoch = epoch;
    void execute(method, input, startedEpoch).then((result) => {
      if (epoch !== startedEpoch) throw new AuthWorkerError('CANCELLED');
      scope.postMessage({ version: 1, id, ok: true, result });
    }).catch((error: unknown) => {
      let code: AuthWorkerErrorCode = 'INTERNAL';
      if (error instanceof AuthWorkerError) code = error.code;
      else if (error instanceof z.ZodError) code = 'INVALID_REQUEST';
      else if (error && typeof error === 'object' && 'name' in error && 'code' in error) {
        if (error.name === 'ClientOpaqueError' && workerErrorCode.safeParse(error.code).success) code = error.code as AuthWorkerErrorCode;
        else if (error.name === 'DeviceStoreError') code = 'AUTHENTICATION';
        else if (['PairingClientError', 'RecoveryClientError', 'EnrolmentClientError', 'EnrolmentCryptoError', 'RolesClientError', 'AccessChangeClientError'].includes(String(error.name))) code = ['INCOMPLETE_KEYS', 'FINGERPRINT_MISMATCH'].includes(String(error.code)) ? error.code as AuthWorkerErrorCode : 'CONTEXT_MISMATCH';
      }
      scope.postMessage({ version: 1, id, ok: false, code });
    });
  });
  return { clear };
}

// A separate module-worker entry is bundled for browsers; importing its types never installs a Window handler.
if (typeof document === 'undefined' && typeof globalThis.postMessage === 'function' && typeof globalThis.addEventListener === 'function' && 'importScripts' in globalThis) {
  installAuthWorker(globalThis, { origin: globalThis.location.origin, crypto: globalThis.crypto,
    webAssembly: globalThis.WebAssembly, indexedDB: globalThis.indexedDB });
}
