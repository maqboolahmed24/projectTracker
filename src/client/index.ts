/** Browser-only library entry. No server secrets, database code, or frontend screens. */
export * as cryptography from '../shared/crypto.js';
export * as password from './opaque.js';
export * as recovery from './recovery.js';
export { IndexedDeviceStore, wrapDeviceBundle, unwrapDeviceBundle } from './device-store.js';
export { ActivationController, HttpActivationTransport, IndexedActivationStore } from './activation-controller.js';
export { AuthWorkerClient } from './auth-worker-client.js';
export { RememberedProfiles } from './remembered-profiles.js';
export { AuthController, HttpAuthTransport } from './auth-controller.js';
export { verifySecurityHistory } from '../shared/security-history.js';
export { PasswordChangeController, HttpPasswordChangeTransport, IndexedPasswordChangeStore } from './password-change.js';
export { PairingController, HttpPairingTransport, IndexedPairingStore, seedActivationPin } from './pairing.js';
export { openClient } from './runtime.js';
export { RecoveryController, HttpRecoveryTransport, IndexedRecoveryStore } from './recovery-controller.js';
export { EnrolmentController, HttpEnrolmentTransport } from './enrolment-controller.js';
export { IndexedEnrolmentStore } from './enrolment-store.js';
export { RolesController, HttpRolesTransport, IndexedRolesStore } from './roles-controller.js';
export { AccessChangeController, HttpAccessChangeTransport } from './access-change-controller.js';
export { IndexedAccessChangeStore } from './access-change-store.js';
