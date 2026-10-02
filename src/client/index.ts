/** Browser-only library entry. No server secrets, database code, or frontend screens. */
export * as cryptography from '../shared/crypto.js';
export * as password from './opaque.js';
export * as recovery from './recovery.js';
export { IndexedDeviceStore, wrapDeviceBundle, unwrapDeviceBundle } from './device-store.js';
export { ActivationController, HttpActivationTransport, IndexedActivationStore } from './activation-controller.js';
export { avatarSelection, avatarShapeIds, avatarColourIds, avatarColours, DEFAULT_AVATAR, resolveAvatarSelection } from '../shared/avatar.js';
export type { AvatarSelection } from '../shared/avatar.js';
export { ProfileController } from './profile-controller.js';
export { ProfileClientError } from './profile-crypto.js';
export type { CurrentProfile } from './profile-crypto.js';
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

export { ProjectCreateController, HttpProjectCreateTransport } from './project-create-controller.js';
export { IndexedProjectCreateStore } from './project-create-store.js';

export { TeamsController, HttpTeamsTransport } from './teams-controller.js';
export { IndexedTeamsStore } from './teams-store.js';
export type { ReadableTeamChange, ReadableTeamHistory, TeamsPage } from './teams-crypto.js';

export { PlanningController, HttpPlanningTransport } from './planning-controller.js';
export { IndexedPlanningStore } from './planning-store.js';
export type { ExecutePlanningInput, CreateTaskInput } from './planning-controller.js';
export type { PlanningIntent, ReadablePlanning, ReadablePlanningAudit, PlanningPrivateContent } from './planning-crypto.js';

export { CollaborationController, HttpCollaborationTransport } from './collaboration-controller.js';
export { IndexedCollaborationStore } from './collaboration-store.js';
export type { PostCommentInput, PostUpdateInput, HideCollaborationInput, CollaborationReadInput } from './collaboration-controller.js';
export type { ReadableCollaborationEntry } from './collaboration-crypto.js';
export { InboxController, HttpInboxTransport } from './inbox-controller.js';
export type { InboxCommand, InboxReceipt } from '../shared/inbox.js';

export { ReportingController, HttpReportingTransport } from './reporting-controller.js';
export { IndexedReportingStore } from './reporting-store.js';
export { IndexedInboxStore } from './inbox-store.js';
export { WriteError, WriteConflict, assertOnline } from './write-state.js';
export { ReceiptController } from './receipts-controller.js';
export { UpgradeController, HttpUpgradeTransport } from './upgrade-controller.js';
export { IndexedUpgradeStore } from './upgrade-store.js';
export type { UpgradeOperationResult } from './upgrade-controller.js';
export type { ReceiptLookupInput } from './receipts-controller.js';
export type { ReportingLiveState } from './reporting-controller.js';
export type { ReadableReporting } from './reporting-crypto.js';
export type { ReportingScope } from '../shared/reporting.js';
export { calculateProgress, progressClock, canonicalProgressScope } from '../shared/progress.js';

export { ExportController, HttpExportTransport } from './export-controller.js';
export type { ExportDownload } from './export-controller.js';
export { RestorationController, HttpRestorationTransport, IndexedRestorationStore } from './restoration-controller.js';

export { LifecycleController, HttpLifecycleTransport } from './lifecycle-controller.js';
export { IndexedLifecycleStore } from './lifecycle-store.js';

export { DirectoryController } from './directory-controller.js';
export type { WorkspaceDirectory, DirectoryPerson } from './directory-crypto.js';
