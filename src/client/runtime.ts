import { ActivationController, HttpActivationTransport, IndexedActivationStore } from './activation-controller.js';
import { AuthController, AuthenticatedHttp, HttpAuthTransport } from './auth-controller.js';
import { AuthWorkerClient } from './auth-worker-client.js';
import { IndexedDeviceStore } from './device-store.js';
import { PairingController, HttpPairingTransport, IndexedPairingStore, seedActivationPin } from './pairing.js';
import { PasswordChangeController, HttpPasswordChangeTransport, IndexedPasswordChangeStore } from './password-change.js';
import { RememberedProfiles } from './remembered-profiles.js';
import { RecoveryController, HttpRecoveryTransport, IndexedRecoveryStore } from './recovery-controller.js';
import { EnrolmentController, HttpEnrolmentTransport } from './enrolment-controller.js';
import { IndexedEnrolmentStore } from './enrolment-store.js';
import { RolesController, HttpRolesTransport, IndexedRolesStore } from './roles-controller.js';
import { AccessChangeController, HttpAccessChangeTransport } from './access-change-controller.js';
import { IndexedAccessChangeStore } from './access-change-store.js';
import { ProjectCreateController, HttpProjectCreateTransport } from './project-create-controller.js';
import { IndexedProjectCreateStore } from './project-create-store.js';
import { TeamsController, HttpTeamsTransport } from './teams-controller.js';
import { IndexedTeamsStore } from './teams-store.js';
import { PlanningController, HttpPlanningTransport } from './planning-controller.js';
import { IndexedPlanningStore } from './planning-store.js';
import { CollaborationController, HttpCollaborationTransport } from './collaboration-controller.js';
import { IndexedCollaborationStore } from './collaboration-store.js';
import { InboxController, HttpInboxTransport } from './inbox-controller.js';
import { ReportingController, HttpReportingTransport } from './reporting-controller.js';
import { IndexedReportingStore } from './reporting-store.js';
import { IndexedInboxStore } from './inbox-store.js';
import { ReceiptController } from './receipts-controller.js';
import { UpgradeController, HttpUpgradeTransport } from './upgrade-controller.js';
import { IndexedUpgradeStore } from './upgrade-store.js';
import { ExportController, HttpExportTransport } from './export-controller.js';
import { ProfileController } from './profile-controller.js';
import { DirectoryController } from './directory-controller.js';
import { LifecycleController, HttpLifecycleTransport } from './lifecycle-controller.js';
import { IndexedLifecycleStore } from './lifecycle-store.js';
import { RestorationController, HttpRestorationTransport, IndexedRestorationStore } from './restoration-controller.js';

/** Browser client composition without presentation. All lifecycle hooks are installed here. */
export async function openClient(options: { origin?: string; trustedServiceKeys?: Record<string, string> } = {}) {
  const worker = new AuthWorkerClient(options.origin ? { origin: options.origin } : {});
  const stores: { close(): void }[] = [];
  const detach: (() => void)[] = [];
  try {
    await worker.ready();
    const origin = worker.origin;
    const devices = await IndexedDeviceStore.open(); stores.push(devices);
    const remembered = await RememberedProfiles.open(origin); stores.push(remembered);
    const pendingActivation = await IndexedActivationStore.open(); stores.push(pendingActivation);
    const changes = await IndexedPasswordChangeStore.open(); stores.push(changes);
    const pairingRecords = await IndexedPairingStore.open(origin); stores.push(pairingRecords);
    const recoveryRecords = await IndexedRecoveryStore.open(origin); stores.push(recoveryRecords);
    const enrolmentRecords = await IndexedEnrolmentStore.open(origin); stores.push(enrolmentRecords);
    const roleOperations = await IndexedRolesStore.open(origin); stores.push(roleOperations);
    const accessOperations = await IndexedAccessChangeStore.open(origin); stores.push(accessOperations);
    const projectOperations = await IndexedProjectCreateStore.open(origin); stores.push(projectOperations);
    const teamOperations = await IndexedTeamsStore.open(origin); stores.push(teamOperations);
    const planningOperations = await IndexedPlanningStore.open(origin); stores.push(planningOperations);
    const collaborationOperations = await IndexedCollaborationStore.open(origin); stores.push(collaborationOperations);
    const reportingOperations = await IndexedReportingStore.open(origin); stores.push(reportingOperations);
    const inboxOperations = await IndexedInboxStore.open(origin); stores.push(inboxOperations);
    const upgradeOperations = await IndexedUpgradeStore.open(origin); stores.push(upgradeOperations);
    const restorationOperations = await IndexedRestorationStore.open(origin); stores.push(restorationOperations);
    const lifecycleOperations = await IndexedLifecycleStore.open(origin); stores.push(lifecycleOperations);
    const auth = new AuthController(new HttpAuthTransport(origin), worker, devices, remembered);
    const receipts = new ReceiptController(auth,new AuthenticatedHttp(origin));detach.push(receipts.attachAuthLifecycle());
    const activation = new ActivationController(new HttpActivationTransport(origin), pendingActivation, devices,
      { onVerifiedReceipt: async (receipt, genesis) => { await seedActivationPin(pairingRecords, genesis, receipt); } });
    const passwordChanges = new PasswordChangeController({ devices, changes, worker,
      transport: new HttpPasswordChangeTransport({ origin, csrfToken: () => auth.current()?.session.csrfToken }) });
    const pairing = new PairingController(auth, new HttpPairingTransport(origin), devices, pairingRecords,
      { remembered, ...(options.trustedServiceKeys ? { trustedServiceKeys: { ...options.trustedServiceKeys } } : {}) });
    const recoveries = new RecoveryController(auth, new HttpRecoveryTransport(origin, () => auth.current()?.session.csrfToken),
      devices, recoveryRecords, pairingRecords,
      { ...(options.trustedServiceKeys ? { trustedServiceKeys: { ...options.trustedServiceKeys } } : {}) });
    const enrolments = new EnrolmentController(auth, new HttpEnrolmentTransport(origin, () => auth.current()?.session.csrfToken),
      devices, enrolmentRecords, pairingRecords, { remembered, ...(options.trustedServiceKeys ? { trustedServiceKeys: { ...options.trustedServiceKeys } } : {}) });
    const roles = new RolesController(auth, new HttpRolesTransport(origin, () => auth.current()?.session.csrfToken), roleOperations, pairingRecords,
      { ...(options.trustedServiceKeys ? { trustedServiceKeys: { ...options.trustedServiceKeys } } : {}) });
    const accessChanges = new AccessChangeController(auth, new HttpAccessChangeTransport(origin, () => auth.current()?.session.csrfToken), accessOperations, pairingRecords,
      { ...(options.trustedServiceKeys ? { trustedServiceKeys: { ...options.trustedServiceKeys } } : {}) });
    const lifecycle = new LifecycleController(auth, new HttpLifecycleTransport(origin, () => auth.current()?.session.csrfToken), lifecycleOperations, pairingRecords,
      new HttpAccessChangeTransport(origin, () => auth.current()?.session.csrfToken),
      { prepare: (input, callOptions) => worker.prepareLifecycle(input, callOptions), ...(options.trustedServiceKeys ? { trustedServiceKeys: { ...options.trustedServiceKeys } } : {}) });
    detach.push(lifecycle.attachAuthLifecycle(), () => lifecycle.clear());
    const directory = new DirectoryController(auth, pairingRecords, accessChanges,
      new HttpAccessChangeTransport(origin, () => auth.current()?.session.csrfToken),
      { ...(options.trustedServiceKeys ? { trustedServiceKeys: { ...options.trustedServiceKeys } } : {}) });
    detach.push(directory.attachAuthLifecycle(), () => directory.clear());
    const profiles = new ProfileController(auth, pairingRecords, accessChanges,
      new HttpAccessChangeTransport(origin, () => auth.current()?.session.csrfToken),
      { ...(options.trustedServiceKeys ? { trustedServiceKeys: { ...options.trustedServiceKeys } } : {}) });
    detach.push(profiles.attachAuthLifecycle(), () => profiles.clear());
    const exports = new ExportController(auth, new HttpExportTransport(origin, () => auth.current()?.session.csrfToken), pairingRecords, accessChanges,
      new HttpAccessChangeTransport(origin, () => auth.current()?.session.csrfToken),
      { ...(options.trustedServiceKeys ? { trustedServiceKeys: { ...options.trustedServiceKeys } } : {}) });
    detach.push(exports.attachAuthLifecycle(), () => exports.clear());
    const restoration = new RestorationController(auth, new HttpRestorationTransport(origin, () => auth.current()?.session.csrfToken), pairingRecords,
      new HttpAccessChangeTransport(origin, () => auth.current()?.session.csrfToken), restorationOperations, worker,
      { ...(options.trustedServiceKeys ? { trustedServiceKeys: { ...options.trustedServiceKeys } } : {}) });
    detach.push(restoration.attachAuthLifecycle(), () => restoration.clear());
    const planning = new PlanningController(auth, new HttpPlanningTransport(origin, () => auth.current()?.session.csrfToken), planningOperations, pairingRecords, accessChanges,
      { closingSettings: () => reporting.settingsProof(), onWrite: () => reporting.relevantWrite(), ...(options.trustedServiceKeys ? { trustedServiceKeys: { ...options.trustedServiceKeys } } : {}) });
    detach.push(planning.attachAuthLifecycle(), () => planning.clear());
    const collaboration = new CollaborationController(auth, new HttpCollaborationTransport(origin, () => auth.current()?.session.csrfToken), collaborationOperations,
      pairingRecords, planningOperations, accessChanges, new HttpPlanningTransport(origin, () => auth.current()?.session.csrfToken),
      { ...(options.trustedServiceKeys ? { trustedServiceKeys: { ...options.trustedServiceKeys } } : {}) });
    detach.push(collaboration.attachAuthLifecycle(), () => collaboration.clear());
    const reporting = new ReportingController(auth, new HttpReportingTransport(origin, () => auth.current()?.session.csrfToken), pairingRecords, planningOperations,
      accessChanges, new HttpAccessChangeTransport(origin, () => auth.current()?.session.csrfToken), reportingOperations,
      { ...(options.trustedServiceKeys ? { trustedServiceKeys: { ...options.trustedServiceKeys } } : {}) });
    detach.push(reporting.attachAuthLifecycle(), () => reporting.clear());
    const inbox = new InboxController(auth, new HttpInboxTransport(origin, () => auth.current()?.session.csrfToken), inboxOperations);
    detach.push(inbox.attachAuthLifecycle(), () => inbox.clear());
    const teams = new TeamsController(auth, new HttpTeamsTransport(origin, () => auth.current()?.session.csrfToken), teamOperations, pairingRecords, accessChanges,
      new HttpAccessChangeTransport(origin, () => auth.current()?.session.csrfToken), { ...(options.trustedServiceKeys ? { trustedServiceKeys: { ...options.trustedServiceKeys } } : {}) });
    detach.push(teams.attachAuthLifecycle(), () => teams.clear());
    const upgrades = new UpgradeController(auth, new HttpUpgradeTransport(origin, () => auth.current()?.session.csrfToken), upgradeOperations, pairingRecords,
      planningOperations, collaborationOperations, accessChanges, new HttpAccessChangeTransport(origin, () => auth.current()?.session.csrfToken),
      { planning: new HttpPlanningTransport(origin, () => auth.current()?.session.csrfToken), teams: new HttpTeamsTransport(origin, () => auth.current()?.session.csrfToken),
        collaboration: new HttpCollaborationTransport(origin, () => auth.current()?.session.csrfToken) },
      { onWrite: () => reporting.relevantWrite(), ...(options.trustedServiceKeys ? { trustedServiceKeys: { ...options.trustedServiceKeys } } : {}) });
    detach.push(upgrades.attachAuthLifecycle(), () => upgrades.clear());
    const projectCreation = new ProjectCreateController(auth, new HttpProjectCreateTransport(origin, () => auth.current()?.session.csrfToken), projectOperations, pairingRecords, accessChanges,
      { ...(options.trustedServiceKeys ? { trustedServiceKeys: { ...options.trustedServiceKeys } } : {}) });
    detach.push(projectCreation.attachAuthLifecycle(), () => projectCreation.clear());
    detach.push(accessChanges.attachAuthLifecycle(), () => accessChanges.clear());
    detach.push(roles.attachAuthLifecycle(), () => roles.clear());
    detach.push(activation.attachAuthLifecycle(auth), passwordChanges.attachAuthLifecycle(auth), () => pairing.close());
    detach.push(recoveries.attachAuthLifecycle(), () => recoveries.clear());
    detach.push(enrolments.attachAuthLifecycle(), () => enrolments.clear());
    // onClear locks immediately, including failed sign-out and refresh. Confirmed
    // sign-out clears pending business requests. Security ceremonies retain their
    // exact drafts/capabilities for ambiguous-commit recovery until explicit Forget.
    detach.push(auth.onSignedOut(async reference => {
      const results = await Promise.allSettled([planning, collaboration, reporting, inbox, teams, projectCreation, accessChanges, roles, upgrades, restoration, lifecycle]
        .map(controller => controller.forgetDevice(reference)));
      if (results.some(result => result.status === 'rejected')) throw new Error('Pending request cleanup failed');
    }));
    let closing: Promise<void> | undefined;
    return { auth, activation, passwordChanges, pairing, recoveries, enrolments, roles, accessChanges, projectCreation, teams, planning, collaboration, inbox, reporting, receipts, upgrades, exports, restoration, lifecycle, profiles, directory, remembered,
      /** Revokes this browser session and closes local handles; failure is reported after local cleanup. */
      close(): Promise<void> {
        closing ??= (async () => {
          try { await auth.logout(); }
          finally { detach.forEach((remove) => remove()); worker.close(); stores.forEach((store) => store.close()); }
        })();
        return closing;
      },
    };
  } catch (error) {
    detach.forEach((remove) => remove()); worker.close(); stores.forEach((store) => store.close());
    throw error;
  }
}
export type ClientRuntime = Awaited<ReturnType<typeof openClient>>;
