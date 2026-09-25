import { ActivationController, HttpActivationTransport, IndexedActivationStore } from './activation-controller.js';
import { AuthController, HttpAuthTransport } from './auth-controller.js';
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
    const auth = new AuthController(new HttpAuthTransport(origin), worker, devices, remembered);
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
    detach.push(accessChanges.attachAuthLifecycle(), () => accessChanges.clear());
    detach.push(roles.attachAuthLifecycle(), () => roles.clear());
    detach.push(activation.attachAuthLifecycle(auth), passwordChanges.attachAuthLifecycle(auth), () => pairing.close());
    detach.push(recoveries.attachAuthLifecycle(), () => recoveries.clear());
    detach.push(enrolments.attachAuthLifecycle(), () => enrolments.clear());
    let closing: Promise<void> | undefined;
    return { auth, activation, passwordChanges, pairing, recoveries, enrolments, roles, accessChanges, remembered,
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
