/** Headless write states. No automatic retry, merge, queue, or reconnect listener. */
export type WriteErrorCode = 'OFFLINE' | 'CONFLICT' | 'REVIEW_REQUIRED' | 'UPDATE_REQUIRED' | 'RESTRICTED' | 'RETRY_REQUIRED' | 'STORAGE';
export class WriteError extends Error {
  constructor(readonly code: WriteErrorCode, readonly serverCode?: string) {
    super(`Write failed (${code})`); this.name = 'WriteError';
  }
}
/** Current data is fetched and verified under current access; unsaved input stays in memory only. */
export class WriteConflict<Current, Unsaved> extends WriteError {
  constructor(readonly operationId: string, readonly current: Current, readonly unsaved: Unsaved) {
    super('CONFLICT'); this.name = 'WriteConflict';
  }
}
export function assertOnline(check: () => boolean = () => globalThis.navigator?.onLine !== false): void {
  if (!check()) throw new WriteError('OFFLINE');
}
export function isWriteConflict(error: unknown): boolean {
  return typeof error === 'object' && error !== null && 'code' in error && error.code === 'CONFLICT';
}
