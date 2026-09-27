import { digestObject } from '../shared/crypto.js';
import { verifySecurityHistory, type SecurityHistoryInput, type SecurityHistoryState } from '../shared/security-history.js';
function invalid(): never { throw new Error('Invalid security history prefix'); }
export function securityHistoryResolver(history: SecurityHistoryInput, current: SecurityHistoryState) {
  const cache = new Map<string, Promise<SecurityHistoryState>>([[`${current.securityVersion}:${current.securityHead}`, Promise.resolve(current)]]);
  return async (version: string, requestedHead?: string) => {
    if (BigInt(version) > BigInt(current.securityVersion) || BigInt(version) < 1n) invalid();
    const offset = Number(BigInt(version) - 1n);
    if (!Number.isSafeInteger(offset) || offset > history.transitions.length) invalid();
    const head = requestedHead ?? await digestObject(offset === 0 ? history.genesis : history.transitions[offset - 1]);
    const key = `${version}:${head}`; let promise = cache.get(key);
    if (!promise) {
      if (BigInt(version) > BigInt(current.securityVersion) || BigInt(version) < 1n) invalid();
      const length = Number(BigInt(version) - 1n); if (!Number.isSafeInteger(length) || length > history.transitions.length) invalid();
      const { pin: _pin, ...base } = history;
      promise = verifySecurityHistory({ ...base, transitions: history.transitions.slice(0, length), expected: { securityVersion: version, securityHead: head } }); cache.set(key, promise);
    }
    return promise;
  };
}
