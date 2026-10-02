import { parseJsonStrict } from '../../src/shared/json.js';

/** Private, versioned presentation handoffs. No passwords, phrases or resume capabilities. */
export type IdentityHandoff =
  | { version: 1; kind: 'signin'; origin: string; workspaceId: string; accountId: string }
  | { version: 1; kind: 'join'; origin: string; workspaceId: string; code: string; genesisFingerprint: string }
  | { version: 1; kind: 'reset'; origin: string; workspaceId: string; code: string }
  | { version: 1; kind: 'approve'; origin: string; workspaceId: string; operationId: string; ceremony: 'join' | 'reset' | 'pair' }
  | { version: 1; kind: 'promote'; origin: string; workspaceId: string; operationId: string };
export type HandoffInput = IdentityHandoff extends infer T ? T extends IdentityHandoff ? Omit<T, 'version' | 'origin'> : never : never;
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const fingerprint = /^[0-9a-f]{64}$/;
const fail = (): never => { throw new Error('This link is not valid for this workspace. Ask the person who sent it for a new one.'); };
function safeOrigin(value: string): boolean {
  try { const u = new URL(value); return u.origin === value && (u.protocol === 'https:' || (u.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(u.hostname))); } catch { return false; }
}
function validate(value: unknown, origin: string): IdentityHandoff {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail();
  const v = value as Record<string, unknown>;
  if (v.version !== 1 || v.origin !== origin || !safeOrigin(origin) || typeof v.workspaceId !== 'string' || !uuid.test(v.workspaceId)) fail();
  const fields: Record<string, string[]> = { signin: ['accountId'], join: ['code', 'genesisFingerprint'], reset: ['code'], approve: ['operationId', 'ceremony'], promote: ['operationId'] };
  if (typeof v.kind !== 'string' || !Object.hasOwn(fields, v.kind)) fail();
  const required = ['version', 'kind', 'origin', 'workspaceId', ...fields[String(v.kind)]!];
  if (Object.keys(v).length !== required.length || required.some(k => !Object.hasOwn(v, k))) fail();
  if ('accountId' in v && (typeof v.accountId !== 'string' || !uuid.test(v.accountId))) fail();
  if ('operationId' in v && (typeof v.operationId !== 'string' || !uuid.test(v.operationId))) fail();
  if (v.kind === 'join' && (typeof v.code !== 'string' || !/^JOIN-[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}$/.test(v.code) || typeof v.genesisFingerprint !== 'string' || !fingerprint.test(v.genesisFingerprint))) fail();
  if (v.kind === 'reset' && (typeof v.code !== 'string' || !/^RESET-[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}$/.test(v.code))) fail();
  if (v.kind === 'approve' && !['join', 'reset', 'pair'].includes(String(v.ceremony))) fail();
  return v as IdentityHandoff;
}
export function encodeHandoff(value: HandoffInput, origin = location.origin): string {
  const accepted = validate({ ...value, version: 1, origin }, origin);
  return btoa(JSON.stringify(accepted)).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}
export function createHandoffLink(value: HandoffInput, origin = location.origin): string {
  return `${origin}/#access=${encodeHandoff(value, origin)}`;
}
export function parseHandoff(input: string, origin = location.origin): IdentityHandoff {
  const text = input.trim(); if (!text || text.length > 12_000) fail();
  let value: unknown;
  try {
    if (text.startsWith('{')) value = parseJsonStrict(text);
    else {
      let encoded = text;
      if (text.startsWith('https://') || text.startsWith('http://')) {
        const url = new URL(text); if (url.origin !== origin || url.username || url.password || url.search || url.pathname !== '/') fail();
        const params = new URLSearchParams(url.hash.slice(1));
        if ([...params.keys()].length !== 1 || !params.has('access')) fail();
        encoded = params.get('access')!;
      } else if (text.startsWith('#access=')) encoded = text.slice(8);
      if (!/^[A-Za-z0-9_-]+$/.test(encoded)) fail();
      value = parseJsonStrict(atob(encoded.replaceAll('-', '+').replaceAll('_', '/')));
    }
  } catch { fail(); }
  return validate(value, origin);
}
export function downloadPrivateFile(filename: string, value: unknown): void {
  const url = URL.createObjectURL(new Blob([JSON.stringify(value, null, 2)], { type: 'application/json' }));
  const a = document.createElement('a'); a.href = url; a.download = filename; a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
export interface RecoveryKitFile { version: 1; language: 'english'; application: string; workspaceId: string; accountId: string; genesisFingerprint: string; phrase: string }
export function parseRecoveryKit(input: string, origin = location.origin): RecoveryKitFile {
  if (input.length > 12_000) fail();
  let v: Record<string, unknown> = {}; try { v = parseJsonStrict(input) as Record<string, unknown>; } catch { fail(); }
  const keys = ['version', 'language', 'application', 'workspaceId', 'accountId', 'genesisFingerprint', 'phrase'];
  if (!v! || typeof v !== 'object' || Array.isArray(v) || Object.keys(v).length !== keys.length || keys.some(k => !Object.hasOwn(v, k)) || v.version !== 1 || v.language !== 'english' || v.application !== origin || !safeOrigin(origin) ||
    typeof v.workspaceId !== 'string' || !uuid.test(v.workspaceId) || typeof v.accountId !== 'string' || !uuid.test(v.accountId) || typeof v.genesisFingerprint !== 'string' || !fingerprint.test(v.genesisFingerprint) || typeof v.phrase !== 'string' || v.phrase.length > 512 || v.phrase.split(' ').length !== 24) fail();
  return v as unknown as RecoveryKitFile;
}
