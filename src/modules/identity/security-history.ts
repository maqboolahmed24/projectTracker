import { z } from 'zod';
import type pg from 'pg';
import { transaction, type Databases } from '../../db.js';
import { AppError } from '../../errors.js';
import { counter, digest, identifier, positiveCounter } from '../../shared/contracts.js';
import { canonicalJson, digestObject } from '../../shared/crypto.js';
import { pairingReceipt, pairingTranscript } from '../../shared/pairing.js';
import type { SessionService } from './sessions.js';

export const HISTORY_PAGE_BYTES = 512 * 1024;
export const HISTORY_RECORD_BYTES = 1024 * 1024;
export const HISTORY_RESPONSE_BYTES = 3 * 1024 * 1024;
export const HISTORY_PAGE_RECORDS = 128;
const anchor = z.strictObject({ securityHead: digest, securityVersion: positiveCounter });
export const pairingHistoryRequest = z.strictObject({ operationId: identifier, mode: z.enum(['transcript', 'current']),
  anchor: anchor.optional(), afterVersion: counter.default('0') }).refine((request) => request.afterVersion === '0' || !!request.anchor);
export type PairingHistoryRequest = z.infer<typeof pairingHistoryRequest>;
export type HistoryAnchor = z.infer<typeof anchor>;
export interface PairingHistoryPage {
  workspaceId: string; operationId: string; mode: 'transcript' | 'current'; anchor: HistoryAnchor; current: HistoryAnchor;
  afterVersion: string; genesis: unknown | null; transitions: unknown[]; nextAfterVersion: string | null;
}
interface Ceremony { profile_id: string; public_state: { transcript?: unknown } }
interface RecordRow { sequence: string; head: string; signed_transition: unknown }
const invalid = () => new AppError('HISTORY_CURSOR_INVALID', 'Restart security history verification from its anchored head', 409);
const unavailable = () => new AppError('SECURITY_FENCED', 'Workspace security history is unavailable', 503);

/**
 * Every page rechecks live authentication/ceremony visibility while holding current
 * workspace authority. The anchor is an immutable retained journal prefix, never a
 * substitute for current access. Complete signed records are never truncated or
 * split; one valid large record can use the explicit bounded history response margin.
 */
export async function readPairingHistoryPage(input: { databases: Databases; sessions: SessionService }, cookie: string, value: unknown): Promise<PairingHistoryPage> {
  const parsed = pairingHistoryRequest.safeParse(value);
  if (!parsed.success) throw new AppError('INVALID_REQUEST', 'Invalid security history request', 400);
  const request = parsed.data;
  return transaction(input.databases.control, async (control) => {
    const principal = await input.sessions.resolveCurrent(control, cookie);
    const workspaceId = principal.workspaceId;
    const ceremony = (await control.query<Ceremony>(`SELECT c.profile_id,c.public_state FROM security.ceremonies c
      JOIN security.profiles p ON p.workspace_id=c.workspace_id AND p.profile_id=$3 AND p.state='active'
      WHERE c.workspace_id=$1 AND c.ceremony_id=$2 AND c.kind='device_pair'
      AND (c.profile_id=p.profile_id OR (p.is_owner AND $4))`,
    [workspaceId, request.operationId, principal.accountId, principal.accessLevel === 'device_approved'])).rows[0];
    if (!ceremony) throw new AppError('PAIRING_FORBIDDEN', 'This session cannot inspect this device pairing', 403);
    const transcript = pairingTranscript.safeParse(ceremony.public_state.transcript);
    if (!transcript.success || transcript.data.workspaceId !== workspaceId || transcript.data.operationId !== request.operationId ||
      transcript.data.accountId !== ceremony.profile_id) throw new AppError('PAIRING_INVALID', 'Choose an approving device before verifying history', 409);
    const current: HistoryAnchor = { securityHead: principal.securityHead, securityVersion: principal.securityVersion };
    let lowerVersion = transcript.data.securityVersion;
    if (request.mode === 'current') {
      const receipt = (await control.query<{ outcome: unknown }>(`SELECT outcome FROM security.operation_receipts
        WHERE workspace_id=$1 AND operation_id=$2 AND operation_kind='device_pair'`, [workspaceId, request.operationId])).rows[0];
      const checked = pairingReceipt.safeParse(receipt?.outcome);
      if (!checked.success || checked.data.workspaceId !== workspaceId || checked.data.operationId !== request.operationId ||
        checked.data.accountId !== ceremony.profile_id) throw new AppError('PAIRING_INVALID', 'Complete device approval before verifying current delivery authority', 409);
      lowerVersion = checked.data.securityVersion;
    }
    return readAuthorizedSecurityHistoryPage(control, request, { workspaceId, current,
      transcript: { securityHead: transcript.data.securityHead, securityVersion: transcript.data.securityVersion }, lowerVersion });
  });
}


export interface SecurityHistoryReadContext {
  workspaceId: string; current: HistoryAnchor; transcript: HistoryAnchor; lowerVersion: string;
}

/** Caller must authorize each page and retain the same transaction/current-workspace lock. */
export async function readAuthorizedSecurityHistoryPage(control: pg.PoolClient, request: PairingHistoryRequest,
  context: SecurityHistoryReadContext): Promise<PairingHistoryPage> {
  const { workspaceId, current, lowerVersion } = context;
  const expected = request.mode === 'transcript' ? context.transcript : current;
  const through = request.anchor ?? expected;
  if (BigInt(through.securityVersion) > BigInt(current.securityVersion) || BigInt(through.securityVersion) < BigInt(lowerVersion) ||
    (request.mode === 'transcript' && (through.securityVersion !== expected.securityVersion || through.securityHead !== expected.securityHead))) throw invalid();
  const bound = (await control.query<{ head: string }>('SELECT head FROM security.security_transitions WHERE workspace_id=$1 AND sequence=$2', [workspaceId, through.securityVersion])).rows[0];
  if (!bound || bound.head !== through.securityHead) throw invalid();
  if (BigInt(request.afterVersion) >= BigInt(through.securityVersion)) throw invalid();
  const metadata = (await control.query<{ sequence: string; storage_bytes: number }>(`SELECT sequence,octet_length(signed_transition::text) AS storage_bytes
    FROM security.security_transitions WHERE workspace_id=$1 AND sequence>$2 AND sequence<=$3 ORDER BY sequence LIMIT $4`,
  [workspaceId, request.afterVersion, through.securityVersion, HISTORY_PAGE_RECORDS])).rows;
  const ids: string[] = [];
  let estimated = 4096, expectedSequence = BigInt(request.afterVersion) + 1n;
  for (const item of metadata) {
    if (item.sequence !== String(expectedSequence)) throw unavailable();
    // PostgreSQL JSONB adds spaces; allow that bounded representation overhead,
    // then enforce the exact canonical record size after fetching the candidate.
    if (item.storage_bytes > HISTORY_RECORD_BYTES * 2) throw unavailable();
    if (ids.length && estimated + item.storage_bytes > HISTORY_PAGE_BYTES) break;
    ids.push(item.sequence); estimated += item.storage_bytes; expectedSequence++;
    if (estimated >= HISTORY_PAGE_BYTES) break;
  }
  if (!ids.length) throw unavailable();
  const rows = (await control.query<RecordRow>(`SELECT sequence,head,signed_transition FROM security.security_transitions
    WHERE workspace_id=$1 AND sequence=ANY($2::bigint[]) ORDER BY sequence`, [workspaceId, ids])).rows;
  if (rows.length !== ids.length) throw unavailable();
  const page: PairingHistoryPage = { workspaceId, operationId: request.operationId, mode: request.mode, anchor: through, current,
    afterVersion: request.afterVersion, genesis: null, transitions: [], nextAfterVersion: null };
  for (const row of rows) {
    // Activation journals both proofs, but its head identifies the signed genesis
    // alone. Preserve the historical row and publish that exact genesis object.
    const activation = row.sequence === '1' ? z.strictObject({ genesis: z.record(z.string(), z.unknown()), recoveryProof: z.record(z.string(), z.unknown()) }).safeParse(row.signed_transition) : null;
    if (activation && !activation.success) throw unavailable();
    const record = activation?.success ? activation.data.genesis : row.signed_transition;
    if (Buffer.byteLength(canonicalJson(record), 'utf8') > HISTORY_RECORD_BYTES ||
      await digestObject(record) !== row.head) throw unavailable();
    if (row.sequence === '1') {
      const genesis = (await control.query<{ object_hash: string; versioned_object: unknown }>(`SELECT o.object_hash,o.versioned_object
        FROM security.workspaces w JOIN security.staged_objects o ON o.workspace_id=w.workspace_id AND o.object_id=w.genesis_object_id
        WHERE w.workspace_id=$1 AND o.object_kind='genesis' AND o.state='committed'`, [workspaceId])).rows[0];
      if (!genesis || genesis.object_hash !== row.head || await digestObject(genesis.versioned_object) !== row.head) throw unavailable();
      page.genesis = record;
    } else page.transitions.push(record);
  }
  const last = ids.at(-1)!;
  page.nextAfterVersion = last === through.securityVersion ? null : last;
  // JSONB size was only a fetch budget. Check the exact emitted UTF-8 bytes too.
  // A single <=1MiB record has explicit response margin; ordinary pages stay512KiB.
  const actualBytes = Buffer.byteLength(JSON.stringify(page), 'utf8');
  if (actualBytes > HISTORY_RESPONSE_BYTES || (ids.length > 1 && actualBytes > HISTORY_PAGE_BYTES)) throw unavailable();

  return page;
}
