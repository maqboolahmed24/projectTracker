import type { FastifyInstance, FastifyRequest } from 'fastify';
import { z } from 'zod';
import { AppError } from '../../errors.js';
import { parseInput } from '../../http.js';
import { binary, identifier } from '../../shared/contracts.js';
import { recoveryApproval, recoveryBeginPhrase, recoveryBeginReset, recoveryConfirmation, recoveryFinalize,
  recoveryIssueReset, recoveryOperationReference, recoveryPhraseProof, recoveryProofFinish, recoveryProofStart,
  recoveryReference, recoveryRegistration, recoveryRevokeReset } from '../../shared/recovery.js';
import type { RequestBudgets } from './budgets.js';
import type { RecoveryService, RecoveryAuth, RecoveryOperationReference } from './recovery.js';
import { pairingHistoryRequest, readAuthorizedSecurityHistoryPage } from './security-history.js';
import { readSessionCookie } from './sessions.js';

const reference = z.union([recoveryReference, recoveryOperationReference]);
const confirmation = z.union([recoveryReference.extend({ confirmation: recoveryConfirmation }),
  recoveryOperationReference.extend({ confirmation: recoveryConfirmation })]);
const approval = z.union([recoveryReference.extend({ approval: recoveryApproval }),
  recoveryOperationReference.extend({ approval: recoveryApproval })]);
const finalize = z.union([recoveryReference.extend({ requestHash: recoveryFinalize.shape.requestHash }), recoveryFinalize]);
const historyFields = { mode: pairingHistoryRequest.shape.mode, anchor: pairingHistoryRequest.shape.anchor,
  afterVersion: pairingHistoryRequest.shape.afterVersion };
const history = z.union([recoveryReference.extend(historyFields), recoveryOperationReference.extend(historyFields)])
  .refine((value) => value.afterVersion === '0' || !!value.anchor);

/** Bind quotas to the actual profile resolved by the service, never a supplied account label. */
export function recoveryAccountBudget(budgets: Pick<RequestBudgets, 'take'>) {
  return ({ workspaceId, accountId, history }: { workspaceId: string; accountId: string; history: boolean }) => budgets.take([
    { purpose: history ? 'recovery-target-history-account' : 'recovery-target-account', key: `${workspaceId}:${accountId}`,
      limit: history ? 1000 : 120, windowMs: 600000 },
    { purpose: history ? 'recovery-target-history-workspace' : 'recovery-target-workspace', key: workspaceId,
      limit: history ? 4000 : 480, windowMs: 600000 },
  ]);
}

export function registerRecoveryRoutes(app: FastifyInstance, input: {
  origin: string; recovery: RecoveryService; budgets: Pick<RequestBudgets, 'take'>;
}) {
  function cookie(request: FastifyRequest) {
    const value = readSessionCookie(request.headers.cookie);
    if (!value) throw new AppError('AUTH_REQUIRED', 'Authentication required', 401);
    return value;
  }
  function auth(request: FastifyRequest): RecoveryAuth {
    const value = request.headers['x-csrf-token'];
    if (typeof value !== 'string' || !binary(32).safeParse(value).success) throw new AppError('CSRF_REJECTED', 'Request verification failed', 403);
    return { cookieValue: cookie(request), csrfToken: value };
  }
  // A capability-bound target may still carry the cookie invalidated by commit.
  // Do not let that stale cookie replace its explicit operation credential.
  const authority = (request: FastifyRequest, body: RecoveryOperationReference & { resumeToken?: string }) =>
    body.resumeToken === undefined ? auth(request) : undefined;
  const operationReference = (body: RecoveryOperationReference & { resumeToken?: string }) =>
    body.resumeToken === undefined ? { workspaceId: body.workspaceId, operationId: body.operationId } :
      { workspaceId: body.workspaceId, operationId: body.operationId, resumeToken: body.resumeToken };
  function route<T>(path: string, schema: z.ZodType<T>, handler: (body: T, request: FastifyRequest) => Promise<unknown>, paged = false) {
    app.post(`/v1/auth/recovery/${path}`, { preHandler: async (request) => {
      if (request.headers.origin !== input.origin || request.headers['sec-fetch-site'] === 'cross-site') throw new AppError('ORIGIN_REJECTED', 'Request origin is not allowed', 403);
      if (Object.keys(request.query as object).length) throw new AppError('INVALID_REQUEST', 'Invalid request', 400);
      await input.budgets.take([{ purpose: paged ? 'recovery-history-source' : 'recovery-source', key: request.ip,
        limit: paged ? 1200 : 120, windowMs: 600000 }]);
    } }, async (request) => {
      const body = parseInput(schema, request.body);
      const keys = body as { workspaceId?: string; accountId?: string; operationId?: string; resetId?: string; code?: string };
      await input.budgets.take([
        ...(keys.workspaceId ? [{ purpose: paged ? 'recovery-history-workspace' : 'recovery-workspace', key: keys.workspaceId,
          limit: paged ? 4000 : 480, windowMs: 600000 }] : []),
        ...(keys.operationId || keys.resetId || keys.code ? [{ purpose: paged ? 'recovery-history-operation' : 'recovery-operation',
          key: `${keys.workspaceId}:${keys.operationId ?? keys.resetId ?? keys.code}`, limit: paged ? 1000 : 120, windowMs: 600000 }] : []),
        ...(keys.accountId ? [{ purpose: 'recovery-account', key: `${keys.workspaceId}:${keys.accountId}`, limit: 15, windowMs: 600000 }] : []),
      ]);
      try { return await handler(body, request); }
      catch (error) {
        if (error instanceof AppError) throw error;
        throw new AppError('RECOVERY_UNAVAILABLE', 'Recovery is temporarily unavailable; retain the local draft', 503);
      }
    });
  }
  route('reset/issue', recoveryIssueReset, (body, request) => { const credentials = auth(request);
    return input.recovery.issueReset(credentials.cookieValue, credentials.csrfToken, body); });
  route('reset/revoke', recoveryRevokeReset, (body, request) => { const credentials = auth(request);
    return input.recovery.revokeReset(credentials.cookieValue, credentials.csrfToken, body); });
  route('reset/begin', recoveryBeginReset, (body) => input.recovery.beginReset(body));
  route('phrase/begin', recoveryBeginPhrase, (body) => input.recovery.beginPhrase(body));
  route('phrase/prove', recoveryReference.extend({ proof: recoveryPhraseProof }), (body) => input.recovery.provePhrase(body));
  route('claim', recoveryOperationReference, (body, request) => input.recovery.claim(body, auth(request)));
  route('inspect', reference, (body, request) => input.recovery.inspect(body, authority(request, body)));
  route('registration', recoveryRegistration, (body) => input.recovery.registration(body));
  route('proof/start', recoveryProofStart, (body) => input.recovery.startProof(body));
  route('proof/finish', recoveryProofFinish, (body) => input.recovery.finishProof(body));
  route('confirm', confirmation, (body, request) => input.recovery.confirm(operationReference(body), body.confirmation, authority(request, body)));
  route('materials', reference, (body, request) => input.recovery.materials(body, authority(request, body)));
  route('stage', approval, (body, request) => input.recovery.stage(operationReference(body), body.approval, authority(request, body)));
  route('finalize', finalize, (body, request) => input.recovery.finalize(body, authority(request, body)));
  route('status', reference, (body, request) => input.recovery.status(body, authority(request, body)));
  route('cancel', recoveryReference, (body) => input.recovery.cancel(body));
  route('delivery', z.strictObject({ operationId: identifier }), (body, request) => input.recovery.delivery(cookie(request), body.operationId));
  route('history', history, (body, request) => input.recovery.withAuthorizedHistory(operationReference(body),
    body.mode === 'current' ? auth(request) : authority(request, body), async (control, context) => {
      if (body.mode === 'current' && !context.receipt) throw new AppError('RECOVERY_INVALID', 'Complete recovery before verifying delivery authority', 409);
      return readAuthorizedSecurityHistoryPage(control, {
        operationId: body.operationId, mode: body.mode, afterVersion: body.afterVersion, ...(body.anchor ? { anchor: body.anchor } : {}),
      }, { workspaceId: context.workspaceId, current: context.current,
        transcript: { securityHead: context.binding.securityHead, securityVersion: context.binding.securityVersion },
        lowerVersion: body.mode === 'current' ? context.receipt!.securityVersion : context.binding.securityVersion });
    }), true);
}
