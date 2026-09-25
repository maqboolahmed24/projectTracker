import type { FastifyInstance, FastifyRequest } from 'fastify';
import { z } from 'zod';
import { AppError } from '../../errors.js';
import { parseInput } from '../../http.js';
import { binary, digest, identifier } from '../../shared/contracts.js';
import { enrolmentApproval, enrolmentBegin, enrolmentConfirmation, enrolmentOperationReference, enrolmentReference,
  type EnrolmentOperationReference } from '../../shared/enrolment.js';
import { enrolmentBeginPromotion, enrolmentClaimPromotion, enrolmentIssueJoin, enrolmentIssuanceRequest, enrolmentPromotionDraft,
  enrolmentProofFinish, enrolmentProofStart, enrolmentRegistration, enrolmentRevokeJoin, enrolmentUnlockStart, enrolmentUnlockFinish,
  type EnrolmentAuth } from '../../shared/enrolment-api.js';
import type { RequestBudgets } from './budgets.js';
import type { EnrolmentService } from './enrolment.js';
import { pairingHistoryRequest, readAuthorizedSecurityHistoryPage } from './security-history.js';
import { readSessionCookie } from './sessions.js';

const reference = z.union([enrolmentReference, enrolmentOperationReference]);
const confirmation = z.union([enrolmentReference.extend({ confirmation: enrolmentConfirmation }),
  enrolmentOperationReference.extend({ confirmation: enrolmentConfirmation })]);
const historyFields = { mode: pairingHistoryRequest.shape.mode, anchor: pairingHistoryRequest.shape.anchor,
  afterVersion: pairingHistoryRequest.shape.afterVersion };
const history = z.union([enrolmentReference.extend(historyFields), enrolmentOperationReference.extend(historyFields)])
  .refine((value) => value.afterVersion === '0' || !!value.anchor);
const issuanceHistory = enrolmentOperationReference.extend({ anchor: pairingHistoryRequest.shape.anchor,
  afterVersion: pairingHistoryRequest.shape.afterVersion }).refine((value) => value.afterVersion === '0' || !!value.anchor);

/** Resolved accounts share a quota across replacement invitations and approval attempts. */
export function enrolmentAccountBudget(budgets: Pick<RequestBudgets, 'take'>) {
  return ({ workspaceId, accountId, history }: { workspaceId: string; accountId: string; history: boolean }) => budgets.take([
    { purpose: history ? 'enrolment-target-history-account' : 'enrolment-target-account', key: `${workspaceId}:${accountId}`,
      limit: history ? 1000 : 120, windowMs: 600000 },
    { purpose: history ? 'enrolment-target-history-workspace' : 'enrolment-target-workspace', key: workspaceId,
      limit: history ? 4000 : 480, windowMs: 600000 },
  ]);
}

export function registerEnrolmentRoutes(app: FastifyInstance, input: {
  origin: string; enrolment: EnrolmentService; budgets: Pick<RequestBudgets, 'take'>;
}) {
  function cookie(request: FastifyRequest) {
    const value = readSessionCookie(request.headers.cookie);
    if (!value) throw new AppError('AUTH_REQUIRED', 'Authentication required', 401);
    return value;
  }
  function auth(request: FastifyRequest): EnrolmentAuth {
    const value = request.headers['x-csrf-token'];
    if (typeof value !== 'string' || !binary(32).safeParse(value).success) throw new AppError('CSRF_REJECTED', 'Request verification failed', 403);
    return { cookieValue: cookie(request), csrfToken: value };
  }
  // A target capability remains usable after commit invalidates its old session.
  const authority = (request: FastifyRequest, body: EnrolmentOperationReference & { resumeToken?: string }) =>
    body.resumeToken === undefined ? auth(request) : undefined;
  const operationReference = (body: EnrolmentOperationReference & { resumeToken?: string }) =>
    body.resumeToken === undefined ? { workspaceId: body.workspaceId, operationId: body.operationId } :
      { workspaceId: body.workspaceId, operationId: body.operationId, resumeToken: body.resumeToken };

  function route<T>(path: string, schema: z.ZodType<T>, handler: (body: T, request: FastifyRequest) => Promise<unknown>, paged = false) {
    app.post(`/v1/auth/enrolment/${path}`, { preHandler: async (request) => {
      if (request.headers.origin !== input.origin || request.headers['sec-fetch-site'] === 'cross-site') throw new AppError('ORIGIN_REJECTED', 'Request origin is not allowed', 403);
      if (Object.keys(request.query as object).length) throw new AppError('INVALID_REQUEST', 'Invalid request', 400);
      await input.budgets.take([{ purpose: paged ? 'enrolment-history-source' : 'enrolment-source', key: request.ip,
        limit: paged ? 1200 : 120, windowMs: 600000 }]);
    } }, async (request) => {
      const body = parseInput(schema, request.body);
      const keys = body as { workspaceId?: string; accountId?: string; operationId?: string; code?: string };
      await input.budgets.take([
        ...(keys.workspaceId ? [{ purpose: paged ? 'enrolment-history-workspace' : 'enrolment-workspace', key: keys.workspaceId,
          limit: paged ? 4000 : 480, windowMs: 600000 }] : []),
        ...(keys.operationId || keys.code ? [{ purpose: paged ? 'enrolment-history-operation' : 'enrolment-operation',
          key: `${keys.workspaceId}:${keys.operationId ?? keys.code}`, limit: paged ? 1000 : 120, windowMs: 600000 }] : []),
        ...(keys.accountId ? [{ purpose: 'enrolment-account', key: `${keys.workspaceId}:${keys.accountId}`, limit: 15, windowMs: 600000 }] : []),
      ]);
      try { return await handler(body, request); }
      catch (error) {
        if (error instanceof AppError) throw error;
        throw new AppError('ENROLMENT_UNAVAILABLE', 'Enrolment is temporarily unavailable; retain the local draft', 503);
      }
    });
  }
  route('join/context', enrolmentIssuanceRequest, (body, request) => { const credentials = auth(request);
    return input.enrolment.issuanceContext(credentials.cookieValue, credentials.csrfToken, body); });
  route('join/history', issuanceHistory, (body, request) => input.enrolment.withIssuanceHistory(body.workspaceId, auth(request),
    (control, context) => readAuthorizedSecurityHistoryPage(control, {
      operationId: body.operationId, mode: 'current', afterVersion: body.afterVersion, ...(body.anchor ? { anchor: body.anchor } : {}),
    }, { workspaceId: context.workspaceId, current: context.current, transcript: context.current, lowerVersion: '1' })), true);
  route('join/issue', enrolmentIssueJoin, (body, request) => { const credentials = auth(request);
    return input.enrolment.issueJoin(credentials.cookieValue, credentials.csrfToken, body); });
  route('join/revoke', enrolmentRevokeJoin, (body, request) => { const credentials = auth(request);
    return input.enrolment.revokeJoin(credentials.cookieValue, credentials.csrfToken, body); });
  route('join/begin', enrolmentBegin, (body) => input.enrolment.begin(body));
  route('promotion/begin', enrolmentBeginPromotion, (body, request) => { const credentials = auth(request);
    return input.enrolment.beginPromotion(credentials.cookieValue, credentials.csrfToken, body); });
  route('promotion/claim', enrolmentClaimPromotion, (body, request) => input.enrolment.claimPromotion(body, auth(request)));
  route('promotion/stage', enrolmentPromotionDraft, (body, request) => input.enrolment.stagePromotion(body, auth(request)));
  route('claim', enrolmentOperationReference, (body, request) => input.enrolment.claim(body, auth(request)));
  route('inspect', reference, (body, request) => input.enrolment.inspect(body, authority(request, body)));
  route('registration', enrolmentRegistration, (body) => input.enrolment.registration(body));
  route('proof/start', enrolmentProofStart, (body) => input.enrolment.startProof(body));
  route('proof/finish', enrolmentProofFinish, (body) => input.enrolment.finishProof(body));
  route('unlock/start', enrolmentUnlockStart, (body) => input.enrolment.unlockStart(body));
  route('unlock/finish', enrolmentUnlockFinish, (body) => input.enrolment.unlockFinish(body));
  route('confirm', confirmation, (body, request) => input.enrolment.confirm(operationReference(body), body.confirmation, authority(request, body)));
  route('materials', enrolmentOperationReference, (body, request) => input.enrolment.materials(body, auth(request)));
  route('stage', enrolmentOperationReference.extend({ approval: enrolmentApproval }),
    (body, request) => input.enrolment.stage(operationReference(body), body.approval, auth(request)));
  route('finalize', enrolmentOperationReference.extend({ requestHash: digest }), (body, request) => input.enrolment.finalize(body, auth(request)));
  route('status', reference, (body, request) => input.enrolment.status(body, authority(request, body)));
  route('cancel', enrolmentReference, (body) => input.enrolment.cancel(body));
  route('delivery', z.strictObject({ operationId: identifier }), (body, request) => input.enrolment.delivery(cookie(request), body.operationId));
  route('history', history, (body, request) => input.enrolment.withAuthorizedHistory(operationReference(body),
    body.mode === 'current' ? auth(request) : authority(request, body), async (control, context) => {
      if (body.mode === 'current' && !context.receipt) throw new AppError('ENROLMENT_INVALID', 'Complete enrolment before verifying delivery authority', 409);
      return readAuthorizedSecurityHistoryPage(control, {
        operationId: body.operationId, mode: body.mode, afterVersion: body.afterVersion, ...(body.anchor ? { anchor: body.anchor } : {}),
      }, { workspaceId: context.workspaceId, current: context.current,
        transcript: { securityHead: context.binding.securityHead, securityVersion: context.binding.securityVersion },
        lowerVersion: body.mode === 'current' ? context.receipt!.securityVersion : context.binding.securityVersion });
    }), true);
}
