import type { FastifyInstance, FastifyRequest } from 'fastify';
import { z } from 'zod';
import type { Databases } from '../../db.js';
import { AppError } from '../../errors.js';
import { parseInput } from '../../http.js';
import { binary, identifier } from '../../shared/contracts.js';
import { pairingApproval, pairingBegin, pairingConfirmation } from '../../shared/pairing.js';
import { passwordChangeBegin, passwordChangeReference, passwordChangeRegistration, passwordChangeProofStart,
  passwordChangeProofFinish, passwordChangeFinalize } from '../../shared/password-change.js';
import type { RequestBudgets } from './budgets.js';
import type { PairingService } from './pairing.js';
import type { PasswordChangeService } from './password-change.js';
import { readSessionCookie, type SessionService } from './sessions.js';
import { readPairingHistoryPage } from './security-history.js';

const operation = z.strictObject({ operationId: identifier });
export function registerSecurityRoutes(app: FastifyInstance, input: {
  origin: string; databases: Databases; sessions: SessionService; budgets: Pick<RequestBudgets, 'take'>;
  pairing: PairingService; passwordChange: PasswordChangeService;
}) {
  const cookie = (request: FastifyRequest) => {
    const value = readSessionCookie(request.headers.cookie);
    if (!value) throw new AppError('AUTH_REQUIRED', 'Authentication required', 401);
    return value;
  };
  const csrf = (request: FastifyRequest) => {
    const value = request.headers['x-csrf-token'];
    if (typeof value !== 'string' || !binary(32).safeParse(value).success) throw new AppError('CSRF_REJECTED', 'Request verification failed', 403);
    return value;
  };
  async function originGuard(request: FastifyRequest) {
    if (request.headers.origin !== input.origin || request.headers['sec-fetch-site'] === 'cross-site') throw new AppError('ORIGIN_REJECTED', 'Request origin is not allowed', 403);
    if (Object.keys(request.query as object).length) throw new AppError('INVALID_REQUEST', 'Invalid request', 400);
    await input.budgets.take([{ purpose: 'authentication-source', key: request.ip, limit: 60, windowMs: 600000 }]);
  }
  async function accountGuard(request: FastifyRequest) {
    await originGuard(request);
    const principal = await input.sessions.authenticate(cookie(request));
    await input.budgets.take([
      { purpose: 'security-account', key: `${principal.workspaceId}:${principal.accountId}`, limit: 60, windowMs: 600000 },
      { purpose: 'security-workspace', key: principal.workspaceId, limit: 240, windowMs: 600000 },
    ]);
  }
  function pairingRoute(path: string, handler: (request: FastifyRequest) => Promise<unknown>) {
    app.post(`/v1/auth/pairing/${path}`, { preHandler: accountGuard }, async (request) => {
      try { return await handler(request); }
      catch (error) {
        if (error instanceof AppError) throw error;
        throw new AppError('PAIRING_UNAVAILABLE', 'Device pairing is temporarily unavailable; retain the local draft', 503);
      }
    });
  }
  pairingRoute('begin', (request) => input.pairing.begin(cookie(request), csrf(request), parseInput(pairingBegin, request.body)));
  pairingRoute('inspect', (request) => input.pairing.inspect(cookie(request), parseInput(operation, request.body).operationId));
  pairingRoute('claim', (request) => input.pairing.claim(cookie(request), csrf(request), parseInput(operation, request.body).operationId));
  pairingRoute('confirm', (request) => input.pairing.confirm(cookie(request), csrf(request), parseInput(pairingConfirmation, request.body)));
  pairingRoute('materials', (request) => input.pairing.materials(cookie(request), parseInput(operation, request.body).operationId));
  pairingRoute('stage', (request) => input.pairing.stageApproval(cookie(request), csrf(request), parseInput(pairingApproval, request.body)));
  pairingRoute('commit', (request) => input.pairing.commit(cookie(request), csrf(request), parseInput(operation, request.body).operationId));
  pairingRoute('delivery', (request) => input.pairing.delivery(cookie(request), parseInput(operation, request.body).operationId));
  // Signed history is an authenticated paged read. It must not consume the small
  // login/mutation attempt budgets on every page of the same verification journey.
  app.post('/v1/auth/pairing/history', { preHandler: async (request) => {
    if (request.headers.origin !== input.origin || request.headers['sec-fetch-site'] === 'cross-site') throw new AppError('ORIGIN_REJECTED', 'Request origin is not allowed', 403);
    if (Object.keys(request.query as object).length) throw new AppError('INVALID_REQUEST', 'Invalid request', 400);
    await input.budgets.take([{ purpose: 'history-source', key: request.ip, limit: 1200, windowMs: 600000 }]);
    const principal = await input.sessions.authenticate(cookie(request));
    await input.budgets.take([
      { purpose: 'history-account', key: `${principal.workspaceId}:${principal.accountId}`, limit: 1000, windowMs: 600000 },
      { purpose: 'history-workspace', key: principal.workspaceId, limit: 4000, windowMs: 600000 },
    ]);
  } }, async (request) => {
    try { return await readPairingHistoryPage(input, cookie(request), request.body); }
    catch (error) {
      if (error instanceof AppError) throw error;
      throw new AppError('PAIRING_UNAVAILABLE', 'Device pairing is temporarily unavailable; retain the local draft', 503);
    }
  });

  function passwordRoute<T>(path: string, schema: z.ZodType<T>, handler: (body: T, request: FastifyRequest) => Promise<unknown>, capabilityOnly = false) {
    app.post(`/v1/auth/password-change/${path}`, { preHandler: capabilityOnly ? originGuard : accountGuard }, async (request) => {
      const body = parseInput(schema, request.body);
      const reference = parseInput(passwordChangeReference, {
        workspaceId: (body as { workspaceId: string }).workspaceId,
        operationId: (body as { operationId: string }).operationId,
        resumeToken: (body as { resumeToken: string }).resumeToken,
      });
      await input.budgets.take([{ purpose: 'password-change-operation', key: `${reference.workspaceId}:${reference.operationId}`, limit: 60, windowMs: 600000 }]);
      return handler(body, request);
    });
  }
  const auth = (request: FastifyRequest) => ({ cookieValue: cookie(request), csrfToken: csrf(request) });
  passwordRoute('begin', passwordChangeBegin, (body, request) => input.passwordChange.begin(body, auth(request)));
  passwordRoute('registration', passwordChangeRegistration, (body, request) => input.passwordChange.registration(body, auth(request)));
  passwordRoute('proof/start', passwordChangeProofStart, (body, request) => input.passwordChange.startProof(body, auth(request)));
  passwordRoute('proof/finish', passwordChangeProofFinish, (body, request) => input.passwordChange.finishProof(body, auth(request)));
  // A successful change revokes this cookie. The service checks an existing
  // capability-bound receipt first and enforces current/recent auth before a first commit.
  passwordRoute('finalize', passwordChangeFinalize, (body, request) => input.passwordChange.finalize(body, auth(request)), true);
  passwordRoute('status', passwordChangeReference, (body) => input.passwordChange.status(body), true);
  passwordRoute('cancel', passwordChangeReference, (body, request) => input.passwordChange.cancel(body, auth(request)));
}
