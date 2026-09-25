import type { FastifyInstance, FastifyRequest } from 'fastify';
import { z } from 'zod';
import { AppError } from '../../errors.js';
import { parseInput } from '../../http.js';
import { binary, identifier } from '../../shared/contracts.js';
import { accessRequest, accessPayload, accessFinalize, accessStatus, accessReference } from '../../shared/access-change.js';
import type { RequestBudgets } from './budgets.js';
import type { AccessChangeService } from './access-change.js';
import { pairingHistoryRequest, readAuthorizedSecurityHistoryPage } from './security-history.js';
import { readSessionCookie } from './sessions.js';
const historyRequest = accessReference.extend({ anchor: pairingHistoryRequest.shape.anchor, afterVersion: pairingHistoryRequest.shape.afterVersion })
  .refine((value) => value.afterVersion === '0' || !!value.anchor);
const deliveryRequest = z.strictObject({ workspaceId: identifier });
export function accessChangeAccountBudget(budgets: Pick<RequestBudgets, 'take'>) {
  return ({ workspaceId, accountId, history }: { workspaceId: string; accountId: string; history: boolean }) => budgets.take([
    { purpose: history ? 'access-change-history-account' : 'access-change-account', key: `${workspaceId}:${accountId}`, limit: history ? 1000 : 120, windowMs: 600000 },
    { purpose: history ? 'access-change-resolved-history-workspace' : 'access-change-resolved-workspace', key: workspaceId, limit: history ? 4000 : 480, windowMs: 600000 },
  ]);
}
export function registerAccessChangeRoutes(app: FastifyInstance, input: { origin: string; accessChanges: AccessChangeService; budgets: Pick<RequestBudgets, 'take'> }) {
  function auth(request: FastifyRequest) {
    const csrfToken = request.headers['x-csrf-token'];
    if (typeof csrfToken !== 'string' || !binary(32).safeParse(csrfToken).success) throw new AppError('CSRF_REJECTED', 'Request verification failed', 403);
    const cookieValue = readSessionCookie(request.headers.cookie); if (!cookieValue) throw new AppError('AUTH_REQUIRED', 'Authentication required', 401);
    return { cookieValue, csrfToken };
  }
  function optionalAuth(request: FastifyRequest) {
    const csrfToken = request.headers['x-csrf-token'];
    return { cookieValue: readSessionCookie(request.headers.cookie), csrfToken: typeof csrfToken === 'string' && binary(32).safeParse(csrfToken).success ? csrfToken : undefined };
  }
  function route<T>(path: string, schema: z.ZodType<T>, handler: (body: T, request: FastifyRequest) => Promise<unknown>, paged = false) {
    app.post(`/v1/auth/access-change/${path}`, { preHandler: async (request) => {
      if (request.headers.origin !== input.origin || request.headers['sec-fetch-site'] === 'cross-site') throw new AppError('ORIGIN_REJECTED', 'Request origin is not allowed', 403);
      if (Object.keys(request.query as object).length) throw new AppError('INVALID_REQUEST', 'Invalid request', 400);
      await input.budgets.take([{ purpose: paged ? 'access-change-history-source' : 'access-change-source', key: request.ip, limit: paged ? 1200 : 120, windowMs: 600000 }]);
    } }, async (request) => {
      const body = parseInput(schema, request.body), fields = body as { workspaceId?: string; operationId?: string; transition?: { body: { binding: { workspaceId: string; operationId: string } } } };
      const ref = fields.transition?.body.binding ?? fields;
      await input.budgets.take([
        ...(ref.workspaceId ? [{ purpose: paged ? 'access-change-history-workspace' : 'access-change-workspace', key: ref.workspaceId, limit: paged ? 4000 : 480, windowMs: 600000 }] : []),
        ...(ref.operationId ? [{ purpose: paged ? 'access-change-history-operation' : 'access-change-operation', key: `${ref.workspaceId}:${ref.operationId}`, limit: paged ? 1000 : 120, windowMs: 600000 }] : []),
      ]);
      try { return await handler(body, request); }
      catch (error) { if (error instanceof AppError) throw error; throw new AppError('ACCESS_UNAVAILABLE', 'Access change is temporarily unavailable; retain the local draft', 503); }
    });
  }
  route('context', accessRequest, (body, request) => { const a = auth(request); return input.accessChanges.context(a.cookieValue, a.csrfToken, body); });
  route('stage', accessPayload, (body, request) => { const a = auth(request); return input.accessChanges.stage(a.cookieValue, a.csrfToken, body); });
  route('finalize', accessFinalize, (body, request) => { const a = optionalAuth(request); return input.accessChanges.finalize(a.cookieValue, a.csrfToken, body); });
  route('status', accessStatus, (body, request) => { const a = body.receiptToken ? optionalAuth(request) : auth(request); return input.accessChanges.status(a.cookieValue, a.csrfToken, body); });
  route('delivery', deliveryRequest, (body, request) => { const a = auth(request); return input.accessChanges.currentDelivery(a.cookieValue, a.csrfToken, body); });
  for (const path of ['history', 'delivery/history'] as const) route(path, historyRequest, (body, request) => {
    const a = auth(request), read = path === 'history' ? input.accessChanges.withAuthorizedHistory.bind(input.accessChanges) : input.accessChanges.withDeliveryHistory.bind(input.accessChanges);
    return read(body.workspaceId, a, (control, context) => readAuthorizedSecurityHistoryPage(control,
      { operationId: body.operationId, mode: 'current', afterVersion: body.afterVersion, ...(body.anchor ? { anchor: body.anchor } : {}) },
      { workspaceId: body.workspaceId, current: context.current, transcript: context.current, lowerVersion: '1' }));
  }, true);
}
