import type { FastifyInstance, FastifyRequest } from 'fastify';
import { z } from 'zod';
import { AppError } from '../../errors.js';
import { parseInput } from '../../http.js';
import { binary } from '../../shared/contracts.js';
import { roleContextRequest, roleFinalize, roleListRequest, rolePayload, roleReference } from '../../shared/roles.js';
import type { RequestBudgets } from './budgets.js';
import type { RoleService } from './roles.js';
import { pairingHistoryRequest, readAuthorizedSecurityHistoryPage } from './security-history.js';
import { readSessionCookie } from './sessions.js';
const historyRequest = roleReference.extend({ anchor: pairingHistoryRequest.shape.anchor, afterVersion: pairingHistoryRequest.shape.afterVersion })
  .refine((value) => value.afterVersion === '0' || !!value.anchor);
export function roleAccountBudget(budgets: Pick<RequestBudgets, 'take'>) {
  return ({ workspaceId, accountId, history }: { workspaceId: string; accountId: string; history: boolean }) => budgets.take([
    { purpose: history ? 'role-history-account' : 'role-account', key: `${workspaceId}:${accountId}`, limit: history ? 1000 : 120, windowMs: 600000 },
    { purpose: history ? 'role-resolved-history-workspace' : 'role-resolved-workspace', key: workspaceId, limit: history ? 4000 : 480, windowMs: 600000 },
  ]);
}
export function registerRoleRoutes(app: FastifyInstance, input: { origin: string; roles: RoleService; budgets: Pick<RequestBudgets, 'take'> }) {
  function auth(request: FastifyRequest) {
    const csrfToken = request.headers['x-csrf-token'];
    if (typeof csrfToken !== 'string' || !binary(32).safeParse(csrfToken).success) throw new AppError('CSRF_REJECTED', 'Request verification failed', 403);
    const cookieValue = readSessionCookie(request.headers.cookie);
    if (!cookieValue) throw new AppError('AUTH_REQUIRED', 'Authentication required', 401);
    return { cookieValue, csrfToken };
  }
  function route<T>(path: string, schema: z.ZodType<T>, handler: (body: T, auth: { cookieValue: string; csrfToken: string }) => Promise<unknown>, paged = false) {
    app.post(`/v1/auth/roles/${path}`, { preHandler: async (request) => {
      if (request.headers.origin !== input.origin || request.headers['sec-fetch-site'] === 'cross-site') throw new AppError('ORIGIN_REJECTED', 'Request origin is not allowed', 403);
      if (Object.keys(request.query as object).length) throw new AppError('INVALID_REQUEST', 'Invalid request', 400);
      await input.budgets.take([{ purpose: paged ? 'role-history-source' : 'role-source', key: request.ip, limit: paged ? 1200 : 120, windowMs: 600000 }]);
    } }, async (request) => {
      const body = parseInput(schema, request.body), credentials = auth(request);
      const fields = body as { workspaceId?: string; operationId?: string; transition?: { body: { binding: { workspaceId: string; operationId: string } } } };
      const ref = fields.transition?.body.binding ?? fields;
      await input.budgets.take([
        ...(ref.workspaceId ? [{ purpose: paged ? 'role-history-workspace' : 'role-workspace', key: ref.workspaceId, limit: paged ? 4000 : 480, windowMs: 600000 }] : []),
        ...(ref.operationId ? [{ purpose: paged ? 'role-history-operation' : 'role-operation', key: `${ref.workspaceId}:${ref.operationId}`, limit: paged ? 1000 : 120, windowMs: 600000 }] : []),
      ]);
      try { return await handler(body, credentials); }
      catch (error) { if (error instanceof AppError) throw error; throw new AppError('ROLE_UNAVAILABLE', 'Role operation is temporarily unavailable; retain the local draft', 503); }
    });
  }
  route('context', roleContextRequest, (body, auth) => input.roles.context(auth.cookieValue, auth.csrfToken, body));
  route('stage', rolePayload, (body, auth) => input.roles.stage(auth.cookieValue, auth.csrfToken, body));
  route('finalize', roleFinalize, (body, auth) => input.roles.finalize(auth.cookieValue, auth.csrfToken, body));
  route('status', roleReference, (body, auth) => input.roles.status(auth.cookieValue, auth.csrfToken, body));
  route('list', roleListRequest, (body, auth) => input.roles.list(auth.cookieValue, auth.csrfToken, body), true);
  route('history', historyRequest, (body, auth) => input.roles.withAuthorizedHistory(body.workspaceId, auth, (control, context) =>
    readAuthorizedSecurityHistoryPage(control, { operationId: body.operationId, mode: 'current', afterVersion: body.afterVersion, ...(body.anchor ? { anchor: body.anchor } : {}) },
      { workspaceId: body.workspaceId, current: context.current, transcript: context.current, lowerVersion: '1' })), true);
}
