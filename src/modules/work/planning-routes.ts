import type { FastifyInstance, FastifyRequest } from 'fastify';
import { z } from 'zod';
import { AppError } from '../../errors.js';
import { parseInput } from '../../http.js';
import { binary } from '../../shared/contracts.js';
import { PLANNING_MAX_BYTES, planningPayload, planningReference, planningStatusRequest } from '../../shared/planning-api.js';
import type { RequestBudgets } from '../identity/budgets.js';
import { pairingHistoryRequest, readAuthorizedSecurityHistoryPage } from '../identity/security-history.js';
import { readSessionCookie } from '../identity/sessions.js';
import type { PlanningService } from './planning.js';
const historyRequest = planningReference.extend({ anchor: pairingHistoryRequest.shape.anchor, afterVersion: pairingHistoryRequest.shape.afterVersion })
  .refine((value) => value.afterVersion === '0' || !!value.anchor);
export function planningAccountBudget(budgets: Pick<RequestBudgets, 'take'>) {
  return ({ workspaceId, accountId }: { workspaceId: string; accountId: string }) => budgets.take([
    { purpose: 'planning-account', key: `${workspaceId}:${accountId}`, limit: 600, windowMs: 600000 },
  ]);
}
export function registerPlanningRoutes(app: FastifyInstance, input: { origin: string; planning: PlanningService; budgets: Pick<RequestBudgets, 'take'> }) {
  function auth(request: FastifyRequest) {
    const csrf = request.headers['x-csrf-token'];
    if (typeof csrf !== 'string' || !binary(32).safeParse(csrf).success) throw new AppError('CSRF_REJECTED', 'Request verification failed', 403);
    const cookie = readSessionCookie(request.headers.cookie); if (!cookie) throw new AppError('AUTH_REQUIRED', 'Authentication required', 401);
    return { cookie, csrf };
  }
  function route<T>(path: string, schema: z.ZodType<T>, handler: (body: T, auth: { cookie: string; csrf: string }) => Promise<unknown>) {
    app.post(`/v1/work/planning/${path}`, { bodyLimit: PLANNING_MAX_BYTES, preHandler: async (request) => {
      if (request.headers.origin !== input.origin || request.headers['sec-fetch-site'] === 'cross-site') throw new AppError('ORIGIN_REJECTED', 'Request origin is not allowed', 403);
      if (Object.keys(request.query as object).length) throw new AppError('INVALID_REQUEST', 'Invalid request', 400);
      await input.budgets.take([{ purpose: 'planning-source', key: request.ip, limit: 1200, windowMs: 600000 }]);
    } }, async (request) => {
      const body = parseInput(schema, request.body), credentials = auth(request);
      const fields = body as { workspaceId?: string; mutation?: { body: { binding: { workspaceId: string } } } }, workspace = fields.mutation?.body.binding.workspaceId ?? fields.workspaceId;
      if (workspace) await input.budgets.take([{ purpose: 'planning-workspace', key: workspace, limit: 2400, windowMs: 600000 }]);
      try { return await handler(body, credentials); }
      catch (error) { if (error instanceof AppError) throw error; throw new AppError('PLANNING_UNAVAILABLE', 'Planning is temporarily unavailable; retain the encrypted draft', 503); }
    });
  }
  route('context', planningReference, (body, a) => input.planning.context(a.cookie, a.csrf, body));
  route('snapshot', planningReference, (body, a) => input.planning.snapshot(a.cookie, a.csrf, body));
  route('save', planningPayload, (body, a) => input.planning.save(a.cookie, a.csrf, body));
  route('status', planningStatusRequest, (body, a) => input.planning.status(a.cookie, a.csrf, body));
  route('history', historyRequest, (body, a) => input.planning.withAuthorizedHistory(a.cookie, a.csrf,
    { workspaceId: body.workspaceId, projectId: body.projectId, operationId: body.operationId },
    (control, principal) => readAuthorizedSecurityHistoryPage(control, { operationId: body.operationId, mode: 'current', afterVersion: body.afterVersion, ...(body.anchor ? { anchor: body.anchor } : {}) },
      { workspaceId: body.workspaceId, current: { securityHead: principal.securityHead, securityVersion: principal.securityVersion },
        transcript: { securityHead: principal.securityHead, securityVersion: principal.securityVersion }, lowerVersion: '1' })));
}
