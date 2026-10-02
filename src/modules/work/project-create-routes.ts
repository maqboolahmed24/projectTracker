import type { FastifyInstance, FastifyRequest } from 'fastify';
import { z } from 'zod';
import { AppError } from '../../errors.js';
import { parseInput } from '../../http.js';
import { binary } from '../../shared/contracts.js';
import { projectCreateRequest, projectCreatePayload, projectCreateFinalize, projectCreateReference } from '../../shared/project-create.js';
import type { RequestBudgets } from '../identity/budgets.js';
import type { ProjectCreateService } from './project-create.js';
import { pairingHistoryRequest, readAuthorizedSecurityHistoryPage } from '../identity/security-history.js';
import { readSessionCookie } from '../identity/sessions.js';
const historyRequest = projectCreateReference.extend({ anchor: pairingHistoryRequest.shape.anchor, afterVersion: pairingHistoryRequest.shape.afterVersion })
  .refine((value) => value.afterVersion === '0' || !!value.anchor);
export function projectCreateAccountBudget(budgets: Pick<RequestBudgets, 'take'>) {
  return ({ workspaceId, accountId, history }: { workspaceId: string; accountId: string; history: boolean }) => budgets.take([
    { purpose: history ? 'project-create-history-account' : 'project-create-account', key: `${workspaceId}:${accountId}`, limit: history ? 1000 : 120, windowMs: 600000 },
    { purpose: history ? 'project-create-resolved-history-workspace' : 'project-create-resolved-workspace', key: workspaceId, limit: history ? 4000 : 480, windowMs: 600000 },
  ]);
}
export function registerProjectCreateRoutes(app: FastifyInstance, input: { origin: string; projectCreation: ProjectCreateService; budgets: Pick<RequestBudgets, 'take'> }) {
  function auth(request: FastifyRequest) {
    const csrfToken = request.headers['x-csrf-token'];
    if (typeof csrfToken !== 'string' || !binary(32).safeParse(csrfToken).success) throw new AppError('CSRF_REJECTED', 'Request verification failed', 403);
    const cookieValue = readSessionCookie(request.headers.cookie); if (!cookieValue) throw new AppError('AUTH_REQUIRED', 'Authentication required', 401);
    return { cookieValue, csrfToken };
  }
  function route<T>(path: string, schema: z.ZodType<T>, handler: (body: T, request: FastifyRequest) => Promise<unknown>, paged = false) {
    app.post(`/v1/work/projects/create/${path}`, { preHandler: async (request) => {
      if (request.headers.origin !== input.origin || request.headers['sec-fetch-site'] === 'cross-site') throw new AppError('ORIGIN_REJECTED', 'Request origin is not allowed', 403);
      if (Object.keys(request.query as object).length) throw new AppError('INVALID_REQUEST', 'Invalid request', 400);
      await input.budgets.take([{ purpose: paged ? 'project-create-history-source' : 'project-create-source', key: request.ip, limit: paged ? 1200 : 120, windowMs: 600000 }]);
    } }, async (request) => {
      const body = parseInput(schema, request.body), fields = body as { workspaceId?: string; operationId?: string; transition?: { body: { binding: { workspaceId: string; operationId: string } } } };
      const ref = fields.transition?.body.binding ?? fields;
      await input.budgets.take([
        ...(ref.workspaceId ? [{ purpose: paged ? 'project-create-history-workspace' : 'project-create-workspace', key: ref.workspaceId, limit: paged ? 4000 : 480, windowMs: 600000 }] : []),
        ...(ref.operationId ? [{ purpose: paged ? 'project-create-history-operation' : 'project-create-operation', key: `${ref.workspaceId}:${ref.operationId}`, limit: paged ? 1000 : 120, windowMs: 600000 }] : []),
      ]);
      try { return await handler(body, request); }
      catch (error) { if (error instanceof AppError) throw error; throw new AppError('PROJECT_UNAVAILABLE', 'Project creation is temporarily unavailable; retain the local draft', 503); }
    });
  }
  route('context', projectCreateRequest, (body, request) => { const a = auth(request); return input.projectCreation.context(a.cookieValue, a.csrfToken, body); });
  route('stage', projectCreatePayload, (body, request) => { const a = auth(request); return input.projectCreation.stage(a.cookieValue, a.csrfToken, body); });
  route('finalize', projectCreateFinalize, (body, request) => { const a = auth(request); return input.projectCreation.finalize(a.cookieValue, a.csrfToken, body); });
  route('status', projectCreateReference, (body, request) => { const a = auth(request); return input.projectCreation.status(a.cookieValue, a.csrfToken, body); });
  route('history', historyRequest, (body, request) => {
    const a = auth(request);
    return input.projectCreation.withAuthorizedHistory(body.workspaceId, a, (control, context) => readAuthorizedSecurityHistoryPage(control,
      { operationId: body.operationId, mode: 'current', afterVersion: body.afterVersion, ...(body.anchor ? { anchor: body.anchor } : {}) },
      { workspaceId: body.workspaceId, current: context.current, transcript: context.current, lowerVersion: '1' }));
  }, true);
}
