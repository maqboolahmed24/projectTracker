import type { FastifyInstance, FastifyRequest } from 'fastify';
import { z } from 'zod';
import { AppError } from '../../errors.js';
import { parseInput } from '../../http.js';
import { binary } from '../../shared/contracts.js';
import { teamContextRequest, teamHistoryRequest, teamListRequest, teamPayload, teamReference } from '../../shared/teams.js';
import type { RequestBudgets } from '../identity/budgets.js';
import { readSessionCookie } from '../identity/sessions.js';
import type { TeamAuth, TeamService } from './teams.js';

export function teamAccountBudget(budgets: Pick<RequestBudgets, 'take'>) {
  return ({ workspaceId, accountId }: { workspaceId: string; accountId: string }) => budgets.take([
    { purpose: 'team-account', key: `${workspaceId}:${accountId}`, limit: 240, windowMs: 600000 },
    { purpose: 'team-workspace', key: workspaceId, limit: 2000, windowMs: 600000 },
  ]);
}
export function registerTeamRoutes(app: FastifyInstance, options: { origin: string; teams: TeamService; budgets: Pick<RequestBudgets, 'take'> }) {
  function credentials(request: FastifyRequest): TeamAuth {
    const csrfToken = request.headers['x-csrf-token'], cookieValue = readSessionCookie(request.headers.cookie);
    if (typeof csrfToken !== 'string' || !binary(32).safeParse(csrfToken).success) throw new AppError('CSRF_REJECTED', 'Request verification failed', 403);
    if (!cookieValue) throw new AppError('AUTH_REQUIRED', 'Authentication required', 401);
    return { csrfToken, cookieValue };
  }
  function route<T>(path: string, schema: z.ZodType<T>, handle: (auth: TeamAuth, body: T) => Promise<unknown>) {
    app.post(`/v1/work/teams/${path}`, { preHandler: async (request) => {
      if (request.headers.origin !== options.origin || request.headers['sec-fetch-site'] === 'cross-site') throw new AppError('ORIGIN_REJECTED', 'Request origin is not allowed', 403);
      if (Object.keys(request.query as object).length) throw new AppError('INVALID_REQUEST', 'Invalid request', 400);
      await options.budgets.take([{ purpose: 'team-source', key: request.ip, limit: 500, windowMs: 600000 }]);
    } }, async (request) => {
      const body = parseInput(schema, request.body), auth = credentials(request);
      try { return await handle(auth, body); }
      catch (error) { if (error instanceof AppError) throw error; throw new AppError('TEAM_UNAVAILABLE', 'Team operation is temporarily unavailable; retain the saved request', 503); }
    });
  }
  route('context', teamContextRequest, (auth, body) => options.teams.context(auth, body));
  route('save', teamPayload, (auth, body) => options.teams.save(auth, body));
  route('status', teamReference, (auth, body) => options.teams.status(auth, body));
  route('history', teamHistoryRequest, (auth, body) => options.teams.history(auth, body));
  route('list', teamListRequest, (auth, body) => options.teams.list(auth, body));
}
