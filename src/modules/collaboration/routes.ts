import type { FastifyInstance, FastifyRequest } from 'fastify';
import { z } from 'zod';
import { AppError } from '../../errors.js';
import { parseInput } from '../../http.js';
import { binary } from '../../shared/contracts.js';
import { collaborationContextRequest, collaborationHistoryRequest, collaborationListRequest, collaborationPayload,
  collaborationStatusRequest, COLLABORATION_MAX_PAYLOAD_BYTES } from '../../shared/collaboration.js';
import type { RequestBudgets } from '../identity/budgets.js';
import { readSessionCookie } from '../identity/sessions.js';
import type { CollaborationService } from './service.js';

export function collaborationAccountBudget(budgets: Pick<RequestBudgets,'take'>) {
  return ({ workspaceId,accountId }: { workspaceId:string;accountId:string }) => budgets.take([
    { purpose:'collaboration-account',key:`${workspaceId}:${accountId}`,limit:600,windowMs:600000 },
  ]);
}
export function registerCollaborationRoutes(app: FastifyInstance, input: { origin:string;collaboration:CollaborationService;budgets:Pick<RequestBudgets,'take'> }) {
  function auth(request: FastifyRequest) {
    const csrf = request.headers['x-csrf-token'];
    if (typeof csrf !== 'string' || !binary(32).safeParse(csrf).success) throw new AppError('CSRF_REJECTED','Request verification failed',403);
    const cookie = readSessionCookie(request.headers.cookie); if (!cookie) throw new AppError('AUTH_REQUIRED','Authentication required',401);
    return { cookie,csrf };
  }
  function route<T>(path: string, schema: z.ZodType<T>, action: (body:T,credentials:{cookie:string;csrf:string}) => Promise<unknown>) {
    app.post(`/v1/collaboration/${path}`,{ bodyLimit:COLLABORATION_MAX_PAYLOAD_BYTES,preHandler:async (request,reply) => {
      reply.header('cache-control','no-store');
      if (request.headers.origin !== input.origin || request.headers['sec-fetch-site'] === 'cross-site') throw new AppError('ORIGIN_REJECTED','Request origin is not allowed',403);
      if (Object.keys(request.query as object).length) throw new AppError('INVALID_REQUEST','Invalid request',400);
      await input.budgets.take([{ purpose:'collaboration-source',key:request.ip,limit:1200,windowMs:600000 }]);
    } },async (request) => {
      const body = parseInput(schema,request.body), credentials = auth(request);
      const fields = body as { workspaceId?:string;mutation?:{body:{binding:{workspaceId:string}}} };
      const workspaceId = fields.workspaceId ?? fields.mutation?.body.binding.workspaceId;
      if (workspaceId) await input.budgets.take([{ purpose:'collaboration-workspace',key:workspaceId,limit:2400,windowMs:600000 }]);
      try { return await action(body,credentials); }
      catch (error) { if (error instanceof AppError) throw error; throw new AppError('COLLABORATION_UNAVAILABLE','Collaboration is temporarily unavailable; retain the encrypted draft',503); }
    });
  }
  route('context',collaborationContextRequest,(body,a) => input.collaboration.context(a.cookie,a.csrf,body));
  route('save',collaborationPayload,(body,a) => input.collaboration.save(a.cookie,a.csrf,body));
  route('status',collaborationStatusRequest,(body,a) => input.collaboration.status(a.cookie,a.csrf,body));
  route('list',collaborationListRequest,(body,a) => input.collaboration.list(a.cookie,a.csrf,body));
  route('history',collaborationHistoryRequest,(body,a) => input.collaboration.history(a.cookie,a.csrf,body));
}
