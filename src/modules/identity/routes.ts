import type { FastifyInstance, FastifyRequest } from 'fastify';
import { z } from 'zod';
import { AppError } from '../../errors.js';
import { parseInput } from '../../http.js';
import { binary, identifier, positiveCounter } from '../../shared/contracts.js';
import type { ActivationService } from './activation.js';
import type { RequestBudgets } from './budgets.js';

const packet = binary(1, 4096);
const empty = z.object({}).strict();
const draft = z.object({ draftGeneration: positiveCounter }).strict();
const reserveInput = z.object({ licenceKey: z.string().max(100), operationId: identifier, resumeToken: binary(32) }).strict();
const requestHash = z.string().regex(/^[a-f0-9]{64}$/);

export function registerActivationRoutes(app: FastifyInstance, input: {
  origin: string; service: ActivationService; budgets: Pick<RequestBudgets, 'take'>;
}) {
  function credentials(request: FastifyRequest) {
    const { activationId } = parseInput(z.object({ activationId: identifier }).strict(), request.params);
    const value = request.headers.authorization;
    if (!value?.startsWith('Setup ') || !binary(32).safeParse(value.slice(6)).success) {
      throw new AppError('ACTIVATION_INVALID', 'Setup is not available', 404);
    }
    return { activationId, resumeToken: value.slice(6) };
  }
  async function guard(request: FastifyRequest) {
    if (request.headers.origin !== input.origin || request.headers['sec-fetch-site'] === 'cross-site') {
      throw new AppError('ORIGIN_REJECTED', 'Request origin is not allowed', 403);
    }
    if (Object.keys(request.query as object).length) throw new AppError('INVALID_REQUEST', 'Invalid request', 400);
    await input.budgets.take([{ purpose: 'activation-source', key: request.ip, limit: 120, windowMs: 600000 }]);
  }
  async function protectedGuard(request: FastifyRequest) {
    await guard(request);
    const auth = credentials(request);
    await input.budgets.take([{ purpose: 'activation-attempt', key: auth.activationId, limit: 120, windowMs: 600000 }]);
  }
  function protectedRoute(path: string, handler: (request: FastifyRequest, credentials: { activationId: string; resumeToken: string }) => Promise<unknown>) {
    app.post(`/v1/activation/:activationId/${path}`, { preHandler: protectedGuard }, async (request) => {
      try { return await handler(request, credentials(request)); }
      catch (error) {
        if (error instanceof AppError) throw error;
        throw new AppError('SETUP_UNAVAILABLE', 'Setup is temporarily unavailable; retry the same operation', 503);
      }
    });
  }
  app.post('/v1/activation/reserve', { preHandler: guard }, async (request) => {
    const body = parseInput(reserveInput, request.body);
    await input.budgets.take([{ purpose: 'activation-licence', key: body.licenceKey, limit: 20, windowMs: 600000 }]);
    try { return await input.service.reservations.reserve(body); }
    catch (error) {
      if (error instanceof AppError) throw error;
      throw new AppError('SETUP_UNAVAILABLE', 'Setup is temporarily unavailable; retry the same operation', 503);
    }
  });
  protectedRoute('status', async (request, auth) => {
    parseInput(empty, request.body);
    return input.service.status(auth.activationId, auth.resumeToken);
  });
  protectedRoute('registration', async (request, auth) => input.service.registration(auth.activationId, auth.resumeToken,
    parseInput(draft.extend({ registrationRequest: packet }).strict(), request.body)));
  protectedRoute('proof/start', async (request, auth) => input.service.startProof(auth.activationId, auth.resumeToken,
    parseInput(draft.extend({ payload: z.unknown().refine((v) => v !== undefined), startLoginRequest: packet }).strict(), request.body)));
  protectedRoute('proof/finish', async (request, auth) => input.service.finishProof(auth.activationId, auth.resumeToken,
    parseInput(draft.extend({ proofId: identifier, finishLoginRequest: packet }).strict(), request.body)));
  protectedRoute('finalize', async (request, auth) => input.service.finalize(auth.activationId, auth.resumeToken,
    parseInput(draft.extend({ requestHash }).strict(), request.body)));
  protectedRoute('replace-draft', async (request, auth) => input.service.reservations.replaceDraft(auth.activationId, auth.resumeToken,
    parseInput(z.object({ expectedDraftGeneration: positiveCounter, operationId: identifier }).strict(), request.body)));
}
