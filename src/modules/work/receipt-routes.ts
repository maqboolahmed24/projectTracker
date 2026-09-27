import type { FastifyInstance } from 'fastify';
import { AppError } from '../../errors.js';
import { parseInput } from '../../http.js';
import { binary } from '../../shared/contracts.js';
import { receiptLookupRequest } from '../../shared/receipts.js';
import type { RequestBudgets } from '../identity/budgets.js';
import { readSessionCookie } from '../identity/sessions.js';
import type { ReceiptService } from './receipts.js';

export function registerReceiptRoutes(app: FastifyInstance, options: { origin: string; receipts: ReceiptService; budgets: Pick<RequestBudgets, 'take'> }) {
  app.post('/v1/work/receipts', { bodyLimit: 4096, preHandler: async (request, reply) => {
    reply.header('cache-control', 'no-store');
    if (request.headers.origin !== options.origin || request.headers['sec-fetch-site'] === 'cross-site')
      throw new AppError('ORIGIN_REJECTED', 'Request origin is not allowed', 403);
    if (Object.keys(request.query as object).length) throw new AppError('INVALID_REQUEST', 'Invalid receipt request', 400);
    await options.budgets.take([{ purpose: 'receipts-source', key: request.ip, limit: 600, windowMs: 600000 }]);
  } }, async request => {
    const body = parseInput(receiptLookupRequest, request.body), cookie = readSessionCookie(request.headers.cookie), csrf = request.headers['x-csrf-token'];
    if (!cookie) throw new AppError('AUTH_REQUIRED', 'Authentication required', 401);
    if (typeof csrf !== 'string' || !binary(32).safeParse(csrf).success) throw new AppError('CSRF_REJECTED', 'Request verification failed', 403);
    try { return await options.receipts.lookup(cookie, csrf, body); }
    catch (error) { if (error instanceof AppError) throw error; throw new AppError('RECEIPT_UNAVAILABLE', 'Operation receipt is temporarily unavailable', 503); }
  });
}
