import { PassThrough } from 'node:stream';
import type { FastifyInstance } from 'fastify';
import { AppError } from '../../errors.js';
import { parseInput } from '../../http.js';
import { binary } from '../../shared/contracts.js';
import { LIVE_POLL_MS, LIVE_STREAM_MS, liveRequest } from '../../shared/live.js';
import type { RequestBudgets } from '../identity/budgets.js';
import { readSessionCookie } from '../identity/sessions.js';
import type { LiveService } from './live.js';

export function registerLiveRoutes(app: FastifyInstance, input: {
  origin: string; live: Pick<LiveService, 'checkpoint'>; budgets: Pick<RequestBudgets, 'take'>;
  pollMs?: number; streamMs?: number;
}) {
  const streams = new Set<() => void>(), byCookie = new Map<string, number>();
  app.addHook('preClose', async () => { for (const stop of streams) stop(); });
  app.post('/v1/work/live', { bodyLimit: 1024, preHandler: async (request, reply) => {
    reply.header('cache-control', 'no-store');
    if (request.headers.origin !== input.origin || request.headers['sec-fetch-site'] === 'cross-site') throw new AppError('ORIGIN_REJECTED', 'Request origin is not allowed', 403);
    if (Object.keys(request.query as object).length) throw new AppError('INVALID_REQUEST', 'Invalid live request', 400);
    await input.budgets.take([{ purpose: 'live-source', key: request.ip, limit: 120, windowMs: 600_000 }]);
  } }, async (request, reply) => {
    const body = parseInput(liveRequest, request.body), cookie = readSessionCookie(request.headers.cookie), csrf = request.headers['x-csrf-token'];
    if (!cookie) throw new AppError('AUTH_REQUIRED', 'Authentication required', 401);
    if (typeof csrf !== 'string' || !binary(32).safeParse(csrf).success) throw new AppError('CSRF_REJECTED', 'Request verification failed', 403);
    if (streams.size >= 128 || (byCookie.get(cookie) ?? 0) >= 2) throw new AppError('LIVE_LIMIT', 'Live connection limit reached', 429);
    // Reserve before awaiting so simultaneous opens cannot exceed the limit.
    byCookie.set(cookie, (byCookie.get(cookie) ?? 0) + 1);
    const stream = new PassThrough({ highWaterMark: 4096 });
    let stopped = false, timer: ReturnType<typeof setTimeout> | undefined;
    const deadline = Date.now() + (input.streamMs ?? LIVE_STREAM_MS);
    const stop = () => {
      if (stopped) return; stopped = true;
      if (timer) clearTimeout(timer);
      streams.delete(stop);
      const count = (byCookie.get(cookie) ?? 1) - 1;
      if (count) byCookie.set(cookie, count); else byCookie.delete(cookie);
      stream.end();
    };
    streams.add(stop); stream.on('close', stop); reply.raw.on('close', stop);
    try {
      const first = await input.live.checkpoint(cookie, csrf, body);
      if (stopped) return reply;
      reply.header('content-type', 'text/event-stream; charset=utf-8').header('x-accel-buffering', 'no').header('connection', 'keep-alive');
      stream.write(`event: checkpoint\ndata: ${JSON.stringify(first)}\n\n`);
      const poll = async () => {
        timer = undefined;
        if (stopped || Date.now() >= deadline) { stop(); return; }
        try {
          const next = await input.live.checkpoint(cookie, csrf, body);
          // Revocation/fence/generation/session errors terminate before any batch.
          if (stopped) return;
          if (!stream.write(`event: checkpoint\ndata: ${JSON.stringify(next)}\n\n`)) { stop(); return; }
          timer = setTimeout(() => { void poll(); }, input.pollMs ?? LIVE_POLL_MS);
          timer.unref();
        } catch { stop(); }
      };
      timer = setTimeout(() => { void poll(); }, input.pollMs ?? LIVE_POLL_MS); timer.unref();
      return reply.send(stream);
    } catch (error) { stop(); throw error; }
  });
}
