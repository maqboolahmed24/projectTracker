import { randomUUID } from 'node:crypto';
import type { Writable } from 'node:stream';
import Fastify, { LogController } from 'fastify';
import type { Config } from './config.js';
import { createDatabases, type Databases } from './db.js';
import { AppError } from './errors.js';
import { parseJsonStrict } from './shared/json.js';
import { mapDatabaseError } from './http.js';
import { registerWorkReadRoutes, type RequireSession } from './modules/work/routes.js';

export function buildApp(config: Config, databases: Databases = createDatabases(config), logStream?: Writable, requireSession?: RequireSession) {
  const app = Fastify({
    logger: {
      level: config.LOG_LEVEL,
      redact: ['req.headers.authorization', 'req.headers.cookie', 'res.headers["set-cookie"]'],
      ...(logStream ? { stream: logStream } : {}),
    },
    logController: new LogController({ disableRequestLogging: true }),
    genReqId: () => randomUUID(),
    requestIdHeader: false,
    trustProxy: false,
    bodyLimit: 1024 * 1024,
    requestTimeout: 30_000,
    onProtoPoisoning: 'error',
    onConstructorPoisoning: 'error',
  });

  app.removeContentTypeParser('application/json');
  app.addContentTypeParser('application/json', { parseAs: 'string' }, (_request, body, done) => {
    try { done(null, parseJsonStrict(String(body))); }
    catch { done(new AppError('INVALID_REQUEST', 'Invalid JSON', 400)); }
  });

  app.addHook('onRequest', async (request, reply) => {
    reply.header('x-request-id', request.id);
    reply.header('x-content-type-options', 'nosniff');
    reply.header('referrer-policy', 'no-referrer');
    reply.header('cache-control', 'no-store');
    reply.header('content-security-policy', "default-src 'none'; frame-ancestors 'none'");
    if (config.NODE_ENV === 'production') reply.header('strict-transport-security', 'max-age=31536000');
  });
  app.addHook('onResponse', async (request, reply) => {
    // Route templates omit account IDs/query tokens; request/response bodies are never logged.
    app.log.info({ requestId: request.id, route: request.routeOptions.url ?? 'unmatched', method: request.method, status: reply.statusCode }, 'request completed');
  });
  app.addHook('onClose', async () => databases.close());
  app.setErrorHandler((error, request, reply) => {
    const mapped = mapDatabaseError(error);
    if (mapped) error = mapped;
    if (error instanceof AppError) {
      return reply.code(error.statusCode).send({ error: { code: error.code, message: error.message, requestId: request.id } });
    }
    const httpError = error as { statusCode?: number };
    const status = httpError.statusCode && httpError.statusCode >= 400 && httpError.statusCode < 500 ? httpError.statusCode : 500;
    if (status === 500) app.log.error({ requestId: request.id, code: 'INTERNAL_ERROR' }, 'request failed');
    return reply.code(status).send({ error: { code: status === 500 ? 'INTERNAL_ERROR' : 'INVALID_REQUEST', message: status === 500 ? 'The request could not be completed' : 'Invalid request', requestId: request.id } });
  });
  app.setNotFoundHandler((request, reply) => reply.code(404).send({ error: { code: 'NOT_FOUND', message: 'Route not found', requestId: request.id } }));

  app.get('/health/live', async () => ({ status: 'ok', service: 'ukda-api' }));
  app.get('/health/ready', async (_request, reply) => {
    try {
      await databases.ready();
      return { status: 'ready' };
    } catch {
      return reply.code(503).send({ status: 'unavailable' });
    }
  });
  registerWorkReadRoutes(app, databases, requireSession ?? (async () => {
    // Password/device authentication is introduced at checkpoint 4; never accept client-asserted identities.
    throw new AppError('AUTH_REQUIRED', 'Authentication required', 401);
  }));
  return app;
}
