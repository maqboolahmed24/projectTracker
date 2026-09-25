import type { FastifyInstance, FastifyRequest } from 'fastify';
import { z } from 'zod';
import { AppError } from '../../errors.js';
import { parseInput } from '../../http.js';
import { binary, identifier } from '../../shared/contracts.js';
import type { AuthenticationService } from './authentication.js';
import type { RequestBudgets } from './budgets.js';
import { buildSessionCookie, clearSessionCookie, readSessionCookie, type SessionService, type IssuedSession } from './sessions.js';
import { deviceChallenge } from '../../shared/auth.js';

const packet = binary(1, 4096);
const loginStart = z.strictObject({ workspaceId: identifier, accountId: identifier, startLoginRequest: packet });
const loginFinish = z.strictObject({ loginId: identifier, finishLoginRequest: packet });
const empty = z.strictObject({});

/** The HttpOnly bearer stays in the cookie. Response bodies contain only public state and CSRF. */
export function publicSession(issued: IssuedSession) {
  return { sessionId: issued.sessionId, workspaceId: issued.workspaceId, accountId: issued.accountId,
    deviceId: issued.deviceId, accessLevel: issued.accessLevel, credentialGeneration: issued.credentialGeneration,
    sessionGeneration: issued.sessionGeneration, dataGeneration: issued.dataGeneration, csrfToken: issued.csrfToken,
    authenticatedAt: issued.authenticatedAt, idleExpiresAt: issued.idleExpiresAt, absoluteExpiresAt: issued.absoluteExpiresAt };
}

export function registerAuthenticationRoutes(app: FastifyInstance, input: {
  origin: string; authentication: AuthenticationService; sessions: SessionService; budgets: Pick<RequestBudgets, 'take'>;
}) {
  async function originGuard(request: FastifyRequest) {
    if (request.headers.origin !== input.origin || request.headers['sec-fetch-site'] === 'cross-site') {
      throw new AppError('ORIGIN_REJECTED', 'Request origin is not allowed', 403);
    }
    if (Object.keys(request.query as object).length) throw new AppError('INVALID_REQUEST', 'Invalid request', 400);
    await input.budgets.take([{ purpose: 'authentication-source', key: request.ip, limit: 60, windowMs: 600000 }]);
  }
  const cookie = (request: FastifyRequest) => {
    const value = readSessionCookie(request.headers.cookie);
    if (!value) throw new AppError('AUTH_REQUIRED', 'Authentication required', 401);
    return value;
  };
  const csrf = (request: FastifyRequest) => {
    const value = request.headers['x-csrf-token'];
    if (typeof value !== 'string' || !binary(32).safeParse(value).success) throw new AppError('CSRF_REJECTED', 'Request verification failed', 403);
    return value;
  };
  app.post('/v1/auth/login/start', { preHandler: originGuard }, async (request) => {
    const body = parseInput(loginStart, request.body);
    await input.budgets.take([
      { purpose: 'authentication-account', key: `${body.workspaceId}:${body.accountId}`, limit: 15, windowMs: 600000 },
      { purpose: 'authentication-workspace', key: body.workspaceId, limit: 120, windowMs: 600000 },
    ]);
    return input.authentication.startLogin(body);
  });
  app.post('/v1/auth/login/finish', { preHandler: originGuard }, async (request, reply) => {
    const previousCookie = readSessionCookie(request.headers.cookie);
    const issued = await input.authentication.finishLogin(parseInput(loginFinish, request.body), previousCookie ? { previousCookie } : {});
    reply.header('set-cookie', buildSessionCookie(issued.cookieValue, new Date(issued.absoluteExpiresAt)));
    return publicSession(issued);
  });
  app.post('/v1/auth/session', { preHandler: originGuard }, async (request) => {
    parseInput(empty, request.body);
    const session = await input.sessions.authenticate(cookie(request));
    // Explicit fields avoid accidentally exposing a bearer or future internal authority values.
    return { workspaceId: session.workspaceId, accountId: session.profileId, sessionId: session.sessionId,
      deviceId: session.deviceId, accessLevel: session.accessLevel, credentialGeneration: session.credentialGeneration,
      sessionGeneration: session.sessionGeneration, dataGeneration: session.dataGeneration,
      securityHead: session.securityHead, securityVersion: session.securityVersion,
      authenticatedAt: session.authenticatedAt, idleExpiresAt: session.idleExpiresAt,
      absoluteExpiresAt: session.absoluteExpiresAt, csrfToken: session.csrfToken };
  });
  app.post('/v1/auth/device-challenge/start', { preHandler: originGuard }, async (request) => {
    const body = parseInput(z.strictObject({ deviceId: identifier }), request.body);
    return input.sessions.beginDeviceChallenge(cookie(request), csrf(request), body.deviceId);
  });
  app.post('/v1/auth/device-challenge/finish', { preHandler: originGuard }, async (request, reply) => {
    const body = parseInput(z.strictObject({ body: deviceChallenge, signature: binary(64) }), request.body);
    const issued = await input.sessions.completeDeviceChallenge(cookie(request), csrf(request), body);
    reply.header('set-cookie', buildSessionCookie(issued.cookieValue, new Date(issued.absoluteExpiresAt)));
    return publicSession(issued);
  });
  app.post('/v1/auth/reauth/start', { preHandler: originGuard }, async (request) => {
    const body = parseInput(z.strictObject({ startLoginRequest: packet }), request.body);
    const principal = await input.sessions.authenticate(cookie(request), { csrfToken: csrf(request), approved: true });
    await input.budgets.take([
      { purpose: 'authentication-account', key: `${principal.workspaceId}:${principal.profileId}`, limit: 15, windowMs: 600000 },
      { purpose: 'authentication-workspace', key: principal.workspaceId, limit: 120, windowMs: 600000 },
    ]);
    return input.authentication.startReauthentication(body, { cookieValue: cookie(request), csrfToken: csrf(request) });
  });
  app.post('/v1/auth/reauth/finish', { preHandler: originGuard }, async (request, reply) => {
    const issued = await input.authentication.finishReauthentication(parseInput(loginFinish, request.body),
      { cookieValue: cookie(request), csrfToken: csrf(request) });
    reply.header('set-cookie', buildSessionCookie(issued.cookieValue, new Date(issued.absoluteExpiresAt)));
    return publicSession(issued);
  });
  app.post('/v1/auth/logout', { preHandler: originGuard }, async (request, reply) => {
    parseInput(empty, request.body);
    await input.sessions.logout(cookie(request), csrf(request));
    reply.header('set-cookie', clearSessionCookie());
    return { loggedOut: true };
  });
}
