import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import Fastify from 'fastify';
import { AppError } from '../src/errors.js';
import { registerSecurityRoutes } from '../src/modules/identity/security-routes.js';
import { registerEnrolmentRoutes, enrolmentAccountBudget } from '../src/modules/identity/enrolment-routes.js';
import { SESSION_COOKIE_NAME } from '../src/modules/identity/sessions.js';
import type { RequestBudget } from '../src/modules/identity/budgets.js';
import { pairingList } from '../src/shared/pairing.js';
import { enrolmentList } from '../src/shared/enrolment-api.js';

test('onboarding: discovery and status use separate bounded read budgets without relaxing origin, cookie or strict input checks', async t => {
  const app = Fastify({ logger: false }), workspaceId = randomUUID(), accountId = randomUUID(), operationId = randomUUID();
  const origin = 'https://ukda.example', seen: RequestBudget[] = [], calls: string[] = [], csrf = 'A'.repeat(43), cookie = `v1.${workspaceId}.${randomUUID()}.${'A'.repeat(43)}`;
  t.after(() => app.close());
  app.setErrorHandler((error, _request, reply) => { const e = error as AppError; void reply.code(e.statusCode ?? 500).send({ code: e.code }); });
  const service = new Proxy({}, { get: (_target, name) => async () => { calls.push(String(name)); return {}; } });
  const budgets = { async take(entries: readonly RequestBudget[]) { seen.push(...entries); } };
  registerSecurityRoutes(app, { origin, budgets, databases: {} as never, pairing: service as never, passwordChange: service as never,
    sessions: { async authenticate(value: string) { if (value !== cookie) throw new AppError('AUTH_REQUIRED', 'Authentication required', 401); return { workspaceId, accountId }; } } as never });
  registerEnrolmentRoutes(app, { origin, budgets, enrolment: service as never });
  const headers = { origin, cookie: `${SESSION_COOKIE_NAME}=${cookie}`, 'x-csrf-token': csrf };
  const post = (path: string, payload: object, requestHeaders = headers) => app.inject({ method: 'POST', url: '/v1/auth/' + path, headers: requestHeaders, payload });
  assert.equal((await post('pairing/list', {})).statusCode, 200);
  assert.equal((await post('pairing/inspect', { operationId })).statusCode, 200);
  assert.equal((await post('enrolment/list', { workspaceId })).statusCode, 200);
  assert.equal((await post('enrolment/inspect', { workspaceId, operationId })).statusCode, 200);
  assert.equal((await post('enrolment/status', { workspaceId, operationId })).statusCode, 200);
  assert.ok(seen.some(entry => entry.purpose === 'pairing-read-account' && entry.limit === 600));
  assert.ok(seen.some(entry => entry.purpose === 'enrolment-read-operation' && entry.limit === 600));
  assert.equal(seen.some(entry => ['authentication-source', 'security-account', 'enrolment-source', 'enrolment-operation'].includes(entry.purpose)), false);
  const successful = calls.length;
  assert.equal((await post('pairing/list', {}, { ...headers, origin: 'https://foreign.example' })).statusCode, 403);
  assert.equal((await post('pairing/list', {}, { ...headers, cookie: '' })).statusCode, 401);
  assert.equal((await post('pairing/list', {}, { ...headers, 'x-csrf-token': '' })).statusCode, 403);
  for (const payload of [{ limit: 0 }, { limit: 51 }, { after: 'wrong' }, { workspaceId }, { resumeToken: 'hidden' }]) assert.equal((await post('pairing/list', payload)).statusCode, 400);
  assert.equal(calls.length, successful);
  await post('pairing/claim', { operationId }); await post('enrolment/claim', { workspaceId, operationId });
  assert.ok(seen.some(entry => entry.purpose === 'security-account' && entry.limit === 60));
  assert.ok(seen.some(entry => entry.purpose === 'enrolment-operation' && entry.limit === 120));
  seen.length = 0;
  await enrolmentAccountBudget(budgets)({ workspaceId, accountId, history: false, read: true });
  assert.deepEqual(seen.map(entry => [entry.purpose, entry.limit]), [['enrolment-target-read-account', 600], ['enrolment-target-read-workspace', 2400]]);
});

test('onboarding: discovery contracts reject embedded capabilities and preserve invitation-start state', () => {
  const workspaceId = randomUUID(), accountId = randomUUID(), operationId = randomUUID(), observedAt = new Date().toISOString();
  const row = { operationId, accountId, deviceId: randomUUID(), state: 'waiting_approver', expiresAt: observedAt, approverAccountId: null, approverDeviceId: null };
  assert.ok(pairingList.safeParse({ workspaceId, observedAt, requests: [row], nextCursor: null }).success);
  for (const extra of [{ transcriptDigest: 'a'.repeat(64) }, { resumeToken: 'private' }, { displayName: 'Private name' }, { signingPublicKey: 'private' }]) {
    assert.equal(pairingList.safeParse({ workspaceId, observedAt, requests: [{ ...row, ...extra }], nextCursor: null }).success, false);
  }
  const invitation = { operationId, accountId, kind: 'join_member', state: 'issued', expiresAt: observedAt, issuerAccountId: accountId, authorizerAccountId: null, recipientStarted: true };
  assert.equal(enrolmentList.parse({ workspaceId, observedAt, invitations: [invitation], nextCursor: null }).invitations[0]!.recipientStarted, true);
});
