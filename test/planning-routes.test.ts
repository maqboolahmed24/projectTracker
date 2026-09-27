import assert from 'node:assert/strict';
import test from 'node:test';
import Fastify from 'fastify';
import { randomUUID } from 'node:crypto';
import { AppError } from '../src/errors.js';
import { registerPlanningRoutes } from '../src/modules/work/planning-routes.js';
import { SESSION_COOKIE_NAME } from '../src/modules/identity/sessions.js';
import { digestObject } from '../src/shared/crypto.js';
import { planningFixture } from './planning-fixture.js';
import { origin } from './password-change-fixture.js';

test('CP07: real planning HTTP validates origin, CSRF and strict encrypted contracts, then commits and replays the authorized operation', async (t) => {
  const f = await planningFixture(t), app = Fastify({ logger: false }), budgets: unknown[] = [];
  app.setErrorHandler((error, _request, reply) => {
    const known = error instanceof AppError; reply.code(known ? error.statusCode : 503).send({ error: { code: known ? error.code : 'UNAVAILABLE' } });
  });
  registerPlanningRoutes(app, { origin, planning: f.planning, budgets: { async take(entries) { budgets.push(entries); } } });
  t.after(() => app.close());
  const auth = f.auth(), headers = { origin, cookie: `${SESSION_COOKIE_NAME}=${auth.cookieValue}`, 'x-csrf-token': auth.csrfToken }, reference = f.reference();
  const post = (path: string, payload: object, custom = headers) => app.inject({ method: 'POST', url: `/v1/work/planning/${path}`, headers: custom, payload });
  assert.equal((await post('context', reference, { ...headers, origin: 'https://foreign.example' })).statusCode, 403);
  assert.equal(budgets.length, 0);
  assert.equal((await post('context', reference, { ...headers, 'x-csrf-token': '' })).statusCode, 403);
  assert.equal((await post('context', reference, { ...headers, cookie: '' })).statusCode, 401);
  assert.equal((await post('context', { ...reference, privateName: 'Do not accept plaintext' })).statusCode, 400);
  assert.equal((await post('context?password=private', reference)).statusCode, 400);
  const initial = await post('context', reference); assert.equal(initial.statusCode, 200); assert.equal(initial.json().graph.project.state, 'planned');
  assert.equal((await post('snapshot', { ...reference, projectId: randomUUID() })).statusCode, 403);
  assert.equal((await post('history', { ...reference, afterVersion: '1' })).statusCode, 400);
  assert.equal((await post('history', { ...reference, afterVersion: '0' })).statusCode, 200);
  const draft = await f.preparePlanning({ action: 'start_project' }), saved = await post('save', draft);
  assert.equal(saved.statusCode, 200); assert.equal(saved.json().state, 'completed');
  assert.deepEqual((await post('save', draft)).json(), saved.json());
  const b = draft.mutation.body.binding;
  const status = await post('status', { workspaceId: b.workspaceId, projectId: b.projectId, operationId: b.operationId, dataGeneration: b.dataGeneration, requestHash: await digestObject(draft) });
  assert.deepEqual(status.json(), saved.json());
  assert.equal((await post('snapshot', reference)).json().graph.project.state, 'active');
});
