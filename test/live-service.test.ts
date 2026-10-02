import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import test from 'node:test';
import Fastify from 'fastify';
import { AppError } from '../src/errors.js';
import { LiveService } from '../src/modules/work/live.js';
import { registerLiveRoutes } from '../src/modules/work/live-routes.js';
import { SESSION_COOKIE_NAME } from '../src/modules/identity/sessions.js';
import { planningFixture } from './planning-fixture.js';
import { origin } from './password-change-fixture.js';

test('CP10 live: authorized metadata changes invalidate; another project is invisible and scope revocation stops the next batch', async (t) => {
  const f = await planningFixture(t), hidden = await f.createProject('Never disclose this project');
  const member = await f.joined(), roleId = (await f.admin.control.query("SELECT role_id FROM security.roles WHERE workspace_id=$1 AND template='member'", [f.workspaceId])).rows[0].role_id as string;
  await f.finalize(await f.draft('set_access', member.binding.accountId, { roleId, projectIds: [f.projectId] }));
  const login = await f.login(member.prepared, member.registered.exportKey), live = new LiveService(f);
  const read = () => live.checkpoint(login.auth.cookieValue, login.auth.csrfToken, { workspaceId: f.workspaceId });
  const initial = await read(); assert.equal((await read()).fingerprint, initial.fingerprint);
  await f.execute({ action: 'edit_project', patch: { phaseLabel: 'phase' } }, { projectId: hidden, content: { name: 'Secret revised' } });
  assert.equal((await read()).fingerprint, initial.fingerprint);
  await f.execute({ action: 'edit_project', patch: { phaseLabel: 'phase' } }, { content: { name: 'Visible private revision' } });
  const changed = await read(); assert.notEqual(changed.fingerprint, initial.fingerprint);
  assert.deepEqual(Object.keys(changed).sort(), ['fingerprint', 'observedAt', 'version']);
  assert.equal(JSON.stringify(changed).includes('private'), false); assert.equal(JSON.stringify(changed).includes(f.projectId), false);
  await assert.rejects(live.checkpoint(login.auth.cookieValue, login.auth.csrfToken, { workspaceId: randomUUID() }), (e: unknown) => e instanceof AppError && e.statusCode === 404);
  await f.finalize(await f.draft('set_access', member.binding.accountId, { roleId, projectIds: [] }));
  await assert.rejects(read(), (e: unknown) => e instanceof AppError && e.statusCode === 401);
});

test('CP10 live HTTP: strict origin/CSRF/body and per-batch validation terminate a stream on lost authority', async (t) => {
  const app = Fastify({ logger: false }); t.after(() => app.close()); let checks = 0;
  app.setErrorHandler((error, _request, reply) => reply.code(error instanceof AppError ? error.statusCode : 503).send({ error: { code: error instanceof AppError ? error.code : 'UNAVAILABLE' } }));
  const workspaceId = randomUUID(), cookie = `v1.${workspaceId}.${randomUUID()}.${Buffer.alloc(32, 1).toString('base64url')}`, csrf = Buffer.alloc(32, 2).toString('base64url');
  registerLiveRoutes(app, { origin, pollMs: 5, streamMs: 100, budgets: { async take() {} }, live: { async checkpoint() {
    checks++; if (checks > 1) throw new AppError('AUTH_REQUIRED', 'Authentication required', 401);
    return { version: 1, fingerprint: 'c'.repeat(64), observedAt: '2026-09-26T00:00:00.000Z' };
  } } });
  const headers = { origin, cookie: `${SESSION_COOKIE_NAME}=${cookie}`, 'x-csrf-token': csrf }, payload = { workspaceId };
  const post = (custom = headers, body: object = payload, url = '/v1/work/live') => app.inject({ method: 'POST', url, headers: custom, payload: body });
  assert.equal((await post({ ...headers, origin: 'https://foreign.example' })).statusCode, 403);
  assert.equal((await post({ ...headers, 'x-csrf-token': '' })).statusCode, 403);
  assert.equal((await post({ ...headers, cookie: '' })).statusCode, 401);
  assert.equal((await post(headers, { ...payload, projectName: 'Forbidden plaintext' })).statusCode, 400);
  assert.equal((await post(headers, payload, '/v1/work/live?token=forbidden')).statusCode, 400);
  assert.equal(checks, 0);
  const response = await post(); assert.equal(response.statusCode, 200); assert.equal(checks, 2);
  assert.equal(response.headers['cache-control'], 'no-store'); assert.match(response.headers['content-type'] as string, /^text\/event-stream/);
  assert.equal(response.body.split('event: checkpoint').length - 1, 1); assert.equal(response.body.includes(cookie), false);
});
