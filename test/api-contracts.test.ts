import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { buildApp } from '../src/app.js';
import { loadConfig } from '../src/config.js';
import { AppError } from '../src/errors.js';
import { parseInput, parseContentOperation, checkWritePreconditions } from '../src/http.js';
import { binary, counter, identifier, type ContentEnvelope } from '../src/shared/contracts.js';
import { parseJsonStrict } from '../src/shared/json.js';
import { scopedCacheKey } from '../src/persistence.js';
import type { Databases } from '../src/db.js';

const fakeDatabases: Databases = { ready: async () => {}, close: async () => {}, application: {} as Databases['application'], control: {} as Databases['control'] };
function app() { return buildApp(loadConfig({ NODE_ENV: 'test', LOG_LEVEL: 'silent', DATABASE_URL: 'postgres://fixture:p@localhost/app', CONTROL_DATABASE_URL: 'postgres://fixture:p@localhost/control' }), fakeDatabases); }
function envelope(): ContentEnvelope {
  return {
    header: { version: 1, purpose: 'ukda.content.v1', algorithm: 'XChaCha20-Poly1305', workspaceId: randomUUID(), scope: 'project', scopeId: randomUUID(), recordId: randomUUID(), recordType: 'task', schema: 1, keyEpoch: '1', revision: '2', operationId: randomUUID(), accountId: randomUUID(), deviceId: randomUUID(), keyGeneration: '1', permissionVersion: '1', securityVersion: '1', securityHead: 'a'.repeat(64), dataGeneration: '1', action: 'task.edit', approvalPolicyId: null, approvalPolicyRevision: null },
    nonce: Buffer.alloc(24, 1).toString('base64url'), ciphertext: Buffer.alloc(32, 2).toString('base64url'), signature: Buffer.alloc(64, 3).toString('base64url'),
  };
}

test('CP02: duplicate JSON keys, malformed Unicode, non-finite numbers and excessive nesting reject before handling', async (t) => {
  const api = app(); t.after(() => api.close());
  api.post('/fixture/parse', async () => ({ accepted: true }));
  const invalid = ['{"a":1,"a":2}', '{"a":1,"\\u0061":2}', '{"outer":{"x":1,"x":2}}', '{"n":1e999}', '{"x":"\\ud800"}', '{"constructor":{}}', '[1,]', '01', '['.repeat(70) + '0' + ']'.repeat(70)];
  for (const payload of invalid) {
    assert.throws(() => parseJsonStrict(payload));
    const result = await api.inject({ method: 'POST', url: '/fixture/parse', headers: { 'content-type': 'application/json' }, payload });
    assert.equal(result.statusCode, 400, payload);
  }
  const good = '{"a":[null,true,false,-1.5e2,"é🎉"],"b":{}}';
  assert.equal(JSON.stringify(parseJsonStrict(good)), JSON.stringify(JSON.parse(good)));
});

test('CP02: envelope structure binds workspace/scope/record/revision and rejects unsupported schemas or encodings', () => {
  const encrypted = envelope();
  const expected = { workspaceId: encrypted.header.workspaceId, scopeId: encrypted.header.scopeId, recordId: encrypted.header.recordId, recordType: 'task' };
  const input = { operationId: encrypted.header.operationId, expectedRevision: '1', dataGeneration: '1', envelope: encrypted };
  assert.deepEqual(parseContentOperation(input, expected), input);
  assert.throws(() => parseContentOperation(input, { ...expected, workspaceId: randomUUID() }), (error: unknown) => error instanceof AppError && error.code === 'INVALID_ENVELOPE_CONTEXT');
  assert.throws(() => parseContentOperation({ ...input, expectedRevision: '2' }, expected));
  assert.throws(() => parseContentOperation({ ...input, envelope: { ...encrypted, header: { ...encrypted.header, schema: 2 } } }, expected), (error: unknown) => error instanceof AppError && error.code === 'UNSUPPORTED_SCHEMA');
  assert.throws(() => parseContentOperation({ ...input, envelope: { ...encrypted, extra: true } }, expected));
  assert.throws(() => parseContentOperation({ ...input, envelope: { ...encrypted, header: { ...encrypted.header, algorithm: 'none' } } }, expected));
  for (const invalid of ['01', '-1', '1.1', '1e3', '9223372036854775808']) assert.throws(() => parseInput(counter, invalid));
  for (const invalid of ['not-an-id', encrypted.header.workspaceId.toUpperCase()]) assert.throws(() => parseInput(identifier, invalid));
  assert.equal(binary(1).safeParse('_w').success, true);
  for (const invalid of ['_x', '_w==', '+w', '_']) assert.equal(binary(1).safeParse(invalid).success, false);
});

test('CP02: errors expose consistent permission, revision, restriction, validation and schema outcomes', async (t) => {
  const api = app(); t.after(() => api.close());
  const valid = { expectedRevision: '2', actualRevision: '2', schema: 1, writeSchema: 1, dataGeneration: '1', currentGeneration: '1', restricted: false };
  api.post('/fixture/write/:failure', async (request) => {
    const failure = (request.params as { failure: string }).failure;
    if (failure === 'permission') throw new AppError('FORBIDDEN', 'This operation is not permitted', 403);
    if (failure === 'database') throw { code: '23503', detail: 'private SQL/record content' };
    checkWritePreconditions({ ...valid, ...(failure === 'revision' ? { expectedRevision: '1' } : {}), ...(failure === 'schema' ? { schema: 2 } : {}), ...(failure === 'restricted' ? { restricted: true } : {}) });
    return { accepted: true };
  });
  for (const [failure, status, code] of [['permission', 403, 'FORBIDDEN'], ['revision', 409, 'REVISION_CONFLICT'], ['schema', 409, 'UNSUPPORTED_SCHEMA'], ['restricted', 423, 'WORKSPACE_RESTRICTED'], ['database', 400, 'INVALID_RELATIONSHIP']] as const) {
    const response = await api.inject({ method: 'POST', url: `/fixture/write/${failure}` });
    assert.equal(response.statusCode, status); assert.equal(response.json().error.code, code);
    assert.equal(response.body.includes('private'), false); assert.ok(response.json().error.requestId);
  }
  assert.equal((await api.inject(`/v1/workspaces/${randomUUID()}/projects`)).statusCode, 401);
});

test('CP02: malformed decimal counters produce HTTP 400 instead of throwing during validation', async (t) => {
  const api = app(); t.after(() => api.close());
  const encrypted = envelope();
  const expected = { workspaceId: encrypted.header.workspaceId, scopeId: encrypted.header.scopeId, recordId: encrypted.header.recordId, recordType: 'task' };
  const input = { operationId: encrypted.header.operationId, expectedRevision: '1', dataGeneration: '1', envelope: encrypted };
  api.post('/fixture/counter', async (request) => { parseInput(counter, (request.body as { value: unknown }).value); return { accepted: true }; });
  api.post('/fixture/envelope', async (request) => { parseContentOperation(request.body, expected); return { accepted: true }; });
  for (const value of ['1.1', '1e3', 'x', '01', '-1', '9223372036854775808']) {
    const requests = [
      { url: '/fixture/counter', payload: { value } },
      { url: '/fixture/envelope', payload: { ...input, expectedRevision: value } },
      { url: '/fixture/envelope', payload: { ...input, envelope: { ...encrypted, header: { ...encrypted.header, revision: value } } } },
    ];
    for (const request of requests) {
      const response = await api.inject({ method: 'POST', ...request });
      assert.equal(response.statusCode, 400); assert.equal(response.json().error.code, 'INVALID_REQUEST');
    }
  }
});

test('CP02: scoped cache keys differ across workspaces, accounts and current authority/data generations', () => {
  const principal = { workspaceId: randomUUID(), profileId: randomUUID(), securityHead: 'a'.repeat(64), securityVersion: '1', dataGeneration: '1' };
  const key = scopedCacheKey(principal, 'project', 'record');
  for (const changed of [{ workspaceId: randomUUID() }, { profileId: randomUUID() }, { securityVersion: '2' }, { dataGeneration: '2' }, { securityHead: 'b'.repeat(64) }]) assert.notEqual(scopedCacheKey({ ...principal, ...changed }, 'project', 'record'), key);
});
