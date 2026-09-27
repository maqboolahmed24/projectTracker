import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, readFile, writeFile, copyFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildApp } from '../src/app.js';
import { loadConfig } from '../src/config.js';
import type { Databases } from '../src/db.js';
import { loadAvatarCatalogue } from '../src/modules/avatars/routes.js';
import { avatarSelection, avatarShapeIds, avatarColourIds, resolveAvatarSelection, DEFAULT_AVATAR } from '../src/shared/avatar.js';

test('avatar catalogue is available before signup, serves every local design and colour, and never reads an account', async t => {
  const databases: Databases = { application: {} as Databases['application'], control: {} as Databases['control'],
    ready: async () => { throw new Error('No database access is needed for avatars'); }, close: async () => {} };
  const app = buildApp(loadConfig({ NODE_ENV: 'test', LOG_LEVEL: 'silent',
    DATABASE_URL: 'postgres://test:password@localhost/application', CONTROL_DATABASE_URL: 'postgres://test:password@localhost/control' }), databases);
  t.after(() => app.close());
  const response = await app.inject('/v1/avatars/catalog');
  assert.equal(response.statusCode, 200);
  const catalogue = response.json<Awaited<ReturnType<typeof loadAvatarCatalogue>>>();
  assert.deepEqual(catalogue.shapes.map(shape => shape.id), [...avatarShapeIds]);
  assert.deepEqual(catalogue.colours.map(colour => colour.id), [...avatarColourIds]);
  assert.deepEqual(catalogue.defaultSelection, DEFAULT_AVATAR);
  assert.equal(catalogue.licence.name, 'CC0-1.0');
  assert.equal(response.headers['cache-control'], 'public, max-age=86400');
  assert.equal(response.headers['x-content-type-options'], 'nosniff');
  assert.equal(response.headers['set-cookie'], undefined);
  const cached = await app.inject({ url: '/v1/avatars/catalog', headers: { 'if-none-match': response.headers.etag! } });
  assert.equal(cached.statusCode, 304); assert.equal(cached.body, '');
  const variants = new Set<string>();
  for (const shape of catalogue.shapes) for (const colour of catalogue.colours) {
    avatarSelection.parse({ shapeId: shape.id, colourId: colour.id });
    assert.match(shape.svg, /currentColor/);
    const rendered = shape.svg.replaceAll('currentColor', colour.hex);
    assert.equal(rendered.includes('currentColor'), false);
    variants.add(rendered);
  }
  assert.equal(variants.size, 240);
  assert.equal((await app.inject('/v1/avatars/catalog?url=https://example.com/picture.svg')).statusCode, 400);
  assert.equal((await app.inject({ method: 'POST', url: '/v1/avatars/catalog', payload: { image: 'data:image/png;base64,abc' } })).statusCode, 404);
});

test('avatar selection rejects unknown IDs, raw colours, uploads and extra fields; only legacy absence has a fallback', () => {
  assert.deepEqual(resolveAvatarSelection(undefined), DEFAULT_AVATAR);
  for (const bad of [null, {}, 'https://example.com/avatar.svg', { shapeId: 'shape-21', colourId: 'teal' },
    { shapeId: '../secret', colourId: 'teal' }, { shapeId: 'shape-01', colourId: '#43a89b' },
    { ...DEFAULT_AVATAR, url: 'https://example.com' }, { ...DEFAULT_AVATAR, image: '<svg/>' }]) {
    assert.throws(() => resolveAvatarSelection(bad));
  }
  const selected = { shapeId: 'shape-20' as const, colourId: 'rose' as const };
  assert.deepEqual(resolveAvatarSelection(selected), selected);
  assert.notEqual(resolveAvatarSelection(undefined), DEFAULT_AVATAR);
});

test('the bundled catalogue fails closed on changed artwork or a manifest path outside its allowlist', async t => {
  const directory = await mkdtemp(join(tmpdir(), 'ukda-avatar-test-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const manifestText = await readFile('assets/avatars/manifest.json', 'utf8');
  const manifest = JSON.parse(manifestText) as { shapes: Array<{ id: string; file: string }> };
  await writeFile(join(directory, 'manifest.json'), manifestText);
  await Promise.all(manifest.shapes.map(shape => copyFile(`assets/avatars/${shape.file}`, join(directory, shape.file))));
  await loadAvatarCatalogue(directory);
  const first = manifest.shapes[0]!;
  const original = await readFile(join(directory, first.file), 'utf8');
  await writeFile(join(directory, first.file), original.replace('currentColor', '#000000'));
  await assert.rejects(loadAvatarCatalogue(directory), /Invalid avatar asset/);
  await writeFile(join(directory, first.file), original);
  first.file = '../../outside.svg';
  await writeFile(join(directory, 'manifest.json'), JSON.stringify(manifest));
  await assert.rejects(loadAvatarCatalogue(directory), /Invalid avatar asset path/);
});
