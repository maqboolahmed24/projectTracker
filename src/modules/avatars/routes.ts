import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { AppError } from '../../errors.js';
import { avatarColours, avatarShapeIds, DEFAULT_AVATAR } from '../../shared/avatar.js';

const manifestShape = z.object({
  id: z.enum(avatarShapeIds), label: z.string().min(1).max(80),
  file: z.string(), sha256: z.string().regex(/^[a-f0-9]{64}$/),
});
const manifest = z.object({ version: z.literal(1), shapes: z.array(manifestShape).length(20) });
const digest = (value: string) => createHash('sha256').update(value).digest('hex');
const geometryTags = new Set(['svg', 'g', 'path', 'rect', 'circle', 'ellipse', 'line', 'polyline', 'polygon', 'defs', 'clipPath']);

/** Only checked-in, hash-pinned artwork is served. There is no URL, seed or upload input. */
export async function loadAvatarCatalogue(directory = resolve('assets/avatars')) {
  const source = manifest.parse(JSON.parse(await readFile(resolve(directory, 'manifest.json'), 'utf8')));
  if (new Set(source.shapes.map(shape => shape.id)).size !== avatarShapeIds.length) throw new Error('Invalid avatar catalogue');
  const shapes = await Promise.all(source.shapes.map(async shape => {
    if (shape.file !== `${shape.id}.svg`) throw new Error('Invalid avatar asset path');
    const svg = await readFile(resolve(directory, shape.file), 'utf8');
    const ids = new Set([...svg.matchAll(/\bid="([a-zA-Z][\w-]*)"/g)].map(match => match[1]));
    // Source artwork uses local clipping for its shading. No external URL is allowed.
    const withoutLocalClips = svg.replace(/\sclip-path="url\(#([a-zA-Z][\w-]*)\)"/g,
      (attribute: string, id: string) => ids.has(id) && id.startsWith(`${shape.id}-`) ? '' : attribute);
    if (Buffer.byteLength(svg) > 32_768 || digest(svg) !== shape.sha256 || !svg.includes('currentColor') ||
      !/^<svg\s[^>]*xmlns="http:\/\/www\.w3\.org\/2000\/svg"[^>]*>/.test(svg) || !svg.trimEnd().endsWith('</svg>') ||
      [...svg.matchAll(/<\/?([a-zA-Z][\w:-]*)\b/g)].some(match => !geometryTags.has(match[1]!)) ||
      /\bon[a-z]+\s*=|\bhref\s*=|<!|<\?|\bstyle\s*=|url\s*\(/i.test(withoutLocalClips)) {
      throw new Error('Invalid avatar asset');
    }
    return { id: shape.id, label: shape.label, svg };
  }));
  if (new Set(shapes.map(shape => shape.svg)).size !== shapes.length) throw new Error('Duplicate avatar artwork');
  return {
    version: 1 as const, defaultSelection: DEFAULT_AVATAR, colours: avatarColours, shapes,
    licence: { name: 'CC0-1.0', source: 'https://www.dicebear.com/styles/critters/',
      url: 'https://creativecommons.org/publicdomain/zero/1.0/' },
  };
}

export function registerAvatarRoutes(app: FastifyInstance) {
  app.register(async routes => {
    const catalogue = await loadAvatarCatalogue();
    const etag = `"${digest(JSON.stringify(catalogue))}"`;
    routes.get('/v1/avatars/catalog', async (request, reply) => {
      if (!z.strictObject({}).safeParse(request.query).success) throw new AppError('INVALID_REQUEST', 'Invalid request', 400);
      // Every signup downloads the same catalogue: selected IDs are never part of an asset request.
      reply.header('cache-control', 'public, max-age=86400');
      reply.header('etag', etag);
      if (request.headers['if-none-match'] === etag) return reply.code(304).send();
      return catalogue;
    });
  });
}
