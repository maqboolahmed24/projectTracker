// Offline, deterministic build recipe for the bundled Critters artwork.
// This is a constrained serializer of the pinned CC0 source, not a runtime dependency.
import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';

const sourceUrl = 'https://cdn.hopjs.net/npm/@dicebear/styles@10.6.0/dist/critters.min.json';
const sourceSha256 = 'df67e34f221589c4949d989996008158d6cdfdcd4149ff92297c51077ca59e9e';
const sourceBytes = await readFile(new URL('./source/critters-10.6.0.json', import.meta.url));
const hash = (value) => createHash('sha256').update(value).digest('hex');
if (hash(sourceBytes) !== sourceSha256) throw new Error('Pinned artwork source checksum mismatch.');
const source = JSON.parse(sourceBytes);
const colours = [
  ['coral', 'Coral', '#e97667'], ['amber', 'Amber', '#e79b47'], ['gold', 'Gold', '#d8b34a'],
  ['lime', 'Lime', '#a4bd56'], ['teal', 'Teal', '#43a89b'], ['mint', 'Mint', '#7abb99'],
  ['sky', 'Sky', '#69b4d8'], ['blue', 'Blue', '#6698d5'], ['indigo', 'Indigo', '#7b82cb'],
  ['violet', 'Violet', '#a083cf'], ['rose', 'Rose', '#ce7f9e'], ['slate', 'Slate', '#8b9dab'],
].map(([id, label, hex]) => ({ id, label, hex }));
const selections = [
  ['Twin Antennae', 'dome', 'antennae', 'round', 'smile', 'dots', 'freckles'],
  ['Signal Box', 'block', 'antenna', 'wide', 'grin', 'bars', null],
  ['Round Ears', 'round', 'earsRound', 'bigPupils', 'tinySmile', 'belly', 'blush'],
  ['Droopy Ears', 'bell', 'earsDroop', 'happy', 'smile', 'speckles', null],
  ['Little Horns', 'peak', 'hornsSmall', 'sideeye', 'smirk', 'chevron', 'freckles'],
  ['Leaf Sprout', 'wedge', 'sprout', 'round', 'catMouth', 'dotRow', null],
  ['Three Eyes', 'blob', 'nub', 'trio', 'grin', 'belly', null],
  ['Spiky Steps', 'steps', 'spikes', 'dots', 'tooth', 'stripes', 'blush'],
  ['Winking Crown', 'dome', 'crown', 'wink', 'tinySmile', 'spot', null],
  ['Tall Bobble', 'tower', 'bobble', 'close', 'smile', 'bar', null],
  ['Pointy Ears', 'block', 'earsPointy', 'uneven', 'blep', 'ring', 'freckles'],
  ['Curved Horns', 'round', 'hornsIn', 'happy', 'teeth', 'dots', null],
  ['Little Fin', 'squat', 'fin', 'wide', 'wavy', 'bars', 'blush'],
  ['Leaning Antennae', 'lean', 'antennae', 'round', 'smirk', 'dotRow', null],
  ['Tilted Horns', 'tilt', 'hornsSmall', 'inward', 'smile', 'speckles', null],
  ['One Eye', 'chimney', 'spike', 'mono', 'laugh', 'bar', null],
  ['Square Ears', 'wedgeInv', 'earsRound', 'round', 'grin', 'stripes', 'blush'],
  ['Sprout Trio', 'bell', 'sprout', 'trio', 'smile', 'belly', null],
  ['Sleepy Bobble', 'dome', 'bobble', 'sleepy', 'tinySmile', 'ring', 'freckles'],
  ['Stepped Crown', 'steps', 'crown', 'sideeye', 'grin', 'chevron', null],
];
const tags = new Set(['g', 'path', 'rect', 'circle', 'ellipse', 'defs', 'clipPath']);
const attributes = new Set(['transform', 'opacity', 'd', 'x', 'y', 'width', 'height', 'rx', 'ry', 'fill', 'stroke', 'stroke-width', 'stroke-linecap', 'stroke-linejoin', 'cx', 'cy', 'r', 'id', 'clip-path', 'fill-rule']);
const escape = (value) => String(value).replaceAll('&', '&amp;').replaceAll('"', '&quot;').replaceAll('<', '&lt;').replaceAll('>', '&gt;');
const shapes = [];
for (let i = 0; i < selections.length; i++) {
  const [label, body, top, eyes, mouth, pattern, cheeks] = selections[i];
  const id = `shape-${String(i + 1).padStart(2, '0')}`;
  const chosen = { body, top, eyes, mouth, pattern, cheeks, animation: null };
  function attrs(values = {}) {
    return Object.entries(values).filter(([key]) => key !== 'class').map(([key, raw]) => {
      if (!attributes.has(key)) throw new Error(`Unexpected source attribute: ${key}`);
      let value = raw;
      if (typeof raw === 'object') {
        if (raw.type !== 'color' || !['body', 'accent', 'ink'].includes(raw.name)) throw new Error('Unexpected source color.');
        value = raw.name === 'ink' ? '#243247' : 'currentColor';
      }
      if (typeof value !== 'string' && typeof value !== 'number') throw new Error('Unexpected source attribute value.');
      if (key === 'id') value = `${id}-${value}`;
      if (key === 'clip-path') {
        if (!/^url\(#[A-Za-z0-9-]+\)$/.test(value)) throw new Error('Nonlocal source reference.');
        value = value.replace('url(#', `url(#${id}-`);
      }
      return ` ${key}="${escape(value)}"`;
    }).join('');
  }
  function render(nodes = []) {
    return nodes.map((node) => {
      if (node.type === 'component') {
        const variant = chosen[node.name];
        if (variant === null) return '';
        const part = source.components[node.name]?.variants[variant];
        if (!part) throw new Error(`Unknown source component: ${node.name}/${variant}`);
        return `<g${attrs(node.attributes)}>${render(part.elements)}</g>`;
      }
      if (node.type !== 'element' || !tags.has(node.name)) throw new Error(`Unsupported source element: ${node.type}/${node.name}`);
      return `<${node.name}${attrs(node.attributes)}>${render(node.children)}</${node.name}>`;
    }).join('');
  }
  // The upstream artwork is a cropped portrait. A small margin preserves the
  // original silhouette and leaves room around ears, antennae and horns.
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 120 120" fill="none"><g transform="translate(10 3)">${render(source.canvas.elements)}</g></svg>\n`;
  const file = `${id}.svg`;
  await writeFile(new URL(file, import.meta.url), svg);
  shapes.push({ id, label, file, sha256: hash(svg), components: chosen });
}
const manifest = {
  version: 1,
  source: { title: 'Critters', creator: 'DiceBear', styleUrl: 'https://www.dicebear.com/styles/critters/', definitionUrl: sourceUrl, package: '@dicebear/styles', packageVersion: '10.6.0', file: 'source/critters-10.6.0.json', sha256: sourceSha256, license: 'CC0-1.0', licenseUrl: 'https://creativecommons.org/publicdomain/zero/1.0/', retrievedOn: '2026-09-27' },
  modifications: ['Twenty fixed component combinations selected for this project.', 'Primary and accent fills use currentColor; fixed dark ink is #243247.', 'Background and animation removed; a consistent transparent 120 by 120 viewBox adds margin.', 'Source classes omitted and local clipping identifiers prefixed by shape ID.'],
  colours, shapes,
};
await writeFile(new URL('./manifest.json', import.meta.url), `${JSON.stringify(manifest, null, 2)}\n`);
console.log(`Generated ${shapes.length} fixed templates with ${colours.length} independent colours.`);
