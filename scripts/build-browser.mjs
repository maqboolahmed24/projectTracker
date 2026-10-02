import { build } from 'esbuild';

await build({
  entryPoints: { client: 'src/client/index.ts', 'auth-worker': 'src/client/auth-worker.ts' },
  outdir: 'dist/browser', bundle: true, format: 'esm', platform: 'browser',
  target: ['es2022'], sourcemap: true, splitting: true,
  // The authenticated application supplies its own presentation layer.
  logLevel: 'info',
});
