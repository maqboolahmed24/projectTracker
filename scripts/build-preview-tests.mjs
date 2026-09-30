import {build} from 'esbuild';
await build({entryPoints:['test/browser/preview-harness.tsx'],outfile:'.local/testing/preview-browser/preview-harness.js',bundle:true,platform:'browser',format:'esm',jsx:'automatic',target:['es2022'],define:{'process.env.NODE_ENV':'"production"'},logLevel:'warning'});
