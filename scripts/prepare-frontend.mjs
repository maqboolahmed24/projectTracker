import { mkdir, cp, readdir, copyFile, rm } from 'node:fs/promises';
await mkdir('web/public/client',{recursive:true});
for(const file of await readdir('dist/browser'))if(file.endsWith('.js'))await copyFile('dist/browser/'+file,'web/public/client/'+file);
// Clear generated assets so retired branding cannot ship after a rename.
await rm('web/public/brand',{recursive:true,force:true});
await cp('brand/maqbool-launch','web/public/brand',{recursive:true,filter:source=>!source.endsWith('.png')&&!source.endsWith('index.html')&&!source.includes('preview.')});
await mkdir('web/public/preview',{recursive:true});
await copyFile('node_modules/pdfjs-dist/build/pdf.worker.min.mjs','web/public/preview/pdf.worker.min.mjs');
console.log('Same-origin client and brand assets prepared.');
