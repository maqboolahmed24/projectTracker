import { mkdir, cp, readdir, copyFile } from 'node:fs/promises';
await mkdir('web/public/client',{recursive:true});
for(const file of await readdir('dist/browser'))if(file.endsWith('.js'))await copyFile('dist/browser/'+file,'web/public/client/'+file);
await cp('brand/ukda-launch','web/public/brand',{recursive:true,filter:source=>!source.endsWith('.png')&&!source.endsWith('index.html')&&!source.includes('preview.')});
console.log('Same-origin client and brand assets prepared.');
