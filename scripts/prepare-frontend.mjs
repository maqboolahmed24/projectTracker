import { mkdir, cp, readdir, copyFile, rm } from 'node:fs/promises';
await mkdir('web/public/client',{recursive:true});
for(const file of await readdir('dist/browser'))if(file.endsWith('.js'))await copyFile('dist/browser/'+file,'web/public/client/'+file);
// This ignored directory is generated; clearing it prevents retired assets shipping after a rename.
await rm('web/public/brand',{recursive:true,force:true});
await cp('brand/maqbool-launch','web/public/brand',{recursive:true,filter:source=>!source.endsWith('.png')&&!source.endsWith('index.html')&&!source.includes('preview.')});
console.log('Same-origin client and brand assets prepared.');
