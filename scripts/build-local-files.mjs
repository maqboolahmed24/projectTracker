import { build } from 'esbuild';
import { mkdir,copyFile,writeFile,chmod,readFile,readdir,rm,stat } from 'node:fs/promises';
import { resolve,join,dirname } from 'node:path';
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
const exec=promisify(execFile);
if(process.platform!=='darwin'||process.arch!=='arm64'||!process.version.startsWith('v24.'))throw new Error('Build the initial Apple silicon package with the pinned Node 24 runtime on macOS.');
const parent=resolve('dist/local-files'),dir=join(parent,'Maqbool Companion'),out=resolve('web/public/downloads/maqbool-local-mac.zip');
await rm(parent,{recursive:true,force:true});await mkdir(join(dir,'licences'),{recursive:true});await mkdir(dirname(out),{recursive:true});
const result=await build({entryPoints:['scripts/local-files.ts'],outfile:join(dir,'companion.mjs'),bundle:true,format:'esm',platform:'node',target:'node24',metafile:true,
 banner:{js:"import { createRequire as __createRequire } from 'node:module'; const require = __createRequire(import.meta.url);"}});
await copyFile(process.execPath,join(dir,'node'));await chmod(join(dir,'node'),0o755);
await copyFile('docs/local-files/NODE-LICENSE.txt',join(dir,'licences/Node.txt'));
// Include licence notices for every bundled package, not the application's full node_modules tree.
const packages=new Set(Object.keys(result.metafile.inputs).flatMap(p=>{const m=p.match(/^node_modules\/(?:@[^/]+\/)?[^/]+/);return m?[m[0]]:[];}));
const notices=[];for(const path of [...packages].sort()){
 const pkg=JSON.parse(await readFile(path+'/package.json','utf8'));notices.push(`${pkg.name} ${pkg.version}: ${pkg.license??'see package licence'}`);
 const candidates=(await readdir(path)).filter(n=>/^(license|licence|copying|notice)/i.test(n));
 for(const name of candidates)if((await stat(join(path,name))).isFile())await copyFile(join(path,name),join(dir,'licences',pkg.name.replaceAll('/','_')+'-'+name));
}
await writeFile(join(dir,'licences','Packages.txt'),notices.join('\n')+'\n');
await copyFile('docs/local-files/README.txt',join(dir,'Read me.txt'));
for(const [name,command] of [['Setup','setup --interactive'],['Start','start'],['New connection','new-connection']]){
 const file=join(dir,name+'.command');await writeFile(file,`#!/bin/zsh\ncd -- "$(dirname -- "$0")" || exit 1\n./node companion.mjs ${command}\nresult=$?\nif [[ $result -ne 0 ]]; then\n  print '\\nPlease read the setup guide, then try again.'\nfi\nprint '\\nPress Return to close this window.'\nread -r\nexit $result\n`);await chmod(file,0o755);
}
await exec(join(dir,'node'),[join(dir,'companion.mjs'),'--help'],{timeout:10000});
await rm(out,{force:true});await exec('/usr/bin/ditto',['-c','-k','--sequesterRsrc','--keepParent',dir,out]);
const bytes=await readFile(out);await writeFile(out+'.sha256',createHash('sha256').update(bytes).digest('hex')+'  maqbool-local-mac.zip\n');
console.log(`Mac companion ready: ${(bytes.length/1024/1024).toFixed(1)} MiB, Apple silicon. Includes runtime and open-source notices.`);
