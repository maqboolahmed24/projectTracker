import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { homedir } from 'node:os';
import { resolve,join } from 'node:path';
import { mkdir,readFile,writeFile,chmod,access,rename } from 'node:fs/promises';
import { randomBytes,randomUUID } from 'node:crypto';
import { createConnection } from 'node:net';
import { z } from 'zod';
import { LocalFilesService } from '../src/local-files/service.js';
import { LocalOffice } from '../src/local-files/office.js';
import { startLocalHttp } from '../src/local-files/http.js';
const exec=promisify(execFile),args=process.argv.slice(2),command=args[0]??'start';
const option=(name:string)=>{const i=args.indexOf(name);return i<0?undefined:args[i+1];};
const state=resolve(option('--state')??join(homedir(),'Library','Application Support','Maqbool','Shared Folder'));
const configSchema=z.strictObject({version:z.literal(1),root:z.string(),origin:z.string().url(),trustedServiceKeys:z.record(z.string(),z.string()),office:z.boolean(),jwtSecret:z.string().min(32)});
const exists=(path:string)=>access(path).then(()=>true,()=>false);
const officeImage='onlyoffice/documentserver:9.4.0@sha256:e3da62a847b9a5d51a11f73cfea1d9c13c3be3809614490d4edddcf01dcf919b';
async function main(){
 if(command==='help'||args.includes('--help')){process.stdout.write('Maqbool Mac companion\nSetup.command configures your workspace and selected folder.\nStart.command opens your connection code. Keep it running while publishing or editing.\n');return;}
 if(process.platform!=='darwin')throw new Error('This companion supports macOS.');
 await exec('/usr/bin/python3',['-I','-c','import os; assert os.open in os.supports_dir_fd']).catch(()=>{throw new Error('Install Apple Command Line Tools first, then reopen Setup.command. See the setup guide.');});
 await mkdir(state,{recursive:true,mode:0o700});await chmod(state,0o700);
 if(command==='setup'){
  const file=join(state,'config.json'),existing=await exists(file)?configSchema.parse(JSON.parse(await readFile(file,'utf8'))):undefined;
  let origin=option('--origin')??existing?.origin;
  if(!origin&&args.includes('--interactive'))origin=(await exec('/usr/bin/osascript',['-e','text returned of (display dialog "Enter your Maqbool website address" default answer "https://maqbool.denmarkeast.cloudapp.azure.com" with title "Maqbool")'])).stdout.trim();
  if(!origin||new URL(origin).origin!==origin||new URL(origin).protocol!=='https:')throw new Error('Enter the full HTTPS address of your Maqbool website, without a path.');
  let root=option('--root')??existing?.root;if(!root){const selected=await exec('/usr/bin/osascript',['-e','POSIX path of (choose folder with prompt "Choose the shared folder Maqbool may publish into")']);root=selected.stdout.trim();}
  root=resolve(root);
  if(existing&&(existing.origin!==origin||resolve(existing.root)!==root))throw new Error('This companion already belongs to another website or folder. Keep its existing settings, or choose a separate settings location with --state.');
  let office=existing?.office||args.includes('--office');
  if(!existing?.office&&args.includes('--interactive'))office=(await exec('/usr/bin/osascript',['-e','button returned of (display dialog "Enable editing inside Maqbool? This optional feature needs Docker Desktop running and at least 4 GB of available memory. You can still upload, review and publish files without it." buttons {"Shared folder only", "Enable editing"} default button "Shared folder only" with title "Maqbool")'])).stdout.trim()==='Enable editing';
  if(office)await exec('docker',['info','--format','{{.ServerVersion}}'],{timeout:15000}).catch(()=>{throw new Error('Open Docker Desktop and wait for it to start, then reopen Setup.command. Or choose Shared folder only.');});
  const response=await fetch(origin+'/v1/application',{redirect:'error',signal:AbortSignal.timeout(15000)});if(!response.ok)throw new Error('Maqbool could not be reached. Check the website address and your connection.');
  const identity=z.object({version:z.literal(1),trustedServiceKeys:z.record(z.string(),z.string().regex(/^[A-Za-z0-9_-]{43}$/))}).parse(await response.json());
  // Resume a partial setup without changing the established trust or identity.
  const config=configSchema.parse(existing?{...existing,office}:{version:1,root,origin,trustedServiceKeys:identity.trustedServiceKeys,office,jwtSecret:randomBytes(48).toString('base64url')});
  if(!existing)await writeFile(file,JSON.stringify(config,null,2),{flag:'wx',mode:0o600});
  const key=join(state,'localhost.key'),cert=join(state,'localhost.crt');
  if(!await exists(key)||!await exists(cert)){
   await writeFile(join(state,'openssl.cnf'),'[req]\ndistinguished_name=dn\nx509_extensions=ext\nprompt=no\n[dn]\nCN=Maqbool local companion\n[ext]\nsubjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n',{mode:0o600});
   await exec('/usr/bin/openssl',['req','-x509','-newkey','rsa:3072','-nodes','-keyout',key,'-out',cert,'-days','365','-config',join(state,'openssl.cnf')]);await chmod(key,0o600);
  }
  await exec('/usr/bin/security',['add-trusted-cert','-r','trustAsRoot','-k',join(homedir(),'Library','Keychains','login.keychain-db'),cert]);
  if(config.office){
   const env=join(state,'office.env');await writeFile(env,`JWT_ENABLED=true\nJWT_SECRET=${config.jwtSecret}\nALLOW_PRIVATE_IP_ADDRESS=true\nALLOW_META_IP_ADDRESS=false\n`,{mode:0o600});
   const found=await exec('docker',['inspect','maqbool-office'],{maxBuffer:1024*1024}).then(r=>JSON.parse(r.stdout)[0],()=>null);
   if(found){
    if(found.Config?.Labels?.['maqbool.state']!==state||found.Config?.Image!==officeImage||!found.Config?.Env?.includes('JWT_SECRET='+config.jwtSecret))throw new Error('An existing editor installation uses different settings. Ask the person who installed it to check before continuing.');
    await exec('docker',['start','maqbool-office']);
   }else await exec('docker',['run','-d','--platform','linux/amd64','--name','maqbool-office','--label','maqbool.state='+state,'--memory=4g','--restart','unless-stopped','-p','127.0.0.1:3420:80','--env-file',env,officeImage],{timeout:600000,maxBuffer:1024*1024});
  }
  if(existing&&config.office!==existing.office)await writeFile(file,JSON.stringify(config,null,2),{mode:0o600});
  process.stdout.write('Setup complete. Open Start.command, then connect your shared folder in Maqbool.\n');
 }else if(command==='new-connection'){
  const running=await new Promise<boolean>(done=>{const socket=createConnection({host:'127.0.0.1',port:3411});let settled=false;const finish=(value:boolean)=>{if(settled)return;settled=true;socket.destroy();done(value);};socket.setTimeout(2000,()=>finish(true));socket.once('connect',()=>finish(true));socket.once('error',error=>finish((error as NodeJS.ErrnoException).code!=='ECONNREFUSED'));});
  if(running)throw new Error('Close the running Start.command window before creating a new connection.');
  const answer=(await exec('/usr/bin/osascript',['-e','button returned of (display dialog "Create a new shared-folder connection? Use this after an Owner removes access or the workspace is restored. Your folder and publication records will be kept. An Owner must approve the new connection in Maqbool." buttons {"Cancel", "Create new connection"} default button "Cancel" with title "Maqbool")'])).stdout.trim();
  if(answer!=='Create new connection')return;
  const retired=randomUUID();for(const name of ['identity','connections']){const file=join(state,name+'.json');if(await exists(file))await rename(file,join(state,name+'.retired-'+retired+'.json'));}
  process.stdout.write('New connection prepared. Open Start.command, then ask an Owner to connect its new code in Maqbool. Your chosen folder and previous publication records are kept.\n');
 }else if(command==='start'){
  if(!await exists(join(state,'config.json')))throw new Error('Open Setup.command first to choose your website and shared folder.');
  const config=configSchema.parse(JSON.parse(await readFile(join(state,'config.json'),'utf8'))),service=await LocalFilesService.open({...config,stateDirectory:state});
  const office=config.office?new LocalOffice({documentServer:'http://127.0.0.1:3420',callbackOrigin:'http://host.docker.internal:3412',publicOrigin:'https://localhost:3411',jwtSecret:config.jwtSecret,verifyPermit:p=>service.verifyEditorPermit(p)}):undefined;
  const listener=await startLocalHttp({service,origin:config.origin,publicOrigin:'https://localhost:3411',tls:{key:await readFile(join(state,'localhost.key')),cert:await readFile(join(state,'localhost.crt'))},...(office?{office,documentServer:'http://127.0.0.1:3420'}:{})});
  await exec('/usr/bin/open',['https://localhost:3411']).catch(()=>{});process.stdout.write('Maqbool shared folder is ready. Keep this window open while publishing or editing.\nClose this window to stop the companion.\n');
  const stop=()=>void listener.close().finally(()=>process.exit(0));process.once('SIGINT',stop);process.once('SIGTERM',stop);
 }else throw new Error('Use setup, start, new-connection or help.');
}
main().catch(error=>{const message=error instanceof z.ZodError?'The saved settings are incomplete. Reopen Setup.command.':error instanceof Error&&!(error as NodeJS.ErrnoException).code?error.message:'Setup could not finish. Check the setup guide, then try again.';process.stderr.write(message+'\n');process.exitCode=1;});
