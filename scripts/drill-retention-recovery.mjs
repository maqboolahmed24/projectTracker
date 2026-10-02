import assert from 'node:assert/strict';
import { randomBytes,randomUUID } from 'node:crypto';
import { mkdir,writeFile } from 'node:fs/promises';
import { fileURLToPath,pathToFileURL } from 'node:url';
import { execute } from './physical-backups.mjs';
import { backupConfiguration,RETENTION_MS } from '../ops/recovery-policy.mjs';
import { enforceBackupExpiry } from '../ops/recovery-expiry.mjs';

const IMAGE='ukda-postgres-recovery:18-2.59.1',LABEL='ukda.retention.drill',DATA='/var/lib/postgresql/18/docker';
const sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms));
/** Actual pgBackRest commands run only against newly allocated, labelled resources.
 * Advancing the policy clock tests the deadline without claiming thirty elapsed days.
 * There are no live Compose service names, host mounts or primary connection strings. */
export async function drillRetentionRecovery(){
 const drillId=randomUUID(),name=`ukda-retention-${drillId}`,dataVolume=`${name}-data`,repoVolume=`${name}-repo`,started=Date.now();
 const evidence={version:1,drillId,startedAt:new Date(started).toISOString(),image:IMAGE,container:name,volumes:[dataVolume,repoVolume],
  scope:'New isolated fixture PostgreSQL and encrypted repository only; policy clock is accelerated, storage commands are real',steps:[],passed:false,cleaned:false};
 let stage='allocate',containerCreated=false;const createdVolumes=[];
 const docker=(args,options)=>execute(args,{timeoutMs:180000,...options});
 const exec=(args,options)=>docker(['exec','-i',name,...args],options);
 const postgres=(args,options)=>docker(['exec','-i','--user','postgres',name,...args],options);
 const sql=(statement,port=5432)=>postgres(['psql','-X','-U','ukda_app_admin','-p',String(port),'-d','ukda_app','-At','-v','ON_ERROR_STOP=1'],{input:statement});
 const backrest=args=>postgres(['pgbackrest','--stanza=app',...args]);
 const info=async()=>{const parsed=JSON.parse(await backrest(['--output=json','info']));return parsed.find(s=>s.name==='app');};
 async function full(){await backrest(['--type=full','backup']);const latest=(await info()).backup.at(-1);assert.equal(latest?.type,'full');return latest;}
 async function sentinel(){assert.equal(await sql("SELECT value FROM retention_probe WHERE id=2;"),'live-fixture-survives');assert.equal(await sql('SELECT count(*) FROM retention_probe WHERE id=1;'),'0');}
 async function clean(){
  if(containerCreated){const row=JSON.parse(await docker(['inspect',name]))[0];
   assert.equal(row.Name,`/${name}`);assert.equal(row.Config.Labels[LABEL],drillId);assert.equal(row.HostConfig.NetworkMode,'none');
   for(const [volume,destination]of [[dataVolume,'/var/lib/postgresql'],[repoVolume,'/backrest']])assert.ok(row.Mounts.some(m=>m.Type==='volume'&&m.Name===volume&&m.Destination===destination));
   await docker(['rm','--force',name]);}
  for(const volume of createdVolumes){const row=JSON.parse(await docker(['volume','inspect',volume]))[0];assert.equal(row.Name,volume);assert.equal(row.Labels[LABEL],drillId);await docker(['volume','rm',volume]);}
  evidence.cleaned=true;
 }
 try{
  evidence.imageId=JSON.parse(await docker(['image','inspect',IMAGE]))[0].Id;
  for(const volume of [dataVolume,repoVolume]){await docker(['volume','create','--label',`${LABEL}=${drillId}`,volume]);createdVolumes.push(volume);}
  await docker(['run','-d','--name',name,'--label',`${LABEL}=${drillId}`,'--network','none','-v',`${dataVolume}:/var/lib/postgresql`,'-v',`${repoVolume}:/backrest`,'--entrypoint','sh',IMAGE,'-c','sleep infinity']);containerCreated=true;
  await exec(['sh','-c',`install -d -o postgres -g postgres -m 700 ${DATA} /etc/pgbackrest /backrest /var/run/postgresql`]);
  const config=backupConfiguration('app',randomBytes(32).toString('hex'));
  await exec(['sh','-c','umask 077; cat > /etc/pgbackrest/pgbackrest.conf; chown postgres:postgres /etc/pgbackrest/pgbackrest.conf'],{input:config});
  evidence.pgBackRestVersion=await postgres(['pgbackrest','version']);assert.equal(evidence.pgBackRestVersion,'pgBackRest 2.59.1');
  stage='initialize isolated database';
  await postgres(['initdb','-D',DATA,'-U','ukda_app_admin','-A','trust']);
  await postgres(['sh','-c',`cat > ${DATA}/postgresql.auto.conf`],{input:"listen_addresses=''\nwal_level=replica\narchive_mode=on\narchive_command='pgbackrest --stanza=app archive-push %p'\narchive_timeout=60s\n"});
  await postgres(['pg_ctl','-D',DATA,'-l','/var/lib/postgresql/fixture.log','-w','start']);
  await postgres(['createdb','-U','ukda_app_admin','ukda_app']);
  await backrest(['stanza-create']);await backrest(['check']);
  const payload=`retention-payload-${randomUUID()}`;
  await sql(`CREATE TABLE retention_probe(id integer PRIMARY KEY,value text NOT NULL); INSERT INTO retention_probe VALUES(1,'${payload}'),(2,'live-fixture-survives');`);
  stage='encrypted contaminated full backup';
  const old=await full();assert.equal((await info()).cipher,'aes-256-cbc');
  await assert.rejects(postgres(['pgbackrest','--stanza=app',`--repo1-cipher-pass=${'00'.repeat(32)}`,'check']));
  assert.equal(await exec(['sh','-c',`if grep -R -a -l '${payload}' /backrest >/dev/null; then printf exposed; else printf absent; fi`]),'absent');
  evidence.steps.push({stage,backup:old.label,encrypted:true,wrongKeyRejected:true,plaintextAbsent:true});
  stage='physical deletion and clean full backup';
  await sql('DELETE FROM retention_probe WHERE id=1; VACUUM (FULL, ANALYZE) retention_probe; CHECKPOINT; SELECT pg_switch_wal();');
  await backrest(['check']);const purgeBoundary=Date.now();await sleep(Math.max(0,Math.ceil(purgeBoundary/1000)*1000+100-Date.now()));
  const cleanBackup=await full();assert.ok(cleanBackup.timestamp.start*1000>=purgeBoundary);await sentinel();
  evidence.steps.push({stage,backup:cleanBackup.label,purgeBoundary:new Date(purgeBoundary).toISOString()});
  stage='expire contaminated set retaining clean full';
  const purges=[{livePayloadsPurgedAt:new Date(purgeBoundary).toISOString(),backupExpiresAt:new Date(purgeBoundary+RETENTION_MS).toISOString()}],commands=[];
  const retained=await enforceBackupExpiry({store:'app',backups:(await info()).backup,purges,now:purgeBoundary+RETENTION_MS,
   run:async(store,args)=>{assert.equal(store,'app');commands.push(args);return backrest(args);},info});
  assert.equal(retained.retired,false);assert.deepEqual((await info()).backup.map(b=>b.label),[cleanBackup.label]);
  assert.equal(await exec(['sh','-c',`test ! -e /backrest/backup/app/${old.label} && printf removed`]),'removed');await sentinel();
  evidence.steps.push({stage,result:retained,commands,expiredDirectoryRemoved:true,fixtureDatabaseUnchanged:true});
  stage='recover retained clean backup';
  const restored='/var/lib/postgresql/18/verified';
  await exec(['install','-d','-o','postgres','-g','postgres','-m','700',restored]);
  await postgres(['pgbackrest','--stanza=app',`--pg1-path=${restored}`,`--set=${cleanBackup.label}`,'--type=immediate','--target-action=promote','restore']);
  stage='start recovered clean fixture';
  await postgres(['pg_ctl','-D',restored,'-l','/var/lib/postgresql/verified.log','-o','-c port=5544 -c listen_addresses= -c archive_mode=off','-w','start']);
  assert.equal(await sql('SELECT count(*) FROM retention_probe WHERE id=1;',5544),'0');assert.equal(await sql('SELECT value FROM retention_probe WHERE id=2;',5544),'live-fixture-survives');
  await postgres(['pg_ctl','-D',restored,'-m','fast','-w','stop']);
  evidence.steps.push({stage,deletedPayloadAbsent:true,retainedSentinelRecovered:true});
  stage='hard expiry without clean set';
  const nextBoundary=Date.now()+1000,nextPurges=[{livePayloadsPurgedAt:new Date(nextBoundary).toISOString(),backupExpiresAt:new Date(nextBoundary+RETENTION_MS).toISOString()}],retirementCommands=[];
  let removedBeforeRecreation=false;
  const retired=await enforceBackupExpiry({store:'app',backups:(await info()).backup,purges:nextPurges,now:nextBoundary+RETENTION_MS,
   run:async(store,args)=>{assert.equal(store,'app');retirementCommands.push(args);const result=await backrest(args);
    if(args.includes('stanza-delete')){assert.ok(args.includes('--repo=1')&&args.includes('--force'));
     assert.equal(await exec(['sh','-c','test ! -e /backrest/backup/app && test ! -e /backrest/archive/app && printf removed']),'removed');
     await sentinel();removedBeforeRecreation=true;}return result;},info});
  assert.equal(retired.retired,true);assert.equal(retired.recreated,true);assert.equal(retired.cleanBackup,false);assert.equal(removedBeforeRecreation,true);
  assert.equal((await info()).backup.length,0);await sentinel();
  evidence.steps.push({stage,result:retired,commands:retirementCommands,backupAndArchiveRemovedBeforeRecreation:true,fixtureDatabaseUnchanged:true});
  stage='replacement full after retirement';
  await sleep(Math.max(0,nextBoundary-Date.now()+100));const replacement=await full();await sentinel();
  assert.equal((await info()).backup.length,1);assert.notEqual(replacement.label,cleanBackup.label);
  evidence.steps.push({stage,backup:replacement.label,encryptedRepositoryRecreated:true,fixtureDatabaseUnchanged:true});evidence.passed=true;
 }catch(error){evidence.failure={stage,error:error instanceof assert.AssertionError?'Assertion failed':error.message};}
 finally{try{await clean();}catch{evidence.cleanupFailure=true;evidence.passed=false;}evidence.completedAt=new Date().toISOString();evidence.elapsedMs=Date.now()-started;
  const path=fileURLToPath(new URL(`../test-results/checkpoint-12-retention-drill-${drillId}.json`,import.meta.url));await mkdir(fileURLToPath(new URL('../test-results/',import.meta.url)),{recursive:true});
  await writeFile(path,JSON.stringify(evidence,null,2)+'\n',{flag:'wx',mode:0o600});evidence.path=path;}
 return evidence;
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
 const result=await drillRetentionRecovery();process.stdout.write(JSON.stringify(result,null,2)+'\n');if(!result.passed)process.exitCode=1;
}
