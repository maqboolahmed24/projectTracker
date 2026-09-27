import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes,randomUUID,createHash } from 'node:crypto';
import { mkdtemp,readFile,writeFile,readdir,stat,chmod,utimes,symlink,rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { RecoveryRecords,checkpointIndex } from '../ops/recovery-records.mjs';
import { enforceBackupExpiry,RETENTION_MARGIN_MS } from '../ops/recovery-expiry.mjs';
import { RETENTION_MS } from '../ops/recovery-policy.mjs';
import { installRows,verifyRestoreRows,retireOwnedArtifacts,RECOVERY_ARTIFACT_MAX_AGE_MS,chooseFullBackups } from '../scripts/recovery.mjs';

async function fixture(t){const directory=await mkdtemp(join(tmpdir(),'ukda-recovery-records-'));t.after(()=>rm(directory,{recursive:true,force:true}));
 const workspaceId=randomUUID(),checkpointId=randomUUID(),secret=randomBytes(32).toString('hex'),records=new RecoveryRecords(directory,secret),
 index={version:1,workspaceId,checkpointId,capturedAt:new Date().toISOString(),backupLabel:'20260927-120000F',controlBackupLabel:'20260927-120001F',walTarget:`ukda_cp_${checkpointId.replaceAll('-','_')}`};
 return {directory,records,index,secret};}

test('recovery records: private atomic encrypted checkpoint, opaque index and authenticated identity/tamper rejection',async t=>{
 const f=await fixture(t),value={manifest:{ciphertext:'already encrypted customer object'},keyObjects:[{value:'private encrypted key object'}]};await f.records.save(f.index,value);
 const names=await readdir(f.directory);assert.equal(names.length,2);assert.equal((await stat(f.directory)).mode&0o777,0o700);
 for(const name of names)assert.equal((await stat(join(f.directory,name))).mode&0o777,0o600);
 const encoded=await readFile(join(f.directory,names.find(n=>n.endsWith('.sealed'))),'utf8');assert.equal(encoded.includes('private encrypted key object'),false);
 const publicIndex=JSON.parse(await readFile(join(f.directory,names.find(n=>n.endsWith('.json'))),'utf8'));assert.deepEqual(publicIndex,f.index);
 assert.deepEqual((await f.records.read(f.index.workspaceId,f.index.checkpointId)).value,value);await assert.rejects(f.records.save(f.index,value));
 await assert.rejects(new RecoveryRecords(f.directory,randomBytes(32).toString('hex')).read(f.index.workspaceId,f.index.checkpointId));
 const changed=JSON.parse(encoded);changed.tag=Buffer.alloc(16).toString('base64');await writeFile(join(f.directory,names.find(n=>n.endsWith('.sealed'))),JSON.stringify(changed));
 await assert.rejects(f.records.read(f.index.workspaceId,f.index.checkpointId));
 assert.throws(()=>checkpointIndex({...f.index,manifest:value.manifest}));assert.throws(()=>checkpointIndex({...f.index,walTarget:`ukda_cp_${randomUUID().replaceAll('-','_')}`}));
});

test('recovery records: purge and thirty-day expiry remove only matching owned records including temp and unindexed ciphertext',async t=>{
 const f=await fixture(t);await f.records.save(f.index,{value:'encrypted'});const prefix=`${f.index.workspaceId}.${randomUUID()}`,
 orphan=`${prefix}.sealed`,temporary=`${prefix}.sealed.${randomUUID()}.tmp`;
 for(const name of [orphan,temporary])await writeFile(join(f.directory,name),'encrypted orphan',{mode:0o600});
 const unrelated=join(f.directory,'operator-notes.txt');await writeFile(unrelated,'retain');await f.records.removeWorkspace(f.index.workspaceId);
 assert.deepEqual(await readdir(f.directory),['operator-notes.txt']);
 const stale=`${randomUUID()}.${randomUUID()}.sealed`,young=`${randomUUID()}.${randomUUID()}.sealed`;
 await writeFile(join(f.directory,stale),'encrypted',{mode:0o600});await writeFile(join(f.directory,young),'encrypted',{mode:0o600});
 const old=new Date(Date.now()-RETENTION_MS-1000);await utimes(join(f.directory,stale),old,old);assert.equal(await f.records.expire(),1);
 assert.ok((await readdir(f.directory)).includes(young));assert.equal(await readFile(unrelated,'utf8'),'retain');
});

test('recovery records: unsafe file permissions and symlink replacement fail closed without removing the target',async t=>{
 const f=await fixture(t);await f.records.save(f.index,{value:'encrypted'});const base=join(f.directory,`${f.index.workspaceId}.${f.index.checkpointId}`);
 await chmod(`${base}.sealed`,0o644);await assert.rejects(f.records.read(f.index.workspaceId,f.index.checkpointId));
 await rm(`${base}.sealed`);const target=join(f.directory,'private-other');await writeFile(target,'untouched');await symlink(target,`${base}.sealed`);
 await assert.rejects(f.records.read(f.index.workspaceId,f.index.checkpointId));await assert.rejects(f.records.removeWorkspace(f.index.workspaceId));assert.equal(await readFile(target,'utf8'),'untouched');
});

const now=Date.parse('2026-10-31T00:00:00Z'),boundary=Date.parse('2026-10-01T00:00:00Z'),old={label:'20260927-120000F',type:'full',timestamp:{start:boundary/1000-100,stop:boundary/1000-90}},
 clean={label:'20261031-120000F',type:'full',timestamp:{start:now/1000,stop:now/1000+2}},purges=[{livePayloadsPurgedAt:new Date(boundary).toISOString(),backupExpiresAt:new Date(now).toISOString()}];
test('hard expiry: keeps a clean full and explicitly expires the contaminated set at its deadline',async()=>{
 const commands=[];let backups=[old,clean];const result=await enforceBackupExpiry({store:'app',backups,purges,now,
 run:async(store,args)=>{commands.push([store,args]);backups=backups.filter(b=>!args.includes(`--set=${b.label}`));},info:async()=>({backup:backups}),fullBackup:async()=>assert.fail('Clean full already exists')});
 assert.deepEqual(commands,[['app',[`--set=${old.label}`,'expire']]]);assert.equal(result.retired,false);assert.deepEqual(backups,[clean]);
});
test('hard expiry: retires before attempting any replacement; recreation failure remains visibly degraded',async()=>{
 const commands=[];let attemptedBackup=0;const result=await enforceBackupExpiry({store:'control',backups:[old],purges,now,
 run:async(store,args)=>{commands.push([store,args]);if(args.includes('stanza-create'))throw new Error('Injected unavailable repository');},
 info:async()=>({backup:[]}),fullBackup:async()=>{attemptedBackup++;throw new Error('Injected backup failure');}});
 assert.equal(attemptedBackup,0);
 assert.deepEqual(commands,[['control',['--force','stop']],['control',['--repo=1','--force','stanza-delete']],['control',['start']],['control',['stanza-create']]]);
 assert.equal(result.retired,true);assert.equal(result.cleanBackup,false);assert.equal(result.recreated,false);
});
test('hard expiry: before the conservative margin no stanza is retired, and invalid deadlines fail instead of deleting',async()=>{
 let calls=0;const input={store:'app',backups:[old],purges,now:now-RETENTION_MARGIN_MS-1,run:async()=>calls++,info:async()=>({backup:[old]}),fullBackup:async()=>calls++};
 assert.equal((await enforceBackupExpiry(input)).retired,false);assert.equal(calls,0);
 await assert.rejects(enforceBackupExpiry({...input,now:now+1,purges:[{...purges[0],livePayloadsPurgedAt:new Date(boundary-1).toISOString()}]}));assert.equal(calls,0);
});

const canonical=value=>JSON.stringify(value),digest=async value=>createHash('sha256').update(canonical(value)).digest('hex');
test('restore row inventory rejects changed, omitted and cross-workspace content before installation',async()=>{
 const workspaceId=randomUUID(),rows=[{workspace_id:workspaceId,id:randomUUID(),encrypted_envelope:{ciphertext:'original'}}],runtime={RESTORE_TABLES:['projects'],RESTORE_MAX_OBJECTS:20,canonicalRestoreRow:(_table,row)=>row,canonicalJson:canonical,digestObject:digest},
 manifest={body:{workspaceId,inventory:{tables:[{table:'projects',count:1,digest:await digest(rows.map(canonical).sort())}]}}};
 await verifyRestoreRows(runtime,manifest,'projects',rows);await assert.rejects(verifyRestoreRows(runtime,manifest,'projects',[]));
 await assert.rejects(verifyRestoreRows(runtime,manifest,'projects',[{...rows[0],encrypted_envelope:{ciphertext:'changed'}}]));
 await assert.rejects(verifyRestoreRows(runtime,manifest,'projects',[{...rows[0],workspace_id:randomUUID()}]));await assert.rejects(verifyRestoreRows(runtime,manifest,'sessions',rows));
});
test('restore installation preserves live workspace authority, checks constraints before reenabling triggers and rejects missing quarantine',async()=>{
 const workspaceId=randomUUID(),restoreId=randomUUID(),calls=[],current={lifecycle:'active',delete_after:null,restore_quarantine:true,active_restore_id:restoreId},
 rows={workspace_id:workspaceId,encrypted_envelope:{ciphertext:'checkpoint'},revision:'7'},tables=new Map([['workspaces',[rows]]]);
 const client={query:async(sql,args)=>{calls.push({sql,args});if(sql.includes('SELECT fence_closed'))return {rows:[{fence_closed:true,restore_quarantine:true}]};
 if(sql.includes('SELECT attname'))return {rows:Object.keys(rows).sort().map(attname=>({attname}))};return {rows:[],rowCount:1};}},
 runtime={RESTORE_TABLES:['workspaces'],application:{},control:{query:async()=>({rows:[current]})},transaction:async(_pool,action)=>action(client)};
 await installRows(runtime,workspaceId,restoreId,tables);const update=calls.find(c=>c.sql.startsWith('UPDATE app.workspaces'));
 assert.equal(update.sql,'UPDATE app.workspaces SET encrypted_envelope=$2,revision=$3 WHERE workspace_id=$1');assert.deepEqual(update.args,[workspaceId,rows.encrypted_envelope,'7']);
 const immediate=calls.findIndex(c=>c.sql==='SET CONSTRAINTS ALL IMMEDIATE'),enabled=calls.findIndex(c=>c.sql.includes('ENABLE TRIGGER'));assert.ok(immediate>=0&&enabled>immediate);
 assert.ok(calls.filter(c=>c.sql.startsWith('DELETE')).every(c=>c.args[0]===workspaceId));
 calls.length=0;current.restore_quarantine=false;await assert.rejects(installRows(runtime,workspaceId,restoreId,tables));assert.equal(calls.some(c=>c.sql.startsWith('DELETE')),false);
});


test('hard expiry: the conservative margin removes contaminated sets before a future deadline without waiting for a full backup',async()=>{
 const actions=[];
 for(const store of ['app','control']){
  const result=await enforceBackupExpiry({store,backups:[old],purges,now:now-RETENTION_MARGIN_MS,
   run:async(s,args)=>{actions.push([s,...args]);},info:async()=>({backup:[]}),fullBackup:async()=>{actions.push(['backup']);return new Promise(()=>{});}});
  assert.equal(result.retired,true);assert.equal(result.recreated,true);assert.equal(result.cleanBackup,false);
 }
 assert.equal(actions.some(a=>a[0]==='backup'),false);
 assert.deepEqual(actions.filter(a=>a.includes('stanza-delete')).map(a=>a[0]),['app','control']);
});

test('recovery records: unindexed ciphertext and interrupted temporary writes expire within the conservative deadline margin',async t=>{
 const f=await fixture(t),names=[`${randomUUID()}.${randomUUID()}.sealed`,`${randomUUID()}.${randomUUID()}.sealed.${randomUUID()}.tmp`],
 current=Date.now(),born=new Date(current-RETENTION_MS+RETENTION_MARGIN_MS-1000);
 for(const name of names){await writeFile(join(f.directory,name),'encrypted',{mode:0o600});await utimes(join(f.directory,name),born,born);}
 assert.equal(await f.records.expire(current),2);assert.deepEqual(await readdir(f.directory),[]);
});

function artifactFixture(){
 const containers=new Map(),volumes=new Map(),calls=[],time=Date.now(),past=new Date(time-RECOVERY_ARTIFACT_MAX_AGE_MS-1000).toISOString(),recent=new Date(time-1000).toISOString();
 function artifact(created,{container=true,volumeCreated=created,label='true'}={}){const name=`ukda-recovery-app-${randomUUID()}`,volume=`${name}-data`;
  volumes.set(volume,{Name:volume,CreatedAt:volumeCreated,Labels:{'ukda.recovery.drill':label}});
  if(container)containers.set(name,{Name:`/${name}`,Created:created,Config:{Labels:{'ukda.recovery.drill':label}},Mounts:[{Type:'volume',Name:volume,Destination:'/var/lib/postgresql'}]});
  return {name,volume};}
 const run=async args=>{calls.push(args);
  if(args[0]==='ps')return [...containers.keys()].join('\n');
  if(args[0]==='inspect')return JSON.stringify([containers.get(args[1])]);
  if(args[0]==='rm'){containers.delete(args[2]);return '';}
  if(args[0]==='volume'&&args[1]==='ls')return [...volumes.keys()].join('\n');
  if(args[0]==='volume'&&args[1]==='inspect')return JSON.stringify([volumes.get(args[2])]);
  if(args[0]==='volume'&&args[1]==='rm'){volumes.delete(args[2]);return '';}
  throw new Error('Unexpected Docker operation');};
 return {artifact,run,containers,volumes,calls,time,past,recent};
}
test('ordinary recovery maintenance removes aged standalone containers and orphan volumes, preserving young attached copies',async()=>{
 const f=artifactFixture(),oldCopy=f.artifact(f.past),oldOrphan=f.artifact(f.past,{container:false}),young=f.artifact(f.recent),
 youngOnOldVolume=f.artifact(f.recent,{volumeCreated:f.past}),youngOrphan=f.artifact(f.recent,{container:false});
 assert.equal(await retireOwnedArtifacts({before:f.time-RECOVERY_ARTIFACT_MAX_AGE_MS,run:f.run}),2);
 assert.equal(f.containers.has(oldCopy.name),false);assert.equal(f.volumes.has(oldCopy.volume),false);assert.equal(f.volumes.has(oldOrphan.volume),false);
 for(const item of [young,youngOnOldVolume,youngOrphan])assert.equal(f.volumes.has(item.volume),true);
 assert.equal(f.containers.has(young.name),true);assert.equal(f.containers.has(youngOnOldVolume.name),true);
});
test('artifact expiry rejects forged ownership and invalid timestamps before destructive commands',async()=>{
 for(const invalid of ['label','timestamp']){
  const f=artifactFixture();f.artifact(invalid==='timestamp'?'invalid':f.past,{label:invalid==='label'?'false':'true'});
  await assert.rejects(retireOwnedArtifacts({before:f.time,run:f.run}));assert.equal(f.calls.some(a=>a[0]==='rm'||a[0]==='volume'&&a[1]==='rm'),false);
 }
});


test('five-minute signed checkpoint capture reuses fresh daily full bases and refreshes missing, future or day-old bases',()=>{
 const moment=Date.parse('2026-10-31T12:00:00Z'),full={type:'full',label:'20261031-000000F',timestamp:{start:(moment-60000)/1000,stop:(moment-30000)/1000},archive:{start:'wal-a',stop:'wal-b'}},
 inventories={app:{backup:[full]},control:{backup:[{...full,label:'20261031-000001F'}]}};
 const first=chooseFullBackups(inventories,moment);assert.ok(first);assert.equal(first.app.label,full.label);
 assert.deepEqual(chooseFullBackups(inventories,moment+5*60*1000),first);
 assert.equal(chooseFullBackups(inventories,moment+24*60*60*1000),null);
 assert.equal(chooseFullBackups({...inventories,control:{backup:[]}},moment),null);
 assert.equal(chooseFullBackups(inventories,moment-60000),null);
});
