import { planDeletionExpiry, RETENTION_MS, storeInfo } from './recovery-policy.mjs';

// Start removal a day before the absolute deadline. A slow backup is never a
// prerequisite for removing an already eligible contaminated repository.
export const RETENTION_MARGIN_MS=24*60*60*1000;
export function retentionWindow(purges,now=Date.now()){
  if(!Number.isFinite(now))throw new Error('Invalid retention time');
  for(const p of purges){const boundary=Date.parse(p.livePayloadsPurgedAt),deadline=Date.parse(p.backupExpiresAt);
    if(!Number.isFinite(boundary)||!Number.isFinite(deadline)||deadline<boundary||deadline>boundary+RETENTION_MS)throw new Error('Invalid retention deadline');}
  return {asOf:now+RETENTION_MARGIN_MS,eligible:purges.some(p=>Date.parse(p.backupExpiresAt)<=now+RETENTION_MARGIN_MS)};
}

/** Exact-stanza deletion is the availability tradeoff when no clean full already
 * exists. Never wait for a replacement backup inside this retention phase.
 * Callers sanitize BOTH stores before starting any replacement backup.
 * https://pgbackrest.org/command.html#command-stanza-delete */
export async function enforceBackupExpiry({store,backups,purges,now=Date.now(),run,info}) {
  storeInfo(store);const window=retentionWindow(purges,now);
  if(!window.eligible)return {store,expired:[],retired:false,cleanBackup:true};
  async function retire(){
    await run(store,['--force','stop']);
    await run(store,['--repo=1','--force','stanza-delete']);
    // Once deletion succeeds, failure to recreate cannot retain old payloads.
    // Recreate metadata only. Recovery remains degraded until a later clean full.
    let recreated=false;
    try{await run(store,['start']);await run(store,['stanza-create']);recreated=true;}catch{}
    return {store,expired:backups.map(b=>b.label),retired:true,recreated,cleanBackup:false};
  }
  let labels;
  try{labels=planDeletionExpiry(backups,purges,window.asOf);}catch{return retire();}
  try{
    for(const label of labels){if(!/^\d{8}-\d{6}F(?:_\d{8}-\d{6}[DI])?$/.test(label))throw new Error('Invalid backup label');await run(store,[`--set=${label}`,'expire']);}
    if(planDeletionExpiry((await info(store)).backup,purges,window.asOf).length)throw new Error('Expiry not confirmed');
    return {store,expired:labels,retired:false,cleanBackup:true};
  }catch{return retire();}
}
