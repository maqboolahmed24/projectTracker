import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { PLANNING_HISTORY_MAX_BYTES,type PlanningContext } from '../shared/planning-api.js';
/** Intern only exact byte-equivalent, schema-parsed signed ciphertext histories. */
export class PlanningHistoryPool {
 private readonly entries=new Map<string,{fingerprint:string;context:PlanningContext}>();private totalBytes=0;
 retain(context:PlanningContext):void {
  const b=context.binding,key=[b.workspaceId,b.projectId,b.dataGeneration,b.beforeVersion,b.beforeHead].join(':'),hash=sha256.create(),encode=new TextEncoder();let bytes=0;
  for(const [kind,values]of [['history',context.history],['audits',context.audits],['outcomes',context.outcomes],['upgrades',context.upgrades??[]]] as const){hash.update(encode.encode(kind));bytes+=kind.length+4;
   for(const item of values){const raw=encode.encode(JSON.stringify(item));bytes+=raw.length+1;hash.update(raw);hash.update(new Uint8Array([0]));}
  }
  const fingerprint=bytesToHex(hash.digest()),prior=this.entries.get(key);
  if(prior){if(prior.fingerprint!==fingerprint)throw new Error('Changed retained planning history');context.history=prior.context.history;context.audits=prior.context.audits;context.outcomes=prior.context.outcomes;
   if(prior.context.upgrades)context.upgrades=prior.context.upgrades;else delete context.upgrades;return;}
  this.totalBytes+=bytes;if(this.totalBytes>PLANNING_HISTORY_MAX_BYTES)throw new Error('Retained planning histories exceed bounds');this.entries.set(key,{fingerprint,context});
 }
}
