import { z } from 'zod';
import { binary, contentEnvelope, counter, digest, identifier, positiveCounter } from './contracts.js';
import { digestObject } from './crypto.js';
import { planningContext, type PlanningContext } from './planning-api.js';
import { teamHistoryPage } from './teams.js';
import { collaborationHistory, type CollaborationHistory } from './collaboration.js';
import { reportingSettings } from './reporting.js';
import {fileManifest} from './files.js';

export const EXPORT_MAX_REFERENCES = 20_000, EXPORT_MAX_PAGES = 4_096;
export const EXPORT_PAGE_BYTES = 16 * 1024 * 1024, EXPORT_TOTAL_BYTES = 64 * 1024 * 1024;
export const EXPORT_NOTICE = 'This file contains readable workspace data and file version metadata. Download managed file contents separately. Shared-drive references include metadata only. Store exports privately; they are not a recovery kit or a backup you can restore.';
export const exportReference = z.strictObject({ workspaceId: identifier, exportId: identifier });
export const exportStartRequest = exportReference.extend({ acknowledgePlaintext: z.literal(true) });
export const exportManifestRecord = z.strictObject({ kind: z.enum(['workspace','profile','team','project','phase','milestone','task','blocker','comment','update','planning_change','team_change','collaboration_change','settings_change','settings','file_version']),
  id: identifier, projectId: identifier.nullable(), revision: counter, digest });
export type ExportManifestRecord = z.infer<typeof exportManifestRecord>;
export const exportManifestKey = (r: {kind:string;id:string}) => `${r.kind}:${r.id}`;
export const exportSourceReference = z.strictObject({ kind: z.enum(['workspace','team','project','comment','update','file_versions']), id: identifier, projectId: identifier.nullable() });
export type ExportSourceReference = z.infer<typeof exportSourceReference>;
export const exportBinding = exportReference.extend({ version: z.literal(1), origin: z.string().url(), accountId: identifier, deviceId: identifier,
  credentialGeneration: positiveCounter, sessionGeneration: positiveCounter, keyGeneration: positiveCounter, signingPublicKey: binary(32),
  securityHead: digest, securityVersion: positiveCounter, dataGeneration: positiveCounter,
  manifestDigest: digest, sourceCount: z.number().int().min(1).max(EXPORT_MAX_PAGES), issuedAt: z.iso.datetime(), expiresAt: z.iso.datetime(), acknowledgePlaintext: z.literal(true) });
export type ExportBinding = z.infer<typeof exportBinding>;
export const exportStart = z.strictObject({ binding: exportBinding, manifest: z.array(exportManifestRecord).min(1).max(EXPORT_MAX_REFERENCES),
  sources: z.array(exportSourceReference).min(1).max(EXPORT_MAX_PAGES) });
export type ExportStart = z.infer<typeof exportStart>;
export const exportSource = z.discriminatedUnion('kind', [
  z.strictObject({ kind: z.literal('workspace'), workspace: contentEnvelope, profiles: z.array(z.strictObject({ id: identifier, revision: positiveCounter,
    state: z.enum(['active','suspended','removed']), envelope: contentEnvelope.nullable() })).max(EXPORT_MAX_REFERENCES), settings: reportingSettings }),
  z.strictObject({ kind: z.literal('project'), context: planningContext }),
  z.strictObject({ kind: z.literal('team'), pages: z.array(teamHistoryPage).min(1).max(512) }),
  z.strictObject({ kind: z.literal('entry'), history: collaborationHistory }),
  z.strictObject({ kind:z.literal('file_versions'),manifests:z.array(fileManifest).min(1).max(100) }),
]);
export type ExportSource = Exclude<z.infer<typeof exportSource>,{kind:'project'|'entry'}> | {kind:'project';context:PlanningContext} | {kind:'entry';history:CollaborationHistory};
export const exportPageRequest = exportReference.extend({ manifestDigest: digest, after: z.string().min(1).max(80).nullable() });
export const exportPage = z.strictObject({ binding: exportBinding, source: exportSourceReference, data: exportSource, nextCursor: z.string().min(1).max(80).nullable() });
export type ExportPage = Omit<z.infer<typeof exportPage>,'data'> & {data:ExportSource};
export const exportFinalize = z.strictObject({ body: z.strictObject({ purpose: z.literal('ukda.plaintext-export.v1'), binding: exportBinding,
  documentDigest: digest, byteLength: z.number().int().min(1).max(EXPORT_TOTAL_BYTES), complete: z.literal(true) }), signature: binary(64) });
export type ExportFinalize = z.infer<typeof exportFinalize>;
export const exportReceipt = z.strictObject({ version: z.literal(1), workspaceId: identifier, exportId: identifier, accountId: identifier,
  dataGeneration: positiveCounter, manifestDigest: digest, documentDigest: digest, finalizedAt: z.iso.datetime(), complete: z.literal(true) });
export type ExportReceipt = z.infer<typeof exportReceipt>;
export const sortedExportManifest = (records: ExportManifestRecord[]) => records.sort((a,b) => exportManifestKey(a) < exportManifestKey(b) ? -1 : exportManifestKey(a) > exportManifestKey(b) ? 1 : 0);
export function exportSources(manifest: ExportManifestRecord[]): ExportSourceReference[] {
  const sources=manifest.filter(r => ['workspace','project','team','comment','update'].includes(r.kind)).map(r => exportSourceReference.parse({kind:r.kind,id:r.id,projectId:r.projectId}));
  const projects=[...new Set(manifest.filter(r=>r.kind==='file_version').map(r=>r.projectId!))].sort();
  for(const projectId of projects){const versions=manifest.filter(r=>r.kind==='file_version'&&r.projectId===projectId);for(let i=0;i<versions.length;i+=100)sources.push({kind:'file_versions',id:versions[i]!.id,projectId});}
  return sources;
}
export async function exportRecord(kind:ExportManifestRecord['kind'],id:string,projectId:string|null,revision:string,value:unknown):Promise<ExportManifestRecord> {
  return exportManifestRecord.parse({kind,id,projectId,revision,digest:await digestObject(value)});
}
/** Reconstruct only business reference metadata; callers must also authenticate each native lineage. */
export async function exportSourceManifest(source:ExportSource):Promise<ExportManifestRecord[]> {
  const refs:ExportManifestRecord[]=[];
  if(source.kind==='workspace') {
    const w=source.settings.workspaceId;
    refs.push(await exportRecord('workspace',w,null,source.workspace.header.revision,source.workspace));
    for(const p of source.profiles) refs.push(await exportRecord('profile',p.id,null,p.revision,p.state==='removed'?{id:p.id,state:'removed'}:p.envelope));
    refs.push({kind:'settings',id:w,projectId:null,revision:source.settings.revision,digest:source.settings.head});
    for(const p of source.settings.history)refs.push(await exportRecord('settings_change',p.mutation.body.binding.operationId,null,String(BigInt(p.mutation.body.binding.expectedRevision)+1n),p));
  } else if(source.kind==='project') {
    const c=source.context,p=c.binding.projectId;
    for(const r of c.records) {const row=r.kind==='project'?c.graph.project:r.kind==='phase'?c.graph.phases.find(x=>x.id===r.id):r.kind==='milestone'?c.graph.milestones.find(x=>x.id===r.id):r.kind==='task'?c.graph.tasks.find(x=>x.id===r.id):c.graph.blockers?.find(x=>x.id===r.id);
      if(!row)throw new Error('Incomplete export project');refs.push(await exportRecord(r.kind,r.id,p,row.revision,r.envelope));}
    for(const m of c.history)refs.push(await exportRecord('planning_change',m.body.binding.operationId,p,m.body.nextVersion,m));
  } else if(source.kind==='file_versions') {
    for(const manifest of source.manifests){const b=manifest.body;refs.push(await exportRecord('file_version',b.versionId,b.binding.projectId,b.version,manifest));}
  } else if(source.kind==='team') {
    const changes=source.pages.flatMap(p=>p.records),last=changes.at(-1)!.payload,b=last.mutation.body.binding;
    refs.push(await exportRecord('team',b.teamId,null,last.envelope.header.revision,last.envelope));
    for(const r of changes) refs.push(await exportRecord('team_change',r.payload.mutation.body.binding.operationId,null,r.payload.envelope.header.revision,r.payload));
  } else {
    const {planning,entry}=source.history,p=planning.binding.projectId;
    const operations=[...(entry.origin.kind==='post'?[entry.origin.payload]:[]),...(entry.moderation?[entry.moderation]:[]),...(entry.events??[])];
    const original=entry.origin.kind==='post'?entry.origin.payload.content:planning.outcomes.find(r=>r.id===(entry.origin as {entryId:string}).entryId)?.envelope;
    if(!original)throw new Error('Missing export original');
    let current=original,revision='1';
    for(const payload of operations) {const b=payload.mutation.body.binding,c=payload.mutation.body.command;
      revision='expectedRevision'in c?String(BigInt(c.expectedRevision)+1n):'1';
      if(c.action==='upgrade_content')current=payload.content!;
      refs.push(await exportRecord('collaboration_change',b.operationId,p,revision,payload));}
    const kind=original.header.recordType;if(kind!=='comment'&&kind!=='update')throw new Error('Invalid export entry');
    refs.push(await exportRecord(kind,original.header.recordId,p,revision,current));
  }
  return sortedExportManifest(refs);
}
