import {Zip,ZipPassThrough} from 'fflate';
import {FILE_MAX_BATCH_BYTES,FILE_MAX_BATCH_ITEMS} from '../shared/files.js';
import {canonicalJson,digestObject} from '../shared/crypto.js';
import {FileClientError} from './files-crypto.js';
import type {FilesController,ReadableFileVersion} from './files-controller.js';

export const FILE_ARCHIVE_NOTICE='This download contains readable private files and a version manifest. Store it privately. Shared-drive files are references only; their contents are not included. Downloading this archive does not publish files to your official shared drive.';
export interface FileArchive {filename:string;mimeType:'application/zip';blob:Blob;manifest:{version:1;purpose:'private-file-export';notice:string;projectId:string;exportedAt:string;items:Record<string,unknown>[]}}
type ArchiveFiles=Pick<FilesController,'context'|'version'|'bytes'>;
function fence(context:Awaited<ReturnType<ArchiveFiles['context']>>){const b=context.binding;return canonicalJson({workspaceId:b.workspaceId,projectId:b.projectId,accountId:b.accountId,deviceId:b.deviceId,
 credentialGeneration:b.credentialGeneration,sessionGeneration:b.sessionGeneration,keyGeneration:b.keyGeneration,securityVersion:b.securityVersion,securityHead:b.securityHead,dataGeneration:b.dataGeneration,permissionVersion:b.permissionVersion,keyEpoch:b.keyEpoch});}
/** Explicit, bounded data exit through existing current-authority downloads.
 * No private archive or retry state is persisted, and external paths are never fetched. */
export async function createFileArchive(files:ArchiveFiles,projectId:string,versionIds:string[],options:{signal?:AbortSignal;onProgress?:(completed:number,total:number)=>void}={}):Promise<FileArchive>{
 if(!versionIds.length||versionIds.length>FILE_MAX_BATCH_ITEMS||new Set(versionIds).size!==versionIds.length)throw new FileClientError('TOO_LARGE');
 const cancelled=()=>{if(options.signal?.aborted)throw new FileClientError('CANCELLED');};cancelled();
 const anchor=await files.context(projectId);cancelled();const binding=anchor.planning.binding;if(!binding.isOwner&&!(binding.permissions as readonly string[]).includes('download_files'))throw new FileClientError('INVALID_FILE');
 const versions:ReadableFileVersion[]=[];let total=0;
 for(const versionId of versionIds){cancelled();const version=await files.version(projectId,versionId);if(version.state!=='ready'||version.manifest.body.versionId!==versionId||version.manifest.body.binding.projectId!==projectId)throw new FileClientError('INVALID_FILE');
  if(version.manifest.body.storage==='managed')total+=version.manifest.body.plainBytes;if(total>FILE_MAX_BATCH_BYTES)throw new FileClientError('TOO_LARGE');versions.push(version);}
 const manifest:FileArchive['manifest']={version:1,purpose:'private-file-export',notice:FILE_ARCHIVE_NOTICE,projectId,exportedAt:new Date().toISOString(),items:[]};
 const chunks:BlobPart[]=[];let packedBytes=0,zipError:Error|undefined;const zip=new Zip((error,data)=>{if(error){zipError=error;return;}packedBytes+=data.length;
  if(packedBytes>FILE_MAX_BATCH_BYTES+4*1024*1024){zipError=new FileClientError('TOO_LARGE');return;}chunks.push(new Uint8Array(data));});
 function add(path:string,bytes:Uint8Array){const entry=new ZipPassThrough(path);zip.add(entry);entry.push(bytes,true);if(zipError)throw zipError;}
 try{
  for(const [index,version]of versions.entries()){cancelled();const b=version.manifest.body,{filename,...metadata}=version.metadata,path=b.storage==='managed'?`files/${b.versionId}/${filename}`:null;
   if(path){const read=await files.bytes(projectId,b.versionId,'download');try{cancelled();if(read.bytes.length!==b.plainBytes||read.metadata.sha256!==version.metadata.sha256||read.metadata.filename!==filename)throw new FileClientError('CHANGED_FILE');add(path,read.bytes);}finally{read.bytes.fill(0);}}
   manifest.items.push({fileId:b.fileId,versionId:b.versionId,version:b.version,priorVersionId:b.priorVersionId,kind:b.kind,storage:b.storage,plainBytes:b.plainBytes,taskIds:b.taskIds,
    manifestDigest:await digestObject(version.manifest),filename,...metadata,archivePath:path,contentsIncluded:path!==null});options.onProgress?.(index+1,versions.length);
  }
  cancelled();if(fence(await files.context(projectId))!==fence(anchor))throw new FileClientError('CONFLICT');cancelled();
  const bytes=new TextEncoder().encode(canonicalJson(manifest));try{add('manifest.json',bytes);}finally{bytes.fill(0);}zip.end();if(zipError)throw zipError;
  return {filename:`project-files-${projectId}-${manifest.exportedAt.slice(0,10)}.zip`,mimeType:'application/zip',blob:new Blob(chunks,{type:'application/zip'}),manifest};
 }catch(error){zip.terminate();chunks.length=0;throw error;}
}
