import { z } from 'zod';
import { binary,digest,identifier } from './contracts.js';
import { fileEditorPermit,fileManifest,FILE_MAX_PLAIN_BYTES } from './files.js';
export const editorStart=z.strictObject({permit:fileEditorPermit,manifest:fileManifest,filename:z.string().min(1).max(240),
 sha256:digest,bytes:binary(1,FILE_MAX_PLAIN_BYTES),theme:z.enum(['light','dark']).default('light')});
export const editorLeaseReference=z.strictObject({leaseId:identifier});
export const editorOpened=z.strictObject({leaseId:identifier,token:binary(32),config:z.record(z.string(),z.unknown()),expiresAt:z.iso.datetime()});
export const editorSnapshot=z.strictObject({leaseId:identifier,state:z.enum(['waiting','ready','unchanged','error']),revision:z.number().int().nonnegative(),
 filename:z.string().min(1).max(240),sha256:digest.nullable(),bytes:binary(1,FILE_MAX_PLAIN_BYTES).nullable()});
export type EditorOpened=z.infer<typeof editorOpened>;
