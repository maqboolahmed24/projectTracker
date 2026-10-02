import { inboxBinding,inboxCommand,validateInboxMutation,type InboxBinding,type InboxCommand } from '../shared/inbox.js';
import { base64urlDecode,signObject } from '../shared/crypto.js';
import type { DeviceBundle } from './device-store.js';
export interface PrepareInboxInput {binding:InboxBinding;command:InboxCommand}
/** Only purpose-bound, non-secret Inbox preferences can be signed by this method. */
export async function prepareInbox(input:PrepareInboxInput,bundle:DeviceBundle){
  const binding=inboxBinding.parse(input.binding),command=inboxCommand.parse(input.command);
  if(binding.signingPublicKey!==bundle.signingPublicKey)throw new Error('Inbox signer mismatch');
  const key=base64urlDecode(bundle.signingPrivateKey,64);
  try{return await validateInboxMutation(await signObject({purpose:'ukda.inbox.v1' as const,binding,command},key));}
  finally{key.fill(0);}
}
