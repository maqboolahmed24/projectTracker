import { receiptLookupRequest, receiptLookupResponse, type ReceiptLookupRequest } from '../shared/receipts.js';
import { AuthenticatedHttp, AuthClientError, type AuthController } from './auth-controller.js';
type WithoutWorkspace<T> = T extends unknown ? Omit<T, 'workspaceId'> : never;
export type ReceiptLookupInput = WithoutWorkspace<ReceiptLookupRequest>;
/** Server acknowledgement only. This helper never advances a security/content pin or installs keys. */
export class ReceiptController {
  private epoch=0;
  constructor(private readonly auth:AuthController,private readonly transport:AuthenticatedHttp){if(auth.origin!==transport.origin)throw new AuthClientError('CONTEXT_MISMATCH');}
  attachAuthLifecycle(){return this.auth.onClear(()=>{this.epoch++;});}
  async lookup(input:ReceiptLookupInput){
    const current=this.auth.current(),epoch=this.epoch;if(current?.localAccess!=='unlocked'||!current.session.deviceId)throw new AuthClientError('AUTH_REQUIRED');
    const request=receiptLookupRequest.parse({...structuredClone(input),workspaceId:current.session.workspaceId}),
      result=await this.transport.post('/v1/work/receipts',request,receiptLookupResponse,{csrfToken:current.session.csrfToken});
    if(epoch!==this.epoch)throw new AuthClientError('CANCELLED');
    if(result.kind!==request.kind||result.receipt&&(result.receipt.workspaceId!==request.workspaceId||result.receipt.operationId!==request.operationId||
      'dataGeneration' in result.receipt&&result.receipt.dataGeneration!==current.session.dataGeneration))throw new AuthClientError('CONTEXT_MISMATCH');
    return result;
  }
}
