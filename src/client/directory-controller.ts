import { canonicalJson } from '../shared/crypto.js';
import { accessDelivery } from '../shared/access-change.js';
import { verifySecurityHistory, type SecurityHistoryInput } from '../shared/security-history.js';
import { AuthClientError, type AuthController } from './auth-controller.js';
import type { AccessChangeController, AccessChangeTransport } from './access-change-controller.js';
import { IndexedPairingStore } from './pairing.js';
import { ProfileClientError } from './profile-crypto.js';
import type { WorkspaceDirectory } from './directory-crypto.js';
import { assertOnline } from './write-state.js';

const same=(a:unknown,b:unknown)=>canonicalJson(a)===canonicalJson(b);
/** Verified workspace labels for presentation, retained only in memory. */
export class DirectoryController {
  private epoch=0;private readonly requests=new Set<AbortController>();
  constructor(private readonly auth:AuthController,private readonly pins:IndexedPairingStore,
    private readonly access:Pick<AccessChangeController,'refreshKeys'>,private readonly security:Pick<AccessChangeTransport,'origin'|'delivery'|'deliveryHistory'>,
    private readonly options:{trustedServiceKeys?:Record<string,string>}={}) {
    if(auth.origin!==pins.origin||auth.origin!==security.origin)throw new ProfileClientError('CONFLICT');
  }
  clear(){this.epoch++;for(const request of this.requests)request.abort();this.requests.clear();}
  attachAuthLifecycle(){return this.auth.onClear(()=>this.clear());}
  private check(epoch:number,signal:AbortSignal){if(epoch!==this.epoch||signal.aborted)throw new ProfileClientError('CANCELLED');}
  async current():Promise<WorkspaceDirectory>{
    assertOnline();const request=new AbortController(),signal=request.signal,epoch=this.epoch;this.requests.add(request);
    try{
      const current=this.auth.current();if(current?.localAccess!=='unlocked'||!current.session.deviceId)throw new AuthClientError('AUTH_REQUIRED');
      const s=current.session,deviceId=s.deviceId;if(!deviceId)throw new AuthClientError('AUTH_REQUIRED');
      const pin=await this.pins.pin(s.workspaceId);this.check(epoch,signal);if(!pin)throw new ProfileClientError('TRUST_REQUIRED');
      const response=await this.security.deliveryHistory({workspaceId:s.workspaceId,operationId:crypto.randomUUID()},{signal});this.check(epoch,signal);
      if(!same(response.anchor,response.current))throw new ProfileClientError('CONFLICT');
      const history:SecurityHistoryInput={workspaceId:s.workspaceId,origin:this.auth.origin,genesisFingerprint:pin.genesisFingerprint,genesis:response.genesis,
        transitions:response.transitions,expected:response.anchor,pin,trustedServiceKeys:this.options.trustedServiceKeys??{}};
      const state=await verifySecurityHistory(history);this.check(epoch,signal);
      const person=state.profiles[s.accountId],device=state.devices[deviceId];
      if(!person?.active||!device?.active||device.accountId!==s.accountId||person.credentialGeneration!==s.credentialGeneration||person.sessionGeneration!==s.sessionGeneration||state.dataGeneration!==s.dataGeneration)throw new ProfileClientError('CONFLICT');
      if(state.restoreQuarantine){
        // Only signed status is shown during restoration; no private content or
        // workspace keys are requested until the existing review completes.
        return {workspaceId:s.workspaceId,workspaceName:'Your workspace',accountId:s.accountId,deviceId,isOwner:person.owner,genesisFingerprint:state.genesisFingerprint,
          people:[],projectIds:[],permissions:[],devices:[],lifecycle:state.lifecycle??'active',deletion:state.deletion??null,
          restoreQuarantine:true,activeRestore:state.activeRestore??null,licenceState:state.licenceState,entitlementState:state.entitlementState,
          writeSchema:state.writeSchema??1,activeUpgrade:state.activeUpgrade??null};
      }
      await this.access.refreshKeys();this.check(epoch,signal);
      const delivery=accessDelivery.parse(await this.security.delivery({workspaceId:s.workspaceId,includeDirectory:true},{signal}));this.check(epoch,signal);
      const matchesActor=(value:typeof delivery)=>value.workspaceId===s.workspaceId&&value.accountId===s.accountId&&value.deviceId===deviceId;
      if(!matchesActor(delivery)||!same(delivery.current,response.current))throw new ProfileClientError('CONFLICT');
      const result=await this.auth.worker.readWorkspaceDirectory({history,materials:delivery.materials,accountId:s.accountId,deviceId},{signal});this.check(epoch,signal);
      const fence=accessDelivery.parse(await this.security.delivery({workspaceId:s.workspaceId},{signal}));this.check(epoch,signal);
      if(!matchesActor(fence)||!same(fence.current,response.current))throw new ProfileClientError('CONFLICT');
      await this.pins.recordVerifiedHistory(history);this.check(epoch,signal);return result;
    }finally{this.requests.delete(request);}
  }
}
