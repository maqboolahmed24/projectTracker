import { canonicalJson } from '../shared/crypto.js';
import { accessDelivery } from '../shared/access-change.js';
import { verifySecurityHistory, type SecurityHistoryInput } from '../shared/security-history.js';
import { AuthClientError, type AuthController } from './auth-controller.js';
import type { AccessChangeController, AccessChangeTransport } from './access-change-controller.js';
import { IndexedPairingStore } from './pairing.js';
import { ProfileClientError, type CurrentProfile } from './profile-crypto.js';
import { assertOnline } from './write-state.js';

const same=(a:unknown,b:unknown)=>canonicalJson(a)===canonicalJson(b);
/** Headless authenticated self-profile reader. Plaintext is returned, never persisted. */
export class ProfileController {
  private epoch=0;private readonly requests=new Set<AbortController>();
  constructor(private readonly auth:AuthController,private readonly pins:IndexedPairingStore,
    private readonly access:Pick<AccessChangeController,'refreshKeys'>,private readonly security:Pick<AccessChangeTransport,'origin'|'delivery'|'deliveryHistory'>,
    private readonly options:{trustedServiceKeys?:Record<string,string>}={}) {
    if(auth.origin!==pins.origin||auth.origin!==security.origin)throw new ProfileClientError('CONFLICT');
  }
  clear(){this.epoch++;for(const request of this.requests)request.abort();this.requests.clear();}
  attachAuthLifecycle(){return this.auth.onClear(()=>this.clear());}
  private check(epoch:number,signal:AbortSignal){if(epoch!==this.epoch||signal.aborted)throw new ProfileClientError('CANCELLED');}
  async current():Promise<CurrentProfile> {
    assertOnline();const request=new AbortController(),signal=request.signal,epoch=this.epoch;this.requests.add(request);
    try {
      const session=this.auth.current();if(session?.localAccess!=='unlocked'||!session.session.deviceId)throw new AuthClientError('AUTH_REQUIRED');
      const s=session.session,deviceId=s.deviceId;if(!deviceId)throw new AuthClientError('AUTH_REQUIRED');
      const pin=await this.pins.pin(s.workspaceId);this.check(epoch,signal);if(!pin)throw new ProfileClientError('TRUST_REQUIRED');
      await this.access.refreshKeys();this.check(epoch,signal);
      const delivery=accessDelivery.parse(await this.security.delivery({workspaceId:s.workspaceId,includeProfile:true},{signal}));this.check(epoch,signal);
      const response=await this.security.deliveryHistory({workspaceId:s.workspaceId,operationId:crypto.randomUUID()},{signal});this.check(epoch,signal);
      const matchesActor=(value:typeof delivery)=>value.workspaceId===s.workspaceId&&value.accountId===s.accountId&&value.deviceId===s.deviceId;
      if(!matchesActor(delivery)||!same(response.anchor,response.current)||!same(delivery.current,response.current))throw new ProfileClientError('CONFLICT');
      const history:SecurityHistoryInput={workspaceId:s.workspaceId,origin:this.auth.origin,genesisFingerprint:pin.genesisFingerprint,genesis:response.genesis,
        transitions:response.transitions,expected:response.anchor,pin,trustedServiceKeys:this.options.trustedServiceKeys??{}},state=await verifySecurityHistory(history);this.check(epoch,signal);
      const profile=state.profiles[s.accountId];if(!profile?.active||profile.credentialGeneration!==s.credentialGeneration||profile.sessionGeneration!==s.sessionGeneration||state.dataGeneration!==s.dataGeneration)throw new ProfileClientError('CONFLICT');
      const result=await this.auth.worker.readCurrentProfile({history,materials:delivery.materials,accountId:s.accountId,deviceId},{signal});this.check(epoch,signal);
      // A concurrent revocation, recovery, restore or profile replacement cannot
      // release plaintext from a read that has already become stale.
      const fence=accessDelivery.parse(await this.security.delivery({workspaceId:s.workspaceId},{signal}));this.check(epoch,signal);
      if(!matchesActor(fence)||!same(fence.current,response.current))throw new ProfileClientError('CONFLICT');
      await this.pins.recordVerifiedHistory(history);this.check(epoch,signal);return result;
    }finally{this.requests.delete(request);}
  }
}
