import { z } from 'zod';
import { canonicalJson } from '../shared/crypto.js';
import { accessDelivery } from '../shared/access-change.js';
import { verifySecurityHistory, type SecurityHistoryInput } from '../shared/security-history.js';
import { EXPORT_MAX_PAGES, EXPORT_PAGE_BYTES, EXPORT_TOTAL_BYTES, EXPORT_NOTICE, exportStart, exportPage, exportReceipt,
  exportManifestKey, type ExportStart, type ExportPage, type ExportFinalize, type ExportReceipt } from '../shared/export.js';
import { AuthenticatedHttp, AuthClientError, type AuthController, type AuthRequestOptions } from './auth-controller.js';
import { IndexedPairingStore } from './pairing.js';
import type { AccessChangeController, AccessChangeTransport } from './access-change-controller.js';
import { ExportClientError, type PrepareExportInput } from './export-crypto.js';
import { assertOnline } from './write-state.js';
import { planningWireValue } from '../shared/planning-api.js';
import { PlanningHistoryPool } from './planning-history-pool.js';

export interface ExportTransport {
  readonly origin:string;
  start(input:{workspaceId:string;exportId:string;acknowledgePlaintext:true},options?:AuthRequestOptions):Promise<ExportStart>;
  page(input:{workspaceId:string;exportId:string;manifestDigest:string;after:string|null},options?:AuthRequestOptions):Promise<ExportPage>;
  finalize(input:ExportFinalize,options?:AuthRequestOptions):Promise<ExportReceipt>;
}
export class HttpExportTransport extends AuthenticatedHttp implements ExportTransport {
  constructor(origin:string,private readonly csrf:()=>string|undefined,fetcher?:typeof fetch){super(origin,fetcher);}
  private request<T>(path:string,input:unknown,schema:z.ZodType<T>,options?:AuthRequestOptions) {const csrfToken=this.csrf();if(!csrfToken)throw new AuthClientError('AUTH_REQUIRED');
    return this.post('/v1/export/'+path,input,schema,{...options,csrfToken});}
  start(input:Parameters<ExportTransport['start']>[0],options?:AuthRequestOptions){return this.request('start',input,exportStart,options);}
  page(input:Parameters<ExportTransport['page']>[0],options?:AuthRequestOptions){return this.request('page',input,exportPage,options) as Promise<ExportPage>;}
  finalize(input:ExportFinalize,options?:AuthRequestOptions){return this.request('finalize',input,exportReceipt,options);}
  protected override responseLimit(){return EXPORT_PAGE_BYTES;}
}
export interface ExportDownload {filename:string;mimeType:'application/json;charset=utf-8';json:string;receipt:ExportReceipt}
/** Headless explicit data exit. No draft, plaintext, automatic retry or download
 * is persisted. Callers receive the file only after the final authority gate. */
export class ExportController {
  readonly notice=EXPORT_NOTICE;
  private epoch=0;private readonly requests=new Set<AbortController>();
  constructor(private readonly auth:AuthController,private readonly transport:ExportTransport,private readonly pins:IndexedPairingStore,
    private readonly access:Pick<AccessChangeController,'refreshKeys'>,private readonly security:Pick<AccessChangeTransport,'delivery'|'deliveryHistory'>,
    private readonly options:{trustedServiceKeys?:Record<string,string>}={}) {
    if(auth.origin!==transport.origin||auth.origin!==pins.origin)throw new ExportClientError('CONFLICT');
  }
  clear(){this.epoch++;for(const request of this.requests)request.abort();this.requests.clear();}
  attachAuthLifecycle(){return this.auth.onClear(()=>this.clear());}
  private check(epoch:number,signal:AbortSignal){if(epoch!==this.epoch||signal.aborted)throw new ExportClientError('CANCELLED');}
  async generate(input:{acknowledgePlaintext:true;exportId?:string}):Promise<ExportDownload> {
    if(input.acknowledgePlaintext!==true)throw new ExportClientError('ACKNOWLEDGEMENT_REQUIRED');assertOnline();
    const reference={exportId:input.exportId??crypto.randomUUID()},request=new AbortController(),signal=request.signal,epoch=this.epoch;this.requests.add(request);
    try {
      const session=this.auth.current();if(session?.localAccess!=='unlocked'||!session.session.deviceId)throw new AuthClientError('AUTH_REQUIRED');
      const s=session.session,pin=await this.pins.pin(s.workspaceId);this.check(epoch,signal);if(!pin)throw new ExportClientError('TRUST_REQUIRED');
      await this.access.refreshKeys();this.check(epoch,signal);
      const delivery=accessDelivery.parse(await this.security.delivery({workspaceId:s.workspaceId},{signal}));this.check(epoch,signal);
      const response=await this.security.deliveryHistory({workspaceId:s.workspaceId,operationId:reference.exportId},{signal});this.check(epoch,signal);
      if(canonicalJson(response.anchor)!==canonicalJson(response.current)||canonicalJson(delivery.current)!==canonicalJson(response.current)||delivery.accountId!==s.accountId||delivery.deviceId!==s.deviceId||delivery.workspaceId!==s.workspaceId)throw new ExportClientError('CONFLICT');
      const history:SecurityHistoryInput={workspaceId:s.workspaceId,origin:this.auth.origin,genesisFingerprint:pin.genesisFingerprint,genesis:response.genesis,transitions:response.transitions,
        expected:response.anchor,pin,trustedServiceKeys:this.options.trustedServiceKeys??{}},state=await verifySecurityHistory(history);this.check(epoch,signal);
      const profile=state.profiles[s.accountId];if(!profile?.active||!profile.owner||profile.credentialGeneration!==s.credentialGeneration||profile.sessionGeneration!==s.sessionGeneration||state.dataGeneration!==s.dataGeneration)throw new ExportClientError('CONFLICT');
      const start=exportStart.parse(await this.transport.start({...reference,workspaceId:s.workspaceId,acknowledgePlaintext:true},{signal}));this.check(epoch,signal);
      const b=start.binding;if(b.exportId!==reference.exportId||b.workspaceId!==s.workspaceId||b.accountId!==s.accountId||b.deviceId!==s.deviceId||b.securityHead!==state.securityHead||b.dataGeneration!==state.dataGeneration)throw new ExportClientError('CONFLICT');
      const pages:ExportPage[]=[],planningHistories=new PlanningHistoryPool();let after:string|null=null,total=new TextEncoder().encode(canonicalJson(start)).byteLength;
      for(let i=0;i<start.sources.length&&i<EXPORT_MAX_PAGES;i++) {
        const page=exportPage.parse(await this.transport.page({...reference,workspaceId:s.workspaceId,manifestDigest:b.manifestDigest,after},{signal})) as ExportPage;this.check(epoch,signal);
        if(canonicalJson(page.binding)!==canonicalJson(b)||canonicalJson(page.source)!==canonicalJson(start.sources[i])||page.nextCursor!==(i+1<start.sources.length?exportManifestKey(page.source):null))throw new ExportClientError('CONFLICT');
        total+=new TextEncoder().encode(canonicalJson(planningWireValue(page))).byteLength;if(total>EXPORT_TOTAL_BYTES)throw new ExportClientError('TOO_LARGE');try{if(page.data.kind==='project')planningHistories.retain(page.data.context);else if(page.data.kind==='entry')planningHistories.retain(page.data.history.planning);}catch{throw new ExportClientError('TOO_LARGE');}pages.push(page);after=page.nextCursor;
      }
      if(pages.length!==start.sources.length||after!==null)throw new ExportClientError('INVALID_EXPORT');
      const prepared=await this.auth.worker.prepareExport({start,pages,history,materials:delivery.materials,accountId:s.accountId,deviceId:s.deviceId,acknowledgePlaintext:true} satisfies PrepareExportInput,{signal});this.check(epoch,signal);
      assertOnline();const receipt=exportReceipt.parse(await this.transport.finalize(prepared.finalize,{signal}));this.check(epoch,signal);
      if(receipt.workspaceId!==b.workspaceId||receipt.exportId!==b.exportId||receipt.accountId!==b.accountId||receipt.dataGeneration!==b.dataGeneration||receipt.manifestDigest!==b.manifestDigest||receipt.documentDigest!==prepared.documentDigest)throw new ExportClientError('INVALID_EXPORT');
      await this.pins.recordVerifiedHistory(history);this.check(epoch,signal);
      return {filename:`workspace-${b.workspaceId}-${b.issuedAt.slice(0,10)}.json`,mimeType:'application/json;charset=utf-8',json:prepared.json,receipt};
    }finally{this.requests.delete(request);}
  }
}
