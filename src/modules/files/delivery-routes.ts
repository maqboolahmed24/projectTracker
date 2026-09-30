import type {FastifyInstance,FastifyRequest} from 'fastify';
import {z} from 'zod';
import {AppError} from '../../errors.js';
import {parseInput} from '../../http.js';
import {binary} from '../../shared/contracts.js';
import {fileReference,FILE_MAX_REQUEST_BYTES} from '../../shared/files.js';
import {deliveryBatchRequest,deliveryCommandRequest,deliveryCreateRequest,deliveryListRequest,deliveryPairContextRequest,deliveryPairRequest,
 deliveryPermitRequest,deliveryPublishRequest,deliveryServiceCommandRequest,deliveryStatusRequest} from '../../shared/file-delivery.js';
import type {RequestBudgets} from '../identity/budgets.js';
import {readSessionCookie} from '../identity/sessions.js';
import type {DeliveryService} from './delivery-service.js';
export function registerDeliveryRoutes(app:FastifyInstance,input:{origin:string;delivery:DeliveryService;budgets:Pick<RequestBudgets,'take'>}){
 function auth(request:FastifyRequest){const csrf=request.headers['x-csrf-token'];if(typeof csrf!=='string'||!binary(32).safeParse(csrf).success)throw new AppError('CSRF_REJECTED','Request verification failed',403);
  const cookie=readSessionCookie(request.headers.cookie);if(!cookie)throw new AppError('AUTH_REQUIRED','Authentication required',401);return {cookie,csrf};}
 function route<T>(path:string,schema:z.ZodType<T>,action:(body:T,a:{cookie:string;csrf:string})=>Promise<unknown>){
  app.post(`/v1/files/delivery/${path}`,{bodyLimit:FILE_MAX_REQUEST_BYTES,preHandler:async(request,reply)=>{reply.header('cache-control','no-store');
   if(request.headers.origin!==input.origin||request.headers['sec-fetch-site']==='cross-site')throw new AppError('ORIGIN_REJECTED','Request origin is not allowed',403);
   if(Object.keys(request.query as object).length)throw new AppError('INVALID_REQUEST','Invalid request',400);
   await input.budgets.take([{purpose:'delivery-source',key:request.ip,limit:2400,windowMs:600000}]);}},async request=>{
    const body=parseInput(schema,request.body),credentials=auth(request);try{return await action(body,credentials);}catch(error){if(error instanceof AppError)throw error;throw new AppError('DELIVERY_UNAVAILABLE','Delivery is temporarily unavailable; retain the prepared batch',503);}
   });
 }
 route('context',fileReference,(b,a)=>input.delivery.context(a.cookie,a.csrf,b));
 route('create',deliveryCreateRequest,(b,a)=>input.delivery.create(a.cookie,a.csrf,b));
 route('list',deliveryListRequest,(b,a)=>input.delivery.list(a.cookie,a.csrf,b));
 route('get',deliveryBatchRequest,(b,a)=>input.delivery.get(a.cookie,a.csrf,b));
 route('confirm',deliveryCommandRequest,(b,a)=>input.delivery.command(a.cookie,a.csrf,b,'confirm'));
 route('cancel',deliveryCommandRequest,(b,a)=>input.delivery.command(a.cookie,a.csrf,b,'cancel'));
 route('record-package',deliveryCommandRequest,(b,a)=>input.delivery.command(a.cookie,a.csrf,b,'record_package'));
 route('check',deliveryBatchRequest,(b,a)=>input.delivery.check(a.cookie,a.csrf,b));
 route('pair-context',deliveryPairContextRequest,(b,a)=>input.delivery.pairContext(a.cookie,a.csrf,b));
 route('pair',deliveryPairRequest,(b,a)=>input.delivery.pair(a.cookie,a.csrf,b));
 route('services',fileReference,(b,a)=>input.delivery.services(a.cookie,a.csrf,b));
 route('revoke-service',deliveryServiceCommandRequest,(b,a)=>input.delivery.revokeService(a.cookie,a.csrf,b));
 route('permit',deliveryPermitRequest,(b,a)=>input.delivery.permit(a.cookie,a.csrf,b));
 route('publish',deliveryPublishRequest,(b,a)=>input.delivery.publish(a.cookie,a.csrf,b));
 route('status',deliveryStatusRequest,(b,a)=>input.delivery.status(a.cookie,a.csrf,b));
}
