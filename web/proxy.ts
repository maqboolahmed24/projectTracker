import { NextResponse, type NextRequest } from 'next/server';
export function proxy(request:NextRequest){
  const nonce=Buffer.from(crypto.randomUUID()).toString('base64');
  const policy=["default-src 'self'",`script-src 'self' 'nonce-${nonce}' 'strict-dynamic' 'wasm-unsafe-eval'`,"worker-src 'self'","style-src 'self' 'unsafe-inline'","img-src 'self' data: blob:","font-src 'self'","connect-src 'self'","object-src 'none'","base-uri 'none'","form-action 'self'","frame-ancestors 'none'"].join('; ');
  const headers=new Headers(request.headers);headers.set('x-nonce',nonce);headers.set('Content-Security-Policy',policy);
  const response=NextResponse.next({request:{headers}});response.headers.set('Content-Security-Policy',policy);response.headers.set('Cache-Control','private, no-store');return response;
}
export const config={matcher:['/((?!v1/|_next/static|_next/image|client/|brand/|favicon.ico).*)']};
