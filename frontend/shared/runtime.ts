import type * as Library from '../../src/client/index.js';
import type { ClientRuntime } from '../../src/client/runtime.js';
export type { ClientRuntime };

let library: Promise<typeof Library> | undefined;
/** Load the already built, same-origin browser library. Keys remain in its Worker. */
export function getClientLibrary(): Promise<typeof Library> {
  const url='/client/client.js';
  library ??= import(/* webpackIgnore: true */ url) as Promise<typeof Library>;
  return library;
}
export async function createClient(): Promise<ClientRuntime> {
  // Test the browser's real Secure-cookie policy before a person starts setup.
  // This disposable marker is unrelated to the HttpOnly authentication cookie.
  const marker='__Host-ukda-browser-check';
  document.cookie=`${marker}=1; Path=/; Secure; SameSite=Lax; Max-Age=10`;
  const cookiesWork=document.cookie.split(';').some(value=>value.trim()===`${marker}=1`);
  document.cookie=`${marker}=; Path=/; Secure; SameSite=Lax; Max-Age=0`;
  if(!cookiesWork)throw Object.assign(new Error('BROWSER_COOKIES'),{code:location.protocol==='http:'?'SECURE_ADDRESS_REQUIRED':'COOKIES_REQUIRED'});
  const [module, response] = await Promise.all([getClientLibrary(), fetch('/v1/application', {cache:'no-store', credentials:'same-origin'})]);
  if (!response.ok) throw new Error('APPLICATION_UNAVAILABLE');
  const config = await response.json() as {trustedServiceKeys:Record<string,string>};
  return module.openClient({origin:location.origin, trustedServiceKeys:config.trustedServiceKeys});
}
