import { Worker } from 'node:worker_threads';
import { AuthWorkerClient, type AuthWorkerEndpoint } from '../src/client/auth-worker-client.js';

/** Real separate-thread driver; browser-engine evidence is recorded by the browser suite. */
export function testAuthWorker(origin: string): AuthWorkerClient {
  return new AuthWorkerClient({ origin, createWorker: () => {
    const worker = new Worker(new URL('./auth-worker-fixture.js', import.meta.url), { workerData: { origin } });
    const bindings = new Map<string, Map<EventListener, (data: unknown) => void>>();
    return {
      postMessage(value) { worker.postMessage(value); }, terminate() { void worker.terminate(); },
      addEventListener(type, listener) {
        const wrapped = (data: unknown) => listener(type === 'message' ? new MessageEvent('message', { data }) : new Event(type));
        const listeners = bindings.get(type) ?? new Map(); bindings.set(type, listeners); listeners.set(listener, wrapped); worker.on(type, wrapped);
      },
      removeEventListener(type, listener) { const wrapped = bindings.get(type)?.get(listener); if (wrapped) worker.off(type, wrapped); bindings.get(type)?.delete(listener); },
    } satisfies AuthWorkerEndpoint;
  } });
}
