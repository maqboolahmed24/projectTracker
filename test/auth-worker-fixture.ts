import { parentPort, workerData } from 'node:worker_threads';
import { IDBFactory } from 'fake-indexeddb';
import { installAuthWorker } from '../src/client/auth-worker.js';

if (!parentPort) throw new Error('Worker fixture requires a worker thread');
const port = parentPort;
const options = workerData as { origin: string; unsupported?: 'wasm' | 'crypto' | 'indexedDB' };
installAuthWorker({
  addEventListener(_type, listener) { port.on('message', (data: unknown) => listener(new MessageEvent('message', { data }))); },
  postMessage(message) { port.postMessage(message); },
}, {
  origin: options.origin,
  crypto: options.unsupported === 'crypto' ? undefined : globalThis.crypto,
  webAssembly: options.unsupported === 'wasm' ? undefined : globalThis.WebAssembly,
  indexedDB: options.unsupported === 'indexedDB' ? undefined : new IDBFactory(),
});
