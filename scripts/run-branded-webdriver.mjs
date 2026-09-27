/** Official Firefox / installed Safari compatibility checks through W3C WebDriver, never a bundled engine.
 * Run only after coordinating exclusive use of the HTTPS browser harness port.
 * No application database is used by the four reused specifications.
 */
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createWriteStream } from 'node:fs';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, writeFile, readFile, readdir, access } from 'node:fs/promises';
import { createServer } from 'node:net';
import { registerHooks } from 'node:module';
import { resolve, join } from 'node:path';
import { pathToFileURL, fileURLToPath } from 'node:url';

const args = process.argv.slice(2);
if (args.includes('--help')) {
  console.log('node --experimental-transform-types scripts/run-branded-webdriver.mjs --browser firefox --version 156.0.1 [--version 155.0.1] [--start-server] [--list]');
  console.log('Safari: --browser safari --version EXACT_INSTALLED_VERSION (one version per run; uses /usr/bin/safaridriver).');
  console.log('Uses .local/branded-browsers/firefox-VERSION/Firefox.app and geckodriver-0.37.1/geckodriver. Existing HTTPS harness required unless --start-server.');
  process.exit(0);
}
const browserName = args.includes('--browser') ? args[args.indexOf('--browser') + 1] : 'firefox';
assert(['firefox', 'safari'].includes(browserName), 'Supported --browser values: firefox, safari');
const browserLabel = browserName === 'safari' ? 'Safari' : 'Firefox';
const versions = args.flatMap((arg, index) => arg === '--version' ? [args[index + 1]] : []);
assert(versions.length > 0 && versions.every(version => /^\d+\.\d+(\.\d+)?$/.test(version)), 'Specify explicit expected --version values');
assert(browserName !== 'safari' || versions.length === 1, 'Safari runs one explicitly expected installed version; preserve evidence before updating');
const origin = 'https://127.0.0.1:3555';
const local = resolve('.local/branded-browsers');
const driverPath = browserName === 'safari' ? '/usr/bin/safaridriver' : join(local, 'geckodriver-0.37.1/geckodriver');
const output = resolve(`test-results/branded-${browserName}-results.json`);
const specificationPaths = ['crypto.spec.ts', 'auth-worker.spec.ts', 'crypto-compatibility.spec.ts', 'progress.spec.ts']
  .map(name => pathToFileURL(resolve('test/browser', name)).href);
const adapterUrl = new URL('./branded-webdriver-test-adapter.mjs', import.meta.url).href;
registerHooks({ resolve(specifier, context, nextResolve) {
  if (specifier === '@playwright/test' && specificationPaths.includes(context.parentURL)) return { url: adapterUrl, shortCircuit: true };
  try { return nextResolve(specifier, context); }
  catch (error) {
    if (error.code === 'ERR_MODULE_NOT_FOUND' && /\.js$/.test(specifier) && /^(\.\/|\.\.\/)/.test(specifier)) {
      return nextResolve(specifier.slice(0, -3) + '.ts', context);
    }
    throw error;
  }
} });
const { registeredTests } = await import(adapterUrl);
for (const specification of specificationPaths) await import(specification);
assert.equal(registeredTests.length, 4, 'Bounded adapter must load exactly the four intended specifications');
if (args.includes('--list')) { console.log(registeredTests.map(test => test.name).join('\n')); process.exit(0); }
await mkdir(resolve('test-results'), { recursive: true });
await mkdir(join(local, 'profiles'), { recursive: true });
await access(driverPath);
if (browserName === 'firefox') for (const version of versions) await access(join(local, `firefox-${version}/Firefox.app/Contents/MacOS/firefox`));
const sleep = ms => new Promise(done => setTimeout(done, ms));
async function availablePort() {
  const server = createServer();
  await new Promise((done, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', done); });
  const { port } = server.address();
  await new Promise(done => server.close(done));
  return port;
}
async function connectBidi(url) {
  const socket = new WebSocket(url);
  let nextId = 0;
  const pending = new Map();
  await new Promise((done, reject) => { socket.addEventListener('open', done, { once: true }); socket.addEventListener('error', reject, { once: true }); });
  socket.addEventListener('message', event => {
    const message = JSON.parse(event.data), entry = pending.get(message.id);
    if (!entry) return;
    pending.delete(message.id); clearTimeout(entry.timeout);
    if (message.type === 'error') entry.reject(new Error(`BiDi ${message.error}: ${message.message}`));
    else entry.resolve(message.result);
  });
  return {
    command(method, params) {
      const id = ++nextId;
      return new Promise((resolve, reject) => {
        const timeout = setTimeout(() => { pending.delete(id); reject(new Error(`BiDi ${method} timed out`)); }, 90000);
        pending.set(id, { resolve, reject, timeout });
        socket.send(JSON.stringify({ id, method, params }));
      });
    },
    close() { socket.close(); for (const entry of pending.values()) { clearTimeout(entry.timeout); entry.reject(new Error('BiDi closed')); } pending.clear(); },
  };
}
async function stop(child) {
  if (!child || child.exitCode !== null || child.signalCode !== null) return;
  const exited = new Promise(done => child.once('exit', done));
  child.kill('SIGTERM');
  const kill = setTimeout(() => child.kill('SIGKILL'), 3000);
  await exited;
  clearTimeout(kill);
}
let harness;
const hashPaths = [...specificationPaths.map(fileURLToPath), ...['run-branded-webdriver.mjs', 'branded-webdriver-test-adapter.mjs'].map(name => resolve('scripts', name)),
  ...(await readdir('dist/browser')).filter(name => name.endsWith('.js')).map(name => resolve('dist/browser', name))];
const hashes = Object.fromEntries(await Promise.all(hashPaths.map(async path => [path, createHash('sha256').update(await readFile(path)).digest('hex')])));
const evidence = { hashes, observedAt: new Date().toISOString(), platform: process.platform, arch: process.arch,
  node: process.version, browser: browserName, origin, driver: driverPath, specifications: specificationPaths.map(fileURLToPath), results: [] };
try {
  if (args.includes('--start-server')) {
    harness = spawn(process.execPath, ['test/browser/server.mjs'], { stdio: ['ignore', 'pipe', 'pipe'] });
    await new Promise((done, reject) => {
      const timeout = setTimeout(() => reject(new Error('HTTPS harness startup timed out')), 15000);
      const fail = () => { clearTimeout(timeout); reject(new Error('HTTPS harness exited before ready (port may already be in use)')); };
      harness.once('exit', fail);
      harness.stderr.on('data', data => process.stderr.write(data));
      harness.stdout.on('data', data => { if (data.toString().includes('ready')) { clearTimeout(timeout); harness.off('exit', fail); done(); } });
    });
  }
  for (const version of versions) {
    const directory = await mkdtemp(join(local, 'profiles', `${browserName}-${version}-`));
    const port = await availablePort();
    const logPath = join(directory, `${browserName}-driver.log`);
    const log = createWriteStream(logPath);
    const driverArgs = browserName === 'safari' ? ['--port', String(port)] : ['--host', '127.0.0.1', '--port', String(port), '--profile-root', directory];
    const driver = spawn(driverPath, driverArgs,
      { stdio: ['ignore', 'pipe', 'pipe'], env: browserName === 'safari' ? process.env : { ...process.env, MOZ_CRASHREPORTER_DISABLE: '1' } });
    driver.stdout.pipe(log); driver.stderr.pipe(log);
    const base = `http://127.0.0.1:${port}`;
    let session, bidi;
    async function command(method, path, body) {
      const response = await fetch(base + path, { method, ...(body === undefined ? {} : { body: JSON.stringify(body), headers: { 'content-type': 'application/json' } }),
        signal: AbortSignal.timeout(95000) });
      const data = await response.json();
      if (!response.ok || typeof data.value?.error === 'string') throw new Error(`WebDriver ${path}: ${data.value?.error ?? response.status}: ${data.value?.message ?? ''}`);
      return data.value;
    }
    const result = { requestedBrowser: browserName, requestedVersion: version, artifactDirectory: directory,
      ...(browserName === 'firefox' ? { profileRoot: directory } : { isolation: 'Safari isolated WebDriver automation window' }), driverLog: logPath, tests: [] };
    evidence.results.push(result);
    try {
      let ready = false;
      for (let count = 0; count < 100; count++) {
        if (driver.exitCode !== null) throw new Error(`${browserLabel} driver exited ${driver.exitCode}; see ${logPath}`);
        try { const status = await command('GET', '/status'); if (status.ready) { ready = true; break; } } catch { /* bounded startup polling */ }
        await sleep(100);
      }
      assert(ready, `${browserLabel} driver did not become ready`);
      const capabilities = browserName === 'safari'
        ? { browserName: 'Safari', browserVersion: version, platformName: 'macOS', acceptInsecureCerts: true }
        : { browserName: 'firefox', acceptInsecureCerts: true, webSocketUrl: true,
          'moz:firefoxOptions': { binary: join(local, `firefox-${version}/Firefox.app/Contents/MacOS/firefox`), args: ['-headless'],
            prefs: { 'app.update.auto': false, 'browser.shell.checkDefaultBrowser': false } } };
      const created = await command('POST', '/session', { capabilities: { alwaysMatch: capabilities } });
      session = created.sessionId;
      result.capabilities = created.capabilities;
      assert.equal(created.capabilities.browserName.toLowerCase(), browserName);
      assert.equal(created.capabilities.browserVersion, version, 'Actual branded browser must match requested version');
      await command('POST', `/session/${session}/timeouts`, { script: 90000, pageLoad: 30000, implicit: 0 });
      let context;
      if (browserName === 'firefox') {
        bidi = await connectBidi(created.capabilities.webSocketUrl);
        const tree = await bidi.command('browsingContext.getTree', {});
        context = tree.contexts[0].context;
      }
      // Classic Marionette execute-script uses a sandbox realm. Application crypto
      // intentionally rejects foreign prototypes. BiDi's default page realm matches
      // normal app objects without changing CSP or weakening that validation.
      async function evaluate(fn, argument) {
        if (browserName === 'safari') {
          const result = await command('POST', `/session/${session}/execute/async`, {
            script: `const serialized = arguments[0], done = arguments[arguments.length - 1]; Promise.resolve().then(() => (${fn.toString()})(JSON.parse(serialized))).then(value => done({ok:true,json:JSON.stringify(value ?? null)}), error => done({ok:false,detail:{name:error.name,message:error.message,stack:error.stack,code:error.code}}));`,
            args: [JSON.stringify(argument ?? null)],
          });
          if (!result.ok) throw new Error(`Browser evaluation: ${result.detail.name}: ${result.detail.message}\n${result.detail.stack ?? ''}`);
          return JSON.parse(result.json);
        }
        const reply = await bidi.command('script.callFunction', {
          functionDeclaration: `async function(serialized) { const result = await (${fn.toString()})(JSON.parse(serialized)); return JSON.stringify(result ?? null); }`,
          awaitPromise: true, target: { context }, resultOwnership: 'none',
          arguments: [{ type: 'string', value: JSON.stringify(argument ?? null) }],
        });
        if (reply.type === 'exception') throw new Error(`Browser evaluation: ${reply.exceptionDetails.text}\n${JSON.stringify(reply.exceptionDetails.stackTrace)}`);
        assert.equal(reply.result.type, 'string', 'BiDi evaluation must return serialized data');
        return JSON.parse(reply.result.value);
      }
      const page = {
        goto: url => command('POST', `/session/${session}/url`, { url: new URL(url, origin).href }),
        reload: () => command('POST', `/session/${session}/refresh`, {}),
        async waitForFunction(fn) {
          for (let count = 0; count < 100; count++) {
            if (await evaluate(fn)) return;
            await sleep(100);
          }
          throw new Error('Client harness did not initialize within 10 seconds');
        },
        evaluate,
      };
      for (const spec of registeredTests) {
        const started = Date.now(), item = { name: spec.name, attachments: [] };
        result.tests.push(item);
        try {
          await spec.run({ page, browser: { version: () => created.capabilities.browserVersion } }, {
            project: { name: `official-${browserName}-${version}-webdriver` },
            attach: async (name, attachment) => item.attachments.push({ name, contentType: attachment.contentType, body: String(attachment.body) }),
          });
          item.status = 'passed';
          console.log(`PASS ${browserLabel} ${version}: ${spec.name}`);
        } catch (error) { item.status = 'failed'; item.error = { message: error.message, stack: error.stack }; process.exitCode = 1; console.error(`FAIL ${browserLabel} ${version}: ${spec.name}: ${error.message}`); }
        item.durationMs = Date.now() - started;
        await writeFile(output, JSON.stringify(evidence, null, 2) + '\n');
      }
    } catch (error) { result.error = { message: error.message, stack: error.stack }; process.exitCode = 1; console.error(`${browserLabel} ${version}: ${error.message}`); }
    finally {
      bidi?.close();
      if (session) await command('DELETE', `/session/${session}`).catch(() => {});
      await stop(driver); log.end();
      await writeFile(output, JSON.stringify(evidence, null, 2) + '\n');
    }
  }
} finally { await stop(harness); }
console.log(`Evidence: ${output}`);
