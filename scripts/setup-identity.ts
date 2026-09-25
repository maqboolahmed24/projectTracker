import { randomBytes } from 'node:crypto';
import { open, unlink } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import * as opaque from '@serenity-kit/opaque';
import { loadIdentityConfig } from '../src/modules/identity/secrets.js';

export type ProvisioningCode = 'USAGE' | 'CONFIGURATION' | 'OUTPUT_EXISTS' | 'OUTPUT_WRITE' | 'DATABASE' | 'COMMIT_UNCERTAIN';
export class ProvisioningError extends Error {
  constructor(readonly code: ProvisioningCode) { super(`Identity operation failed (${code})`); this.name = 'ProvisioningError'; }
}

/** Only an origin is accepted, so environment-file values cannot inject extra settings. */
function checkedOrigin(value: string): string {
  try {
    const url = new URL(value);
    if (!['http:', 'https:'].includes(url.protocol) || url.origin !== value || url.username || url.password || value.length > 200) throw new Error();
    return url.origin;
  } catch { throw new ProvisioningError('CONFIGURATION'); }
}

/** Generate once; replacing these secrets needs an explicit credential/key migration. */
export async function setupIdentity(input: { outputPath: string; origin: string }): Promise<void> {
  const identity = checkedOrigin(input.origin);
  await opaque.ready;
  const config = loadIdentityConfig({
    SECURITY_MASTER_KEY: randomBytes(32).toString('base64url'), SECURITY_KEY_ID: 'service-v1',
    OPAQUE_SERVER_SETUP: opaque.server.createSetup(), OPAQUE_SETUP_ID: 'opaque-v1', AUTH_SERVER_IDENTITY: identity,
  });
  let file: Awaited<ReturnType<typeof open>> | undefined;
  const outputPath = resolve(input.outputPath);
  try {
    file = await open(outputPath, 'wx', 0o600);
    await file.chmod(0o600);
    await file.writeFile(`# Persistent operational identity. Keep private; never regenerate on restart.\n${Object.entries(config).map(([key, value]) => `${key}=${value}`).join('\n')}\n`, 'utf8');
    await file.sync();
    const directory = await open(dirname(outputPath), 'r');
    try { await directory.sync(); } finally { await directory.close(); }
  } catch (error) {
    if (file) {
      await file.close().catch(() => {}); file = undefined;
      await unlink(outputPath).catch(() => {});
    }
    if ((error as { code?: string }).code === 'EEXIST') throw new ProvisioningError('OUTPUT_EXISTS');
    throw new ProvisioningError('OUTPUT_WRITE');
  } finally { await file?.close(); }
}

export async function setupIdentityMain(args: string[], environment: NodeJS.ProcessEnv = process.env): Promise<void> {
  let outputPath = '.env.identity';
  let origin = environment.APP_ORIGIN ?? 'http://localhost:3400';
  const seen = new Set<string>();
  for (let index = 0; index < args.length; index += 2) {
    const name = args[index]; const value = args[index + 1];
    if (!name || !value || !['--output', '--origin'].includes(name) || seen.has(name)) throw new ProvisioningError('USAGE');
    seen.add(name);
    if (name === '--output') outputPath = value; else origin = value;
  }
  if (environment.NODE_ENV === 'production' && !checkedOrigin(origin).startsWith('https://')) throw new ProvisioningError('CONFIGURATION');
  await setupIdentity({ outputPath, origin });
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    await setupIdentityMain(process.argv.slice(2));
    process.stdout.write('Persistent identity configuration written to the private output file\n');
  } catch (error) {
    const code = error instanceof ProvisioningError ? error.code : 'CONFIGURATION';
    process.stderr.write(`Identity setup failed (${code}); check arguments, configuration, and output permissions. Existing files are never overwritten.\n`);
    process.exitCode = 1;
  }
}
