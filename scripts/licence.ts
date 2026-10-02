import { randomUUID } from 'node:crypto';
import { open, unlink } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import pg from 'pg';
import { loadConfig } from '../src/config.js';
import { createDatabases } from '../src/db.js';
import { AppError } from '../src/errors.js';
import { EntitlementOperations, type EntitlementResult } from '../src/modules/identity/entitlements.js';
import { loadIdentityConfig, ServiceSecrets } from '../src/modules/identity/secrets.js';
import { identifier } from '../src/shared/contracts.js';
import { ProvisioningError } from './setup-identity.js';

/**
 * The only plaintext licence key is its private output file. Persist that file
 * before committing issuance so a lost COMMIT response never loses the key.
 */
export async function issueLicenceToFile(input: { pool: pg.Pool; secrets: ServiceSecrets; outputPath: string }): Promise<{ licenceId: string }> {
  const outputPath = resolve(input.outputPath);
  let file: Awaited<ReturnType<typeof open>>;
  try { file = await open(outputPath, 'wx', 0o600); }
  catch (error) { throw new ProvisioningError((error as { code?: string }).code === 'EEXIST' ? 'OUTPUT_EXISTS' : 'OUTPUT_WRITE'); }
  let client: pg.PoolClient | undefined;
  let transactionOpen = false;
  let commitStarted = false;
  let phase: 'OUTPUT_WRITE' | 'DATABASE' = 'OUTPUT_WRITE';
  const disconnected = () => {};
  try {
    await file.chmod(0o600);
    phase = 'DATABASE';
    client = await input.pool.connect();
    client.on('error', disconnected);
    await client.query('BEGIN'); transactionOpen = true;
    const licenceId = randomUUID();
    const licenceKey = `LIC-${input.secrets.token()}`;
    await client.query(`INSERT INTO security.licences (licence_id, verification_digest, verification_key_id, state)
      VALUES ($1, $2, $3, 'available')`, [licenceId, input.secrets.digest('licence', licenceKey), input.secrets.keyId]);
    phase = 'OUTPUT_WRITE';
    await file.writeFile(`${JSON.stringify({ licenceId, licenceKey }, null, 2)}\n`, 'utf8');
    await file.sync();
    const directory = await open(dirname(outputPath), 'r');
    try { await directory.sync(); } finally { await directory.close(); }
    // Release the file before COMMIT so even a close error can still roll back safely.
    await file.close();
    phase = 'DATABASE'; commitStarted = true;
    await client.query('COMMIT'); transactionOpen = false;
    return { licenceId };
  } catch {
    if (transactionOpen) await client?.query('ROLLBACK').catch(() => {});
    await file.close().catch(() => {});
    if (!commitStarted) await unlink(outputPath).catch(() => {});
    // A connection can fail after the server commits. Retain the synced key file
    // and its licence ID for inspection; blindly issuing a replacement is unsafe.
    throw new ProvisioningError(commitStarted ? 'COMMIT_UNCERTAIN' : phase);
  } finally { client?.release(); client?.removeListener('error', disconnected); }
}

export async function licenceMain(args: string[], environment: NodeJS.ProcessEnv = process.env): Promise<{ kind: 'issued' } | { kind: 'changed'; result: EntitlementResult }> {
  const actions = { revoke: 'revoke', 'legacy-expire': 'legacy_expire', reinstate: 'reinstate' } as const;
  const command = args[0];
  let change: { licenceId: string; operationId: string; operatorId: string; action: 'revoke' | 'legacy_expire' | 'reinstate' } | undefined;
  if (command === 'issue') {
    if (args.length !== 3 || args[1] !== '--output' || !args[2]) throw new ProvisioningError('USAGE');
  } else {
    if (!command || !Object.hasOwn(actions, command) || args.length !== 7) throw new ProvisioningError('USAGE');
    const flags: Record<string, string> = {};
    for (let index = 1; index < args.length; index += 2) {
      const flag = args[index]; const value = args[index + 1];
      if (!flag || !value || !['--licence-id', '--operation-id', '--operator-id'].includes(flag) || flags[flag] || !identifier.safeParse(value).success) throw new ProvisioningError('USAGE');
      flags[flag] = value;
    }
    change = { licenceId: flags['--licence-id']!, operationId: flags['--operation-id']!, operatorId: flags['--operator-id']!, action: actions[command as keyof typeof actions] };
  }
  let config: ReturnType<typeof loadConfig>;
  let secrets: ServiceSecrets;
  try { config = loadConfig(environment); secrets = new ServiceSecrets(loadIdentityConfig(environment)); }
  catch { throw new ProvisioningError('CONFIGURATION'); }
  if (change) {
    const databases = createDatabases(config);
    try {
      const { operatorId, ...request } = change;
      return { kind: 'changed', result: await new EntitlementOperations(databases, secrets).change(request, { operatorId }) };
    } finally { await databases.close(); }
  }
  const pool = new pg.Pool({ connectionString: config.CONTROL_DATABASE_URL, connectionTimeoutMillis: 3000, statement_timeout: 15_000, max: 1 });
  pool.on('error', () => {});
  try { await issueLicenceToFile({ pool, secrets, outputPath: args[2]! }); return { kind: 'issued' }; }
  finally { await pool.end(); }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const result = await licenceMain(process.argv.slice(2));
    process.stdout.write(result.kind === 'issued' ? 'Licence issued to the private output file\n' : `${JSON.stringify(result.result)}\n`);
  } catch (error) {
    const code = error instanceof ProvisioningError ? error.code : error instanceof AppError ? error.code : 'DATABASE';
    process.stderr.write(code === 'COMMIT_UNCERTAIN'
      ? 'Licence issuance status is uncertain. The private output file was retained; verify its licence ID before retrying.\n'
      : `Licence operation failed (${code}); check arguments, configuration, database access, and output permissions. Existing files are never overwritten.\n`);
    process.exitCode = 1;
  }
}
