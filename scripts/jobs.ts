import { pathToFileURL } from 'node:url';
import { loadConfig } from '../src/config.js';
import { createDatabases } from '../src/db.js';
import { failedJobs, jobMetrics, replayJob } from '../src/jobs.js';

/** Operator shell only, using the restricted runtime identity. No content/key access. */
export async function jobsCommand(arguments_: string[]): Promise<unknown> {
  const [command, value, extra] = arguments_;
  if (extra || !['failed', 'metrics', 'replay'].includes(command ?? '') || command === 'metrics' && value || command === 'replay' && !value)
    throw new Error('Usage: jobs failed [after-id] | metrics | replay <job-id>');
  const databases = createDatabases(loadConfig());
  try {
    if (command === 'failed') return await failedJobs(databases.application, value ? { after: value } : {});
    if (command === 'metrics') return await jobMetrics(databases.application);
    return await replayJob(databases, value!);
  } finally { await databases.close(); }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try { process.stdout.write(JSON.stringify(await jobsCommand(process.argv.slice(2)), null, 2) + '\n'); }
  catch { process.stderr.write('Job operation failed. Use: npm run jobs -- failed [after-id] | metrics | replay <job-id>\n'); process.exitCode = 1; }
}
