import type { FastifyInstance, FastifyRequest } from 'fastify';
import { z } from 'zod';
import type { Databases } from '../../db.js';
import { AppError } from '../../errors.js';
import { parseInput } from '../../http.js';
import { dataTransaction, type DataPrincipal } from '../../persistence.js';
import { identifier, pageQuery } from '../../shared/contracts.js';

export type RequireSession = (request: FastifyRequest) => Promise<DataPrincipal>;
const workspaceParams = z.strictObject({ workspaceId: identifier });
const projectParams = workspaceParams.extend({ projectId: identifier });
const recordTables = { phases: 'project_phases', milestones: 'milestones', tasks: 'tasks', blockers: 'blockers', comments: 'comments', updates: 'updates' } as const;
const recordsParams = projectParams.extend({ kind: z.enum(['phases', 'milestones', 'tasks', 'blockers', 'comments', 'updates']) });

/** Read-only encrypted record transport. Feature modules add explicitly authorized write actions. */
export function registerWorkReadRoutes(app: FastifyInstance, databases: Databases, requireSession: RequireSession): void {
  async function actor(request: FastifyRequest, workspaceId: string) {
    const principal = await requireSession(request);
    if (principal.workspaceId !== workspaceId) throw new AppError('NOT_FOUND', 'Workspace not available', 404);
    return principal;
  }

  app.get('/v1/workspaces/:workspaceId/projects', async (request) => {
    const params = parseInput(workspaceParams, request.params);
    const query = parseInput(pageQuery, request.query);
    const principal = await actor(request, params.workspaceId);
    return dataTransaction(databases, principal, async (client, state) => {
      const result = await client.query('SELECT * FROM app.projects WHERE workspace_id=$1 AND ($2::uuid IS NULL OR id>$2::uuid) ORDER BY id LIMIT $3', [params.workspaceId, query.after ?? null, query.limit + 1]);
      const records = result.rows.slice(0, query.limit);
      return { records, nextCursor: result.rows.length > query.limit ? records.at(-1)?.id : null, dataGeneration: state.data_generation, securityHead: state.security_head };
    });
  });
  app.get('/v1/workspaces/:workspaceId/projects/:projectId', async (request) => {
    const params = parseInput(projectParams, request.params);
    const principal = await actor(request, params.workspaceId);
    return dataTransaction(databases, principal, async (client, state) => {
      const result = await client.query('SELECT * FROM app.projects WHERE workspace_id=$1 AND id=$2', [params.workspaceId, params.projectId]);
      if (!result.rowCount) throw new AppError('NOT_FOUND', 'Project not available', 404);
      return { record: result.rows[0], dataGeneration: state.data_generation, securityHead: state.security_head };
    });
  });
  app.get('/v1/workspaces/:workspaceId/projects/:projectId/records/:kind', async (request) => {
    const params = parseInput(recordsParams, request.params);
    const query = parseInput(pageQuery, request.query);
    const principal = await actor(request, params.workspaceId);
    return dataTransaction(databases, principal, async (client, state) => {
      const project = await client.query('SELECT 1 FROM app.projects WHERE workspace_id=$1 AND id=$2', [params.workspaceId, params.projectId]);
      if (!project.rowCount) throw new AppError('NOT_FOUND', 'Project not available', 404);
      // Table name comes exclusively from this fixed map, never interpolated request text.
      const result = await client.query(`SELECT * FROM app.${recordTables[params.kind]} WHERE workspace_id=$1 AND project_id=$2 AND ($3::uuid IS NULL OR id>$3::uuid) ORDER BY id LIMIT $4`, [params.workspaceId, params.projectId, query.after ?? null, query.limit + 1]);
      const records = result.rows.slice(0, query.limit);
      return { records, nextCursor: result.rows.length > query.limit ? records.at(-1)?.id : null, dataGeneration: state.data_generation, securityHead: state.security_head };
    });
  });
}
