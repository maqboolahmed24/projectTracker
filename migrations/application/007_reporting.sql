-- Timezone changes preserve the original encrypted activation object and form a
-- separate immutable signed chain. Reporting caches never change business dates.
CREATE TABLE app.reporting_settings (
  workspace_id uuid PRIMARY KEY REFERENCES app.workspaces(workspace_id) DEFERRABLE INITIALLY DEFERRED,
  revision bigint NOT NULL CHECK (revision > 0), head text NOT NULL CHECK (head ~ '^[0-9a-f]{64}$'),
  timezone text NOT NULL, updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE app.reporting_preparations (
  workspace_id uuid NOT NULL REFERENCES app.workspaces(workspace_id) DEFERRABLE INITIALLY DEFERRED,
  operation_id uuid NOT NULL, actor_profile_id uuid NOT NULL, kind text NOT NULL CHECK (kind IN ('settings','summary')),
  data_generation bigint NOT NULL CHECK (data_generation > 0), binding jsonb NOT NULL CHECK (jsonb_typeof(binding)='object'),
  expires_at timestamptz NOT NULL, PRIMARY KEY(workspace_id,operation_id)
);
CREATE TABLE app.reporting_operations (
  workspace_id uuid NOT NULL REFERENCES app.workspaces(workspace_id) DEFERRABLE INITIALLY DEFERRED,
  operation_id uuid NOT NULL, actor_profile_id uuid NOT NULL, kind text NOT NULL CHECK (kind IN ('settings','summary')),
  project_ids uuid[] NOT NULL DEFAULT '{}', data_generation bigint NOT NULL CHECK (data_generation > 0),
  revision bigint NOT NULL CHECK (revision >= 0), request_digest text NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
  payload jsonb NOT NULL CHECK (jsonb_typeof(payload)='object'), receipt jsonb NOT NULL CHECK (jsonb_typeof(receipt)='object'),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(), PRIMARY KEY(workspace_id,operation_id),
  CHECK (cardinality(project_ids) <= 16), CHECK ((kind='settings' AND cardinality(project_ids)=0 AND revision>0) OR (kind='summary' AND cardinality(project_ids)>0))
);
CREATE UNIQUE INDEX reporting_settings_revision ON app.reporting_operations(workspace_id,revision) WHERE kind='settings';
CREATE TABLE app.reporting_summaries (
  workspace_id uuid NOT NULL, scope_hash text NOT NULL CHECK (scope_hash ~ '^[0-9a-f]{64}$'),
  authorization_fingerprint text NOT NULL CHECK (authorization_fingerprint ~ '^[0-9a-f]{64}$'),
  operation_id uuid NOT NULL, project_ids uuid[] NOT NULL CHECK (cardinality(project_ids) BETWEEN 1 AND 16),
  as_of_utc timestamptz NOT NULL, PRIMARY KEY(workspace_id,scope_hash,authorization_fingerprint),
  FOREIGN KEY(workspace_id,operation_id) REFERENCES app.reporting_operations(workspace_id,operation_id) DEFERRABLE INITIALLY DEFERRED
);
CREATE FUNCTION app.reporting_can_read_projects(project_ids uuid[]) RETURNS boolean LANGUAGE sql STABLE
SET search_path=pg_catalog AS $$ SELECT NOT EXISTS (SELECT 1 FROM unnest(project_ids) AS p(id) WHERE NOT app.can_read_project(p.id)) $$;
ALTER TABLE app.reporting_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.reporting_settings FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_scope ON app.reporting_settings USING (workspace_id=app.current_workspace_id()) WITH CHECK (workspace_id=app.current_workspace_id());
ALTER TABLE app.reporting_preparations ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.reporting_preparations FORCE ROW LEVEL SECURITY;
CREATE POLICY actor_scope ON app.reporting_preparations USING (workspace_id=app.current_workspace_id() AND actor_profile_id=app.current_profile_id())
  WITH CHECK (workspace_id=app.current_workspace_id() AND actor_profile_id=app.current_profile_id());
ALTER TABLE app.reporting_operations ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.reporting_operations FORCE ROW LEVEL SECURITY;
CREATE POLICY exact_projects ON app.reporting_operations USING (workspace_id=app.current_workspace_id() AND app.reporting_can_read_projects(project_ids))
  WITH CHECK (workspace_id=app.current_workspace_id() AND app.reporting_can_read_projects(project_ids));
ALTER TABLE app.reporting_summaries ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.reporting_summaries FORCE ROW LEVEL SECURITY;
CREATE POLICY exact_projects ON app.reporting_summaries USING (workspace_id=app.current_workspace_id() AND app.reporting_can_read_projects(project_ids))
  WITH CHECK (workspace_id=app.current_workspace_id() AND app.reporting_can_read_projects(project_ids));
CREATE TRIGGER reporting_operations_immutable BEFORE UPDATE OR DELETE ON app.reporting_operations FOR EACH ROW EXECUTE FUNCTION app.reject_history_mutation();
REVOKE ALL ON app.reporting_settings,app.reporting_preparations,app.reporting_operations,app.reporting_summaries FROM PUBLIC;
