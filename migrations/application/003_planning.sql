-- A complete signed project-local chain binds child-set completeness. Content and
-- closing narratives stay encrypted in record_versions/audit_events/updates.
CREATE TABLE app.project_planning_heads (
  workspace_id uuid NOT NULL,
  project_id uuid NOT NULL,
  planning_version bigint NOT NULL CHECK (planning_version > 0),
  planning_head text NOT NULL CHECK (planning_head ~ '^[a-f0-9]{64}$'),
  graph_digest text NOT NULL CHECK (graph_digest ~ '^[a-f0-9]{64}$'),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(workspace_id,project_id),
  FOREIGN KEY(workspace_id,project_id) REFERENCES app.projects(workspace_id,id) DEFERRABLE INITIALLY DEFERRED
);
CREATE TABLE app.planning_operations (
  workspace_id uuid NOT NULL,
  project_id uuid NOT NULL,
  operation_id uuid NOT NULL,
  data_generation bigint NOT NULL CHECK(data_generation>0),
  planning_version bigint NOT NULL CHECK(planning_version>0),
  request_digest text NOT NULL CHECK(request_digest ~ '^[a-f0-9]{64}$'),
  signed_mutation jsonb NOT NULL CHECK(jsonb_typeof(signed_mutation)='object'),
  closing_snapshot jsonb CHECK(closing_snapshot IS NULL OR jsonb_typeof(closing_snapshot)='object'),
  movements jsonb NOT NULL CHECK(jsonb_typeof(movements)='array'),
  receipt jsonb NOT NULL CHECK(jsonb_typeof(receipt)='object'),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(workspace_id,operation_id),
  UNIQUE(workspace_id,project_id,planning_version),
  FOREIGN KEY(workspace_id,project_id) REFERENCES app.projects(workspace_id,id) DEFERRABLE INITIALLY DEFERRED
);
CREATE TRIGGER planning_operations_immutable BEFORE UPDATE OR DELETE ON app.planning_operations
  FOR EACH ROW EXECUTE FUNCTION app.reject_history_mutation();
DO $policies$
DECLARE table_name text;
BEGIN
  FOREACH table_name IN ARRAY ARRAY['project_planning_heads','planning_operations'] LOOP
    EXECUTE format('ALTER TABLE app.%I ENABLE ROW LEVEL SECURITY',table_name);
    EXECUTE format('ALTER TABLE app.%I FORCE ROW LEVEL SECURITY',table_name);
    EXECUTE format('CREATE POLICY project_scope ON app.%I USING (workspace_id=app.current_workspace_id() AND app.can_read_project(project_id)) WITH CHECK (workspace_id=app.current_workspace_id() AND app.can_read_project(project_id))',table_name);
  END LOOP;
END
$policies$;
REVOKE ALL ON app.project_planning_heads,app.planning_operations FROM PUBLIC;
