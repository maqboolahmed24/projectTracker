-- Independent entries do not advance the project planning head. Each retained
-- signed operation authenticates either an original post or its moderation.
CREATE TABLE app.collaboration_operations (
  workspace_id uuid NOT NULL,
  project_id uuid NOT NULL,
  operation_id uuid NOT NULL,
  entry_kind text NOT NULL CHECK (entry_kind IN ('comment','update')),
  entry_id uuid NOT NULL,
  entry_revision bigint NOT NULL CHECK (entry_revision IN (1,2)),
  data_generation bigint NOT NULL CHECK (data_generation > 0),
  request_digest text NOT NULL CHECK (request_digest ~ '^[a-f0-9]{64}$'),
  payload jsonb NOT NULL CHECK (jsonb_typeof(payload)='object'),
  receipt jsonb NOT NULL CHECK (jsonb_typeof(receipt)='object'),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (workspace_id,operation_id),
  UNIQUE (workspace_id,entry_kind,entry_id,entry_revision),
  FOREIGN KEY (workspace_id,project_id) REFERENCES app.projects(workspace_id,id) DEFERRABLE INITIALLY DEFERRED
);
CREATE INDEX collaboration_project_entries ON app.collaboration_operations(workspace_id,project_id,entry_kind,entry_id);
ALTER TABLE app.collaboration_operations ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.collaboration_operations FORCE ROW LEVEL SECURITY;
CREATE POLICY project_scope ON app.collaboration_operations
  USING (workspace_id=app.current_workspace_id() AND app.can_read_project(project_id))
  WITH CHECK (workspace_id=app.current_workspace_id() AND app.can_read_project(project_id));
CREATE TRIGGER collaboration_operations_immutable BEFORE UPDATE OR DELETE ON app.collaboration_operations
  FOR EACH ROW EXECUTE FUNCTION app.reject_history_mutation();
REVOKE ALL ON app.collaboration_operations FROM PUBLIC;
