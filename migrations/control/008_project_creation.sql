ALTER TABLE security.staged_objects DROP CONSTRAINT staged_objects_object_kind_check;
ALTER TABLE security.staged_objects ADD CONSTRAINT staged_objects_object_kind_check CHECK
  (object_kind IN ('genesis','encrypted_workspace','encrypted_profile','encrypted_role','encrypted_project','key_envelope','custody_manifest','signed_grant'));

-- Durable creation references let a projection retry create both the project and
-- its access rows before the workspace fence opens. Private details stay opaque.
CREATE TABLE security.project_creations (
  workspace_id uuid NOT NULL REFERENCES security.workspaces(workspace_id) ON DELETE CASCADE,
  project_id uuid NOT NULL,
  operation_id uuid NOT NULL,
  project_object_id uuid NOT NULL,
  security_version bigint NOT NULL CHECK (security_version > 1),
  created_at timestamptz NOT NULL,
  PRIMARY KEY(workspace_id,project_id),
  UNIQUE(workspace_id,operation_id),
  CHECK(project_object_id=project_id),
  FOREIGN KEY(workspace_id,project_object_id) REFERENCES security.staged_objects(workspace_id,object_id) DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY(workspace_id,operation_id) REFERENCES security.staged_objects(workspace_id,object_id) DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY(workspace_id,security_version) REFERENCES security.security_transitions(workspace_id,sequence) DEFERRABLE INITIALLY DEFERRED
);
ALTER TABLE security.project_creations ENABLE ROW LEVEL SECURITY;
ALTER TABLE security.project_creations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_workspace ON security.project_creations
  USING(workspace_id=nullif(current_setting('ukda.workspace_id',true),'')::uuid)
  WITH CHECK(workspace_id=nullif(current_setting('ukda.workspace_id',true),'')::uuid);
CREATE TRIGGER project_creations_immutable BEFORE UPDATE ON security.project_creations
  FOR EACH ROW EXECUTE FUNCTION security.reject_immutable_update();
REVOKE ALL ON security.project_creations FROM PUBLIC;
