-- Short-lived signed grants authorise an organisation-controlled editor bridge;
-- file plaintext remains local and saved revisions use the encrypted file API.
CREATE TABLE app.file_editor_permits (
 workspace_id uuid NOT NULL,project_id uuid NOT NULL,id uuid NOT NULL,version_id uuid NOT NULL,service_id uuid NOT NULL,
 actor_profile_id uuid NOT NULL,device_id uuid NOT NULL,signed_permit jsonb NOT NULL,issued_at timestamptz NOT NULL,expires_at timestamptz NOT NULL,
 PRIMARY KEY(workspace_id,id),FOREIGN KEY(workspace_id,project_id,version_id) REFERENCES app.file_versions(workspace_id,project_id,id) DEFERRABLE INITIALLY DEFERRED,
 FOREIGN KEY(workspace_id,project_id,service_id) REFERENCES app.file_local_services(workspace_id,project_id,id) DEFERRABLE INITIALLY DEFERRED
);
ALTER TABLE app.file_editor_permits ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.file_editor_permits FORCE ROW LEVEL SECURITY;
CREATE POLICY project_scope ON app.file_editor_permits USING(workspace_id=app.current_workspace_id() AND app.can_read_project(project_id)) WITH CHECK(workspace_id=app.current_workspace_id() AND app.can_read_project(project_id));
CREATE TRIGGER file_editor_permits_immutable BEFORE UPDATE OR DELETE ON app.file_editor_permits FOR EACH ROW EXECUTE FUNCTION app.reject_history_mutation();
REVOKE ALL ON app.file_editor_permits FROM PUBLIC;
