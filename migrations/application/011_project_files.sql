-- Managed bytes are ciphertext in PostgreSQL WAL. The existing encrypted backup,
-- archive, PITR and tenant deletion protocols therefore cover the same commit.
CREATE TABLE app.project_files (
 workspace_id uuid NOT NULL,project_id uuid NOT NULL,id uuid NOT NULL,
 kind text NOT NULL CHECK(kind IN('source','output')),latest_version_id uuid,
 created_at timestamptz NOT NULL,PRIMARY KEY(workspace_id,id),UNIQUE(workspace_id,project_id,id),
 FOREIGN KEY(workspace_id,project_id) REFERENCES app.projects(workspace_id,id) DEFERRABLE INITIALLY DEFERRED
);
CREATE TABLE app.file_versions (
 workspace_id uuid NOT NULL,project_id uuid NOT NULL,file_id uuid NOT NULL,id uuid NOT NULL,
 version bigint NOT NULL CHECK(version>0),data_generation bigint NOT NULL CHECK(data_generation>0),
 author_profile_id uuid NOT NULL,author_device_id uuid NOT NULL,storage text NOT NULL CHECK(storage IN('managed','external')),
 state text NOT NULL CHECK(state IN('staged','ready','cancelled')),
 reserved_bytes bigint NOT NULL CHECK(reserved_bytes BETWEEN 16 AND 26251264),
 manifest jsonb NOT NULL CHECK(jsonb_typeof(manifest)='object'),created_at timestamptz NOT NULL,
 expires_at timestamptz NOT NULL,completed_at timestamptz,
 PRIMARY KEY(workspace_id,id),UNIQUE(workspace_id,project_id,file_id,version),
 UNIQUE(workspace_id,project_id,file_id,id),
 FOREIGN KEY(workspace_id,project_id,file_id) REFERENCES app.project_files(workspace_id,project_id,id) DEFERRABLE INITIALLY DEFERRED
);
ALTER TABLE app.project_files ADD CONSTRAINT project_file_latest_version FOREIGN KEY(workspace_id,project_id,id,latest_version_id)
 REFERENCES app.file_versions(workspace_id,project_id,file_id,id) DEFERRABLE INITIALLY DEFERRED;
CREATE TABLE app.file_chunks (
 workspace_id uuid NOT NULL,project_id uuid NOT NULL,version_id uuid NOT NULL,chunk_index smallint NOT NULL CHECK(chunk_index BETWEEN 0 AND 99),
 cipher_bytes bytea NOT NULL CHECK(octet_length(cipher_bytes) BETWEEN 41 AND 262184),
 cipher_digest text NOT NULL CHECK(cipher_digest ~ '^[a-f0-9]{64}$'),created_at timestamptz NOT NULL,
 PRIMARY KEY(workspace_id,version_id,chunk_index),
 FOREIGN KEY(workspace_id,version_id) REFERENCES app.file_versions(workspace_id,id) ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED
);
CREATE TABLE app.file_upload_reservations (
 workspace_id uuid NOT NULL,project_id uuid NOT NULL,version_id uuid NOT NULL,reserved_bytes bigint NOT NULL CHECK(reserved_bytes>0),
 expires_at timestamptz NOT NULL,PRIMARY KEY(workspace_id,version_id),
 FOREIGN KEY(workspace_id,version_id) REFERENCES app.file_versions(workspace_id,id) ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED
);
CREATE TABLE app.file_storage_usage (
 workspace_id uuid PRIMARY KEY REFERENCES app.workspaces(workspace_id) DEFERRABLE INITIALLY DEFERRED,
 used_bytes bigint NOT NULL DEFAULT 0 CHECK(used_bytes>=0),reserved_bytes bigint NOT NULL DEFAULT 0 CHECK(reserved_bytes>=0),
 active_uploads integer NOT NULL DEFAULT 0 CHECK(active_uploads BETWEEN 0 AND 4)
);
CREATE TABLE app.task_file_links (
 workspace_id uuid NOT NULL,project_id uuid NOT NULL,task_id uuid NOT NULL,file_id uuid NOT NULL,
 mode text NOT NULL CHECK(mode IN('latest','pinned')),version_id uuid,
 CHECK((mode='pinned')=(version_id IS NOT NULL)),PRIMARY KEY(workspace_id,task_id,file_id),
 FOREIGN KEY(workspace_id,project_id,task_id) REFERENCES app.tasks(workspace_id,project_id,id) DEFERRABLE INITIALLY DEFERRED,
 FOREIGN KEY(workspace_id,project_id,file_id) REFERENCES app.project_files(workspace_id,project_id,id) DEFERRABLE INITIALLY DEFERRED,
 FOREIGN KEY(workspace_id,project_id,file_id,version_id) REFERENCES app.file_versions(workspace_id,project_id,file_id,id) DEFERRABLE INITIALLY DEFERRED
);
CREATE TABLE app.file_operations (
 workspace_id uuid NOT NULL,project_id uuid NOT NULL,operation_id uuid NOT NULL,data_generation bigint NOT NULL CHECK(data_generation>0),
 actor_profile_id uuid NOT NULL,request_digest text NOT NULL CHECK(request_digest ~ '^[a-f0-9]{64}$'),
 payload jsonb NOT NULL CHECK(jsonb_typeof(payload)='object'),receipt jsonb NOT NULL CHECK(jsonb_typeof(receipt)='object'),created_at timestamptz NOT NULL,
 PRIMARY KEY(workspace_id,operation_id),FOREIGN KEY(workspace_id,project_id) REFERENCES app.projects(workspace_id,id) DEFERRABLE INITIALLY DEFERRED
);
CREATE INDEX file_project_versions ON app.file_versions(workspace_id,project_id,file_id,version);
CREATE INDEX file_expired_reservations ON app.file_upload_reservations(workspace_id,expires_at);
CREATE INDEX task_files_project ON app.task_file_links(workspace_id,project_id,task_id);
DO $policies$
DECLARE name text;
BEGIN
 FOREACH name IN ARRAY ARRAY['project_files','file_versions','file_chunks','task_file_links','file_operations'] LOOP
  EXECUTE format('ALTER TABLE app.%I ENABLE ROW LEVEL SECURITY',name);
  EXECUTE format('ALTER TABLE app.%I FORCE ROW LEVEL SECURITY',name);
  EXECUTE format('CREATE POLICY project_scope ON app.%I USING(workspace_id=app.current_workspace_id() AND app.can_read_project(project_id)) WITH CHECK(workspace_id=app.current_workspace_id() AND app.can_read_project(project_id))',name);
  EXECUTE format('REVOKE ALL ON app.%I FROM PUBLIC',name);
 END LOOP;
 FOREACH name IN ARRAY ARRAY['file_upload_reservations','file_storage_usage'] LOOP
  EXECUTE format('ALTER TABLE app.%I ENABLE ROW LEVEL SECURITY',name);
  EXECUTE format('ALTER TABLE app.%I FORCE ROW LEVEL SECURITY',name);
  EXECUTE format('CREATE POLICY tenant_scope ON app.%I USING(workspace_id=app.current_workspace_id()) WITH CHECK(workspace_id=app.current_workspace_id())',name);
  EXECUTE format('REVOKE ALL ON app.%I FROM PUBLIC',name);
 END LOOP;
END $policies$;
-- The service exposes only the numeric aggregate, never another tenant identity.
-- Serialized quota admission needs the deployment total, including retained bytes.
CREATE POLICY deployment_capacity ON app.file_storage_usage FOR SELECT USING(true);
-- Staged uploads may be collected after expiry even if the initiating project
-- grant was removed. Ready versions can never match this cleanup policy.
CREATE POLICY expired_staging_cleanup ON app.file_versions FOR DELETE USING(
 workspace_id=app.current_workspace_id() AND state='staged' AND expires_at<=clock_timestamp());
CREATE FUNCTION app.protect_file_version() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF OLD.state='ready' OR (TG_OP='UPDATE' AND (NEW.state NOT IN('ready','cancelled') OR
   (to_jsonb(NEW)-'state'-'completed_at')<>(to_jsonb(OLD)-'state'-'completed_at'))) THEN
  RAISE EXCEPTION 'File versions are immutable' USING ERRCODE='55000';
 END IF;
 IF TG_OP='DELETE' THEN RETURN OLD; END IF;RETURN NEW;
END $$;
CREATE TRIGGER file_versions_immutable BEFORE UPDATE OR DELETE ON app.file_versions FOR EACH ROW EXECUTE FUNCTION app.protect_file_version();
CREATE FUNCTION app.protect_file_chunk() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF TG_OP='UPDATE' OR EXISTS(SELECT 1 FROM app.file_versions WHERE workspace_id=OLD.workspace_id AND id=OLD.version_id AND state='ready') THEN
  RAISE EXCEPTION 'File chunks are immutable' USING ERRCODE='55000';
 END IF;RETURN OLD;
END $$;
CREATE TRIGGER file_chunks_immutable BEFORE UPDATE OR DELETE ON app.file_chunks FOR EACH ROW EXECUTE FUNCTION app.protect_file_chunk();
CREATE TRIGGER file_operations_immutable BEFORE UPDATE OR DELETE ON app.file_operations FOR EACH ROW EXECUTE FUNCTION app.reject_history_mutation();
