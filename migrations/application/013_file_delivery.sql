CREATE TABLE app.file_delivery_batches (
 workspace_id uuid NOT NULL,project_id uuid NOT NULL,id uuid NOT NULL,data_generation bigint NOT NULL CHECK(data_generation>0),
 creator_profile_id uuid NOT NULL,frozen_digest text NOT NULL CHECK(frozen_digest ~ '^[a-f0-9]{64}$'),signed_batch jsonb NOT NULL,
 state text NOT NULL CHECK(state IN('frozen','confirmed','cancelled','superseded','published')),confirmation jsonb,publication jsonb,
 package_downloads integer NOT NULL DEFAULT 0 CHECK(package_downloads>=0),created_at timestamptz NOT NULL,
 PRIMARY KEY(workspace_id,id),UNIQUE(workspace_id,project_id,id),FOREIGN KEY(workspace_id,project_id) REFERENCES app.projects(workspace_id,id) DEFERRABLE INITIALLY DEFERRED
);
CREATE TABLE app.file_delivery_operations (
 workspace_id uuid NOT NULL,project_id uuid NOT NULL,operation_id uuid NOT NULL,data_generation bigint NOT NULL CHECK(data_generation>0),
 actor_profile_id uuid NOT NULL,request_digest text NOT NULL CHECK(request_digest ~ '^[a-f0-9]{64}$'),payload jsonb NOT NULL,receipt jsonb NOT NULL,created_at timestamptz NOT NULL,
 PRIMARY KEY(workspace_id,operation_id),FOREIGN KEY(workspace_id,project_id) REFERENCES app.projects(workspace_id,id) DEFERRABLE INITIALLY DEFERRED
);
CREATE TABLE app.file_service_pairings (
 workspace_id uuid NOT NULL,project_id uuid NOT NULL,id uuid NOT NULL,service_id uuid NOT NULL,public_key text NOT NULL,
 account_id uuid NOT NULL,device_id uuid NOT NULL,data_generation bigint NOT NULL CHECK(data_generation>0),nonce text NOT NULL,
 expires_at timestamptz NOT NULL,used_at timestamptz,created_at timestamptz NOT NULL,
 PRIMARY KEY(workspace_id,id),FOREIGN KEY(workspace_id,project_id) REFERENCES app.projects(workspace_id,id) DEFERRABLE INITIALLY DEFERRED
);
CREATE TABLE app.file_local_services (
 workspace_id uuid NOT NULL,project_id uuid NOT NULL,id uuid NOT NULL,public_key text NOT NULL,data_generation bigint NOT NULL CHECK(data_generation>0),
 approved_pairing jsonb NOT NULL,state text NOT NULL CHECK(state IN('active','revoked')),created_at timestamptz NOT NULL,
 PRIMARY KEY(workspace_id,project_id,id),FOREIGN KEY(workspace_id,project_id) REFERENCES app.projects(workspace_id,id) DEFERRABLE INITIALLY DEFERRED
);
CREATE TABLE app.file_delivery_permits (
 workspace_id uuid NOT NULL,project_id uuid NOT NULL,id uuid NOT NULL,batch_id uuid NOT NULL,service_id uuid NOT NULL,
 item_index smallint NOT NULL CHECK(item_index BETWEEN 0 AND 63),signed_permit jsonb NOT NULL,issued_at timestamptz NOT NULL,expires_at timestamptz NOT NULL,used_at timestamptz,
 PRIMARY KEY(workspace_id,id),FOREIGN KEY(workspace_id,project_id,batch_id) REFERENCES app.file_delivery_batches(workspace_id,project_id,id) DEFERRABLE INITIALLY DEFERRED,
 FOREIGN KEY(workspace_id,project_id,service_id) REFERENCES app.file_local_services(workspace_id,project_id,id) DEFERRABLE INITIALLY DEFERRED
);
CREATE INDEX delivery_project_batches ON app.file_delivery_batches(workspace_id,project_id,id);
DO $policies$
DECLARE name text;
BEGIN
 FOREACH name IN ARRAY ARRAY['file_delivery_batches','file_delivery_operations','file_service_pairings','file_local_services','file_delivery_permits'] LOOP
  EXECUTE format('ALTER TABLE app.%I ENABLE ROW LEVEL SECURITY',name);
  EXECUTE format('ALTER TABLE app.%I FORCE ROW LEVEL SECURITY',name);
  EXECUTE format('CREATE POLICY project_scope ON app.%I USING(workspace_id=app.current_workspace_id() AND app.can_read_project(project_id)) WITH CHECK(workspace_id=app.current_workspace_id() AND app.can_read_project(project_id))',name);
  EXECUTE format('REVOKE ALL ON app.%I FROM PUBLIC',name);
 END LOOP;
END $policies$;
CREATE FUNCTION app.protect_delivery_batch() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF TG_OP='DELETE' OR (to_jsonb(NEW)-'state'-'confirmation'-'publication'-'package_downloads')<>(to_jsonb(OLD)-'state'-'confirmation'-'publication'-'package_downloads') THEN
  RAISE EXCEPTION 'Delivery manifests are immutable' USING ERRCODE='55000';
 END IF;RETURN NEW;
END $$;
CREATE TRIGGER delivery_batches_immutable BEFORE UPDATE OR DELETE ON app.file_delivery_batches FOR EACH ROW EXECUTE FUNCTION app.protect_delivery_batch();
CREATE TRIGGER delivery_operations_immutable BEFORE UPDATE OR DELETE ON app.file_delivery_operations FOR EACH ROW EXECUTE FUNCTION app.reject_history_mutation();
