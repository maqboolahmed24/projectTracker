-- CP12 recovery/export metadata carries no decrypted customer content.
CREATE TABLE app.export_sessions (
 workspace_id uuid NOT NULL REFERENCES app.workspaces(workspace_id) DEFERRABLE INITIALLY DEFERRED,
 export_id uuid NOT NULL, actor_profile_id uuid NOT NULL, device_id uuid NOT NULL,
 data_generation bigint NOT NULL CHECK(data_generation>0), binding jsonb NOT NULL, manifest jsonb NOT NULL,
 manifest_digest text NOT NULL CHECK(manifest_digest ~ '^[a-f0-9]{64}$'), expires_at timestamptz NOT NULL,
 finalized_at timestamptz, document_digest text CHECK(document_digest ~ '^[a-f0-9]{64}$'),
 PRIMARY KEY(workspace_id,export_id)
);
CREATE TABLE app.restorations (
 workspace_id uuid NOT NULL REFERENCES app.workspaces(workspace_id) DEFERRABLE INITIALLY DEFERRED,
 restore_id uuid NOT NULL, manifest_digest text NOT NULL CHECK(manifest_digest ~ '^[a-f0-9]{64}$'),
 checkpoint_manifest jsonb NOT NULL, state text NOT NULL CHECK(state IN('quarantined','verified','aborted')),
 missing_records jsonb NOT NULL DEFAULT '[]', reconciled_manifest jsonb, created_at timestamptz NOT NULL,
 verified_at timestamptz, PRIMARY KEY(workspace_id,restore_id)
);
CREATE TABLE app.unrecovered_projects (
 workspace_id uuid NOT NULL REFERENCES app.workspaces(workspace_id) DEFERRABLE INITIALLY DEFERRED,
 project_id uuid NOT NULL, restore_id uuid NOT NULL, reason text NOT NULL CHECK(reason='after_checkpoint'),
 PRIMARY KEY(workspace_id,project_id)
);
-- An opaque purge marker survives deletion of its application workspace.
CREATE TABLE app.lifecycle_tombstones (
 workspace_id uuid PRIMARY KEY, deleted_at timestamptz NOT NULL,
 security_head text NOT NULL CHECK(security_head ~ '^[a-f0-9]{64}$'), security_version bigint NOT NULL CHECK(security_version>0)
);
DO $policies$
DECLARE name text;
BEGIN
 FOREACH name IN ARRAY ARRAY['export_sessions','restorations','unrecovered_projects','lifecycle_tombstones'] LOOP
  EXECUTE format('ALTER TABLE app.%I ENABLE ROW LEVEL SECURITY',name);
  EXECUTE format('ALTER TABLE app.%I FORCE ROW LEVEL SECURITY',name);
  EXECUTE format('CREATE POLICY tenant_scope ON app.%I USING(workspace_id=app.current_workspace_id()) WITH CHECK(workspace_id=app.current_workspace_id())',name);
  EXECUTE format('REVOKE ALL ON app.%I FROM PUBLIC',name);
 END LOOP;
END $policies$;
CREATE TRIGGER lifecycle_tombstones_immutable BEFORE UPDATE OR DELETE ON app.lifecycle_tombstones
 FOR EACH ROW EXECUTE FUNCTION app.reject_history_mutation();

-- Deliberately SECURITY INVOKER: even blanket runtime EXECUTE grants cannot
-- confer table ownership, bypass RLS or disable immutable-history triggers.
CREATE FUNCTION app.purge_workspace_payloads(target uuid) RETURNS text[]
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE item record; table_name text; changed text[] := '{}';
BEGIN
 IF current_user::regrole <> (SELECT relowner FROM pg_class WHERE oid='app.workspaces'::regclass) THEN
  RAISE EXCEPTION 'Privileged maintenance identity required' USING ERRCODE='42501';
 END IF;
 PERFORM set_config('row_security','off',true);
 PERFORM set_config('ukda.workspace_id',target::text,true);
 IF NOT EXISTS(SELECT 1 FROM app.lifecycle_tombstones WHERE workspace_id=target) THEN
  RAISE EXCEPTION 'Deletion tombstone required';
 END IF;
 SET CONSTRAINTS ALL DEFERRED;
 FOR item IN SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
  WHERE n.nspname='app' AND c.relkind='r' AND c.relname<>'lifecycle_tombstones'
   AND EXISTS(SELECT 1 FROM pg_attribute a WHERE a.attrelid=c.oid AND a.attname='workspace_id' AND NOT a.attisdropped) LOOP
  EXECUTE format('ALTER TABLE app.%I DISABLE TRIGGER USER',item.relname);
 END LOOP;
 FOR item IN SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
  WHERE n.nspname='app' AND c.relkind='r' AND c.relname<>'lifecycle_tombstones'
   AND EXISTS(SELECT 1 FROM pg_attribute a WHERE a.attrelid=c.oid AND a.attname='workspace_id' AND NOT a.attisdropped)
  ORDER BY (c.relname='workspaces'),c.relname LOOP
  EXECUTE format('DELETE FROM app.%I WHERE workspace_id=$1',item.relname) USING target;
  changed:=array_append(changed,'app.'||item.relname);
 END LOOP;
 FOREACH table_name IN ARRAY changed LOOP EXECUTE format('ALTER TABLE %s ENABLE TRIGGER USER',table_name); END LOOP;
 DELETE FROM graphile_worker._private_jobs WHERE payload->>'workspaceId'=target::text;
 RETURN array_append(changed,'graphile_worker._private_jobs');
END $$;
