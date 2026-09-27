-- The authority store owns only upgrade identity, restrictions and signed
-- decisions. Original/target business ciphertext and batch history stay in app.
ALTER TABLE security.workspaces ADD COLUMN active_upgrade_id uuid;
CREATE TABLE security.encrypted_upgrades (
  workspace_id uuid NOT NULL REFERENCES security.workspaces(workspace_id) ON DELETE CASCADE,
  migration_id uuid NOT NULL, source_schema integer NOT NULL CHECK(source_schema=1),
  target_schema integer NOT NULL CHECK(target_schema=2),
  transform_id text NOT NULL CHECK(transform_id='ukda.content-data.v2'),
  data_generation bigint NOT NULL CHECK(data_generation>0),
  state text NOT NULL CHECK(state IN('active','completed','aborted')),
  manifest_digest text NOT NULL CHECK(manifest_digest ~ '^[0-9a-f]{64}$'),
  signed_start jsonb NOT NULL CHECK(jsonb_typeof(signed_start)='object'),
  signed_finish jsonb CHECK(signed_finish IS NULL OR jsonb_typeof(signed_finish)='object'),
  created_at timestamptz NOT NULL, completed_at timestamptz,
  PRIMARY KEY(workspace_id,migration_id)
);
CREATE UNIQUE INDEX encrypted_upgrades_one_current ON security.encrypted_upgrades(workspace_id) WHERE state='active';
CREATE TABLE security.encrypted_upgrade_operations (
  workspace_id uuid NOT NULL, migration_id uuid NOT NULL, operation_id uuid NOT NULL,
  actor_profile_id uuid NOT NULL, data_generation bigint NOT NULL CHECK(data_generation>0),
  kind text NOT NULL CHECK(kind IN('start','finish','identity')),
  request_digest text NOT NULL CHECK(request_digest ~ '^[0-9a-f]{64}$'),
  signed_operation jsonb NOT NULL CHECK(jsonb_typeof(signed_operation)='object'),
  receipt jsonb NOT NULL CHECK(jsonb_typeof(receipt)='object'), created_at timestamptz NOT NULL,
  PRIMARY KEY(workspace_id,operation_id),
  FOREIGN KEY(workspace_id,migration_id) REFERENCES security.encrypted_upgrades(workspace_id,migration_id) DEFERRABLE INITIALLY DEFERRED
);
DO $policies$
DECLARE name text;
BEGIN
  FOREACH name IN ARRAY ARRAY['encrypted_upgrades','encrypted_upgrade_operations'] LOOP
    EXECUTE format('ALTER TABLE security.%I ENABLE ROW LEVEL SECURITY',name);
    EXECUTE format('ALTER TABLE security.%I FORCE ROW LEVEL SECURITY',name);
    EXECUTE format('CREATE POLICY tenant_workspace ON security.%I USING (workspace_id=nullif(current_setting(''ukda.workspace_id'',true),'''')::uuid) WITH CHECK (workspace_id=nullif(current_setting(''ukda.workspace_id'',true),'''')::uuid)',name);
    EXECUTE format('REVOKE ALL ON security.%I FROM PUBLIC',name);
  END LOOP;
END $policies$;
CREATE TRIGGER encrypted_upgrade_operations_immutable BEFORE UPDATE ON security.encrypted_upgrade_operations
  FOR EACH ROW EXECUTE FUNCTION security.reject_immutable_update();

-- A terminal tombstone aborts progress without reopening any maintenance fence.
CREATE FUNCTION security.abort_encrypted_upgrades_on_delete() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.lifecycle='deleted' AND OLD.lifecycle IS DISTINCT FROM NEW.lifecycle THEN
    UPDATE security.encrypted_upgrades SET state='aborted',completed_at=clock_timestamp()
      WHERE workspace_id=NEW.workspace_id AND state='active';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER abort_encrypted_upgrades AFTER UPDATE OF lifecycle ON security.workspaces
  FOR EACH ROW EXECUTE FUNCTION security.abort_encrypted_upgrades_on_delete();
