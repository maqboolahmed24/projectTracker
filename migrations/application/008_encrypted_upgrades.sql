-- Business ciphertext upgrades are explicit signed history. Deployment SQL does
-- not decrypt, transform, or overwrite retained source representations.
ALTER TABLE app.collaboration_operations DROP CONSTRAINT collaboration_operations_entry_revision_check;
ALTER TABLE app.collaboration_operations ADD CHECK(entry_revision>0);
ALTER TABLE app.planning_operations ADD COLUMN upgrade_items jsonb
  CHECK(upgrade_items IS NULL OR jsonb_typeof(upgrade_items)='array');
CREATE TABLE app.encrypted_upgrades (
  workspace_id uuid NOT NULL REFERENCES app.workspaces(workspace_id) DEFERRABLE INITIALLY DEFERRED,
  migration_id uuid NOT NULL, source_schema integer NOT NULL CHECK(source_schema=1),
  target_schema integer NOT NULL CHECK(target_schema=2),
  transform_id text NOT NULL CHECK(transform_id='ukda.content-data.v2'),
  data_generation bigint NOT NULL CHECK(data_generation>0),
  state text NOT NULL CHECK(state IN('staged','active','completed','aborted')),
  manifest_digest text NOT NULL CHECK(manifest_digest ~ '^[0-9a-f]{64}$'),
  source_manifest jsonb NOT NULL CHECK(jsonb_typeof(source_manifest)='array'),
  signed_start jsonb NOT NULL CHECK(jsonb_typeof(signed_start)='object'),
  signed_finish jsonb CHECK(signed_finish IS NULL OR jsonb_typeof(signed_finish)='object'),
  created_at timestamptz NOT NULL, completed_at timestamptz,
  PRIMARY KEY(workspace_id,migration_id)
);
CREATE UNIQUE INDEX encrypted_upgrades_one_current ON app.encrypted_upgrades(workspace_id)
  WHERE state='active';
CREATE TABLE app.encrypted_upgrade_sources (
  workspace_id uuid NOT NULL, migration_id uuid NOT NULL, record_type text NOT NULL,
  record_id uuid NOT NULL, project_id uuid, source_revision bigint NOT NULL CHECK(source_revision>0),
  source_digest text NOT NULL CHECK(source_digest ~ '^[0-9a-f]{64}$'),
  source_reference jsonb NOT NULL CHECK(jsonb_typeof(source_reference)='object'),
  source_envelope jsonb NOT NULL CHECK(jsonb_typeof(source_envelope)='object'),
  PRIMARY KEY(workspace_id,migration_id,record_type,record_id),
  FOREIGN KEY(workspace_id,migration_id) REFERENCES app.encrypted_upgrades(workspace_id,migration_id) DEFERRABLE INITIALLY DEFERRED
);
CREATE TABLE app.encrypted_upgrade_operations (
  workspace_id uuid NOT NULL, migration_id uuid NOT NULL, operation_id uuid NOT NULL,
  actor_profile_id uuid NOT NULL, data_generation bigint NOT NULL CHECK(data_generation>0),
  request_digest text NOT NULL CHECK(request_digest ~ '^[0-9a-f]{64}$'),
  signed_operation jsonb NOT NULL CHECK(jsonb_typeof(signed_operation)='object'),
  receipt jsonb NOT NULL CHECK(jsonb_typeof(receipt)='object'), created_at timestamptz NOT NULL,
  PRIMARY KEY(workspace_id,operation_id),
  FOREIGN KEY(workspace_id,migration_id) REFERENCES app.encrypted_upgrades(workspace_id,migration_id) DEFERRABLE INITIALLY DEFERRED
);
CREATE TABLE app.encrypted_upgrade_items (
  workspace_id uuid NOT NULL, migration_id uuid NOT NULL, record_type text NOT NULL,
  record_id uuid NOT NULL, operation_id uuid NOT NULL, target_revision bigint NOT NULL CHECK(target_revision>1),
  target_digest text NOT NULL CHECK(target_digest ~ '^[0-9a-f]{64}$'),
  target_envelope jsonb NOT NULL CHECK(jsonb_typeof(target_envelope)='object'),
  signed_item jsonb NOT NULL CHECK(jsonb_typeof(signed_item)='object'),
  created_at timestamptz NOT NULL,
  PRIMARY KEY(workspace_id,migration_id,record_type,record_id,operation_id),
  FOREIGN KEY(workspace_id,migration_id,record_type,record_id)
    REFERENCES app.encrypted_upgrade_sources(workspace_id,migration_id,record_type,record_id) DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY(workspace_id,operation_id) REFERENCES app.encrypted_upgrade_operations(workspace_id,operation_id) DEFERRABLE INITIALLY DEFERRED
);
DO $policies$
DECLARE name text;
BEGIN
  FOREACH name IN ARRAY ARRAY['encrypted_upgrades','encrypted_upgrade_sources','encrypted_upgrade_operations','encrypted_upgrade_items'] LOOP
    EXECUTE format('ALTER TABLE app.%I ENABLE ROW LEVEL SECURITY',name);
    EXECUTE format('ALTER TABLE app.%I FORCE ROW LEVEL SECURITY',name);
    EXECUTE format('CREATE POLICY tenant_scope ON app.%I USING (workspace_id=app.current_workspace_id()) WITH CHECK (workspace_id=app.current_workspace_id())',name);
    EXECUTE format('REVOKE ALL ON app.%I FROM PUBLIC',name);
  END LOOP;
  FOREACH name IN ARRAY ARRAY['encrypted_upgrade_sources','encrypted_upgrade_operations','encrypted_upgrade_items'] LOOP
    EXECUTE format('CREATE TRIGGER upgrade_history_immutable BEFORE UPDATE OR DELETE ON app.%I FOR EACH ROW EXECUTE FUNCTION app.reject_history_mutation()',name);
  END LOOP;
END $policies$;
