ALTER TABLE security.workspaces ADD COLUMN active_deletion_operation_id uuid;
ALTER TABLE security.workspaces ADD COLUMN active_restore_id uuid;
CREATE TABLE security.recovery_health (
 id boolean PRIMARY KEY CHECK(id), measured_at timestamptz NOT NULL, metrics jsonb NOT NULL CHECK(jsonb_typeof(metrics)='object')
);
CREATE FUNCTION security.guard_recovery_health() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF current_user::regrole<>(SELECT relowner FROM pg_class WHERE oid='security.recovery_health'::regclass) THEN
  RAISE EXCEPTION 'Privileged maintenance identity required' USING ERRCODE='42501';
 END IF;
 IF TG_OP='DELETE' THEN RETURN OLD; END IF; RETURN NEW;
END $$;
CREATE TRIGGER recovery_health_privileged BEFORE INSERT OR UPDATE OR DELETE ON security.recovery_health
 FOR EACH ROW EXECUTE FUNCTION security.guard_recovery_health();
CREATE TABLE security.content_checkpoints (
 workspace_id uuid NOT NULL REFERENCES security.workspaces(workspace_id) ON DELETE CASCADE,
 checkpoint_id uuid NOT NULL, manifest_digest text NOT NULL CHECK(manifest_digest ~ '^[a-f0-9]{64}$'),
 manifest jsonb NOT NULL, created_at timestamptz NOT NULL, PRIMARY KEY(workspace_id,checkpoint_id)
);
CREATE TABLE security.restorations (
 workspace_id uuid NOT NULL REFERENCES security.workspaces(workspace_id) ON DELETE CASCADE,
 restore_id uuid NOT NULL, manifest_digest text NOT NULL CHECK(manifest_digest ~ '^[a-f0-9]{64}$'),
 checkpoint_manifest jsonb NOT NULL, request_digest text NOT NULL CHECK(request_digest ~ '^[a-f0-9]{64}$'),
 signed_start jsonb NOT NULL, verification jsonb, state text NOT NULL CHECK(state IN('quarantined','verified','aborted')),
 missing_records jsonb NOT NULL DEFAULT '[]', reconciled_manifest jsonb, created_at timestamptz NOT NULL,
 verified_at timestamptz, PRIMARY KEY(workspace_id,restore_id)
);
CREATE TABLE security.erasure_requests (
 workspace_id uuid NOT NULL REFERENCES security.workspaces(workspace_id) ON DELETE CASCADE,
 request_id uuid NOT NULL, profile_id uuid NOT NULL, signed_request jsonb NOT NULL,
 state text NOT NULL CHECK(state IN('requested','fulfilled')), requested_at timestamptz NOT NULL,
 fulfilled_at timestamptz, PRIMARY KEY(workspace_id,request_id)
);
CREATE UNIQUE INDEX erasure_requests_one_current ON security.erasure_requests(workspace_id,profile_id) WHERE state='requested';
-- No FK: only opaque retirement/retention evidence survives a payload purge.
CREATE TABLE security.workspace_purges (
 workspace_id uuid PRIMARY KEY, deletion_deadline timestamptz NOT NULL,
 final_head text NOT NULL CHECK(final_head ~ '^[a-f0-9]{64}$'), final_security_version bigint NOT NULL CHECK(final_security_version>0),
 logical_payloads_deleted_at timestamptz, live_payloads_purged_at timestamptz, backup_expires_at timestamptz,
 CHECK(live_payloads_purged_at IS NULL OR logical_payloads_deleted_at IS NOT NULL AND live_payloads_purged_at>=logical_payloads_deleted_at),
 CHECK((backup_expires_at IS NULL)=(live_payloads_purged_at IS NULL)),
 CHECK(backup_expires_at IS NULL OR backup_expires_at<=live_payloads_purged_at+interval '30 days')
);
CREATE TABLE security.retired_security_links (
 workspace_id uuid NOT NULL, sequence bigint NOT NULL, previous_head text NOT NULL, head text NOT NULL,
 PRIMARY KEY(workspace_id,sequence)
);
DO $policies$
DECLARE name text;
BEGIN
 FOREACH name IN ARRAY ARRAY['content_checkpoints','restorations','erasure_requests','workspace_purges','retired_security_links'] LOOP
  EXECUTE format('ALTER TABLE security.%I ENABLE ROW LEVEL SECURITY',name);
  EXECUTE format('ALTER TABLE security.%I FORCE ROW LEVEL SECURITY',name);
  EXECUTE format('CREATE POLICY tenant_workspace ON security.%I USING(workspace_id=nullif(current_setting(''ukda.workspace_id'',true),'''')::uuid) WITH CHECK(workspace_id=nullif(current_setting(''ukda.workspace_id'',true),'''')::uuid)',name);
  EXECUTE format('REVOKE ALL ON security.%I FROM PUBLIC',name);
 END LOOP;
END $policies$;
CREATE TRIGGER content_checkpoints_immutable BEFORE UPDATE ON security.content_checkpoints
 FOR EACH ROW EXECUTE FUNCTION security.reject_immutable_update();
CREATE TRIGGER retired_security_links_immutable BEFORE UPDATE OR DELETE ON security.retired_security_links
 FOR EACH ROW EXECUTE FUNCTION security.reject_immutable_update();
CREATE FUNCTION security.retire_removed_profile() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.state='removed' AND OLD.state<>'removed' THEN
  INSERT INTO security.deletion_tombstones(workspace_id,entity_kind,entity_id,deleted_at,security_version)
   SELECT NEW.workspace_id,'profile',NEW.profile_id,NEW.removed_at,GREATEST(security_version,1) FROM security.workspaces WHERE workspace_id=NEW.workspace_id
   ON CONFLICT DO NOTHING;
  UPDATE security.erasure_requests SET state='fulfilled',fulfilled_at=NEW.removed_at
   WHERE workspace_id=NEW.workspace_id AND profile_id=NEW.profile_id AND state='requested';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER profile_retirement AFTER UPDATE OF state ON security.profiles FOR EACH ROW EXECUTE FUNCTION security.retire_removed_profile();
CREATE FUNCTION security.reject_retired_identity() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF EXISTS(SELECT 1 FROM security.deletion_tombstones WHERE workspace_id=NEW.workspace_id AND
   (entity_kind='workspace' OR entity_kind='profile' AND entity_id=NEW.profile_id)) THEN
  RAISE EXCEPTION 'Identity permanently retired' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER profile_not_retired BEFORE INSERT ON security.profiles FOR EACH ROW EXECUTE FUNCTION security.reject_retired_identity();
CREATE FUNCTION security.reject_retired_workspace() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF EXISTS(SELECT 1 FROM security.deletion_tombstones WHERE workspace_id=NEW.workspace_id AND entity_kind='workspace') THEN
  RAISE EXCEPTION 'Workspace permanently retired' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER workspace_not_retired BEFORE INSERT ON security.workspaces FOR EACH ROW EXECUTE FUNCTION security.reject_retired_workspace();

CREATE FUNCTION security.purge_workspace_payloads(target uuid) RETURNS text[]
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE item record; table_name text; changed text[] := '{}'; licence uuid;
BEGIN
 IF current_user::regrole <> (SELECT relowner FROM pg_class WHERE oid='security.workspaces'::regclass) THEN
  RAISE EXCEPTION 'Privileged maintenance identity required' USING ERRCODE='42501';
 END IF;
 PERFORM set_config('row_security','off',true);
 PERFORM set_config('ukda.workspace_id',target::text,true);
 IF NOT EXISTS(SELECT 1 FROM security.deletion_tombstones WHERE workspace_id=target AND entity_kind='workspace') THEN
  RAISE EXCEPTION 'Deletion tombstone required';
 END IF;
 SELECT licence_id INTO licence FROM security.licences WHERE activated_workspace_id=target;
 INSERT INTO security.retired_security_links SELECT workspace_id,sequence,previous_head,head FROM security.security_transitions
  WHERE workspace_id=target ON CONFLICT DO NOTHING;
 SET CONSTRAINTS ALL DEFERRED;
 FOR item IN SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
  WHERE n.nspname='security' AND c.relkind='r' AND c.relname NOT IN('deletion_tombstones','workspace_purges','retired_security_links')
   AND EXISTS(SELECT 1 FROM pg_attribute a WHERE a.attrelid=c.oid AND a.attname='workspace_id' AND NOT a.attisdropped) LOOP
  EXECUTE format('ALTER TABLE security.%I DISABLE TRIGGER USER',item.relname);
 END LOOP;
 -- Operational entitlement receipts also carry workspace-specific journal payloads.
 DELETE FROM security.entitlement_operations WHERE licence_id=licence;
 changed:=array_append(changed,'security.entitlement_operations');
 FOR item IN SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
  WHERE n.nspname='security' AND c.relkind='r' AND c.relname NOT IN('deletion_tombstones','workspace_purges','retired_security_links')
   AND EXISTS(SELECT 1 FROM pg_attribute a WHERE a.attrelid=c.oid AND a.attname='workspace_id' AND NOT a.attisdropped)
  ORDER BY (c.relname='workspaces'),c.relname LOOP
  EXECUTE format('DELETE FROM security.%I WHERE workspace_id=$1',item.relname) USING target;
  changed:=array_append(changed,'security.'||item.relname);
 END LOOP;
 FOREACH table_name IN ARRAY changed LOOP
  IF table_name<>'security.entitlement_operations' THEN EXECUTE format('ALTER TABLE %s ENABLE TRIGGER USER',table_name); END IF;
 END LOOP;
 UPDATE security.workspace_purges SET logical_payloads_deleted_at=coalesce(logical_payloads_deleted_at,clock_timestamp()) WHERE workspace_id=target;
 RETURN changed;
END $$;
CREATE FUNCTION security.complete_physical_purge(target uuid) RETURNS void
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE completed timestamptz := clock_timestamp();
BEGIN
 IF current_user::regrole <> (SELECT relowner FROM pg_class WHERE oid='security.workspaces'::regclass) THEN
  RAISE EXCEPTION 'Privileged maintenance identity required' USING ERRCODE='42501';
 END IF;
 PERFORM set_config('ukda.workspace_id',target::text,true);
 UPDATE security.workspace_purges SET live_payloads_purged_at=completed,backup_expires_at=completed+interval '30 days'
  WHERE workspace_id=target AND logical_payloads_deleted_at IS NOT NULL AND live_payloads_purged_at IS NULL;
 IF NOT FOUND AND NOT EXISTS(SELECT 1 FROM security.workspace_purges WHERE workspace_id=target AND live_payloads_purged_at IS NOT NULL) THEN
  RAISE EXCEPTION 'Logical purge required';
 END IF;
END $$;
