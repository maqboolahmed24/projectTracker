-- Append-only repair: applied lifecycle migrations remain unchanged.
CREATE OR REPLACE FUNCTION security.purge_workspace_payloads(target uuid) RETURNS text[]
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
 -- Validate the final deletion state and drain queued FK trigger events before
 -- ALTER TABLE restores immutable-history triggers. Any constraint failure
 -- rolls back both the deletes and trigger changes.
 SET CONSTRAINTS ALL IMMEDIATE;
 FOREACH table_name IN ARRAY changed LOOP
  IF table_name<>'security.entitlement_operations' THEN EXECUTE format('ALTER TABLE %s ENABLE TRIGGER USER',table_name); END IF;
 END LOOP;
 UPDATE security.workspace_purges SET logical_payloads_deleted_at=coalesce(logical_payloads_deleted_at,clock_timestamp()) WHERE workspace_id=target;
 RETURN changed;
END $$;
