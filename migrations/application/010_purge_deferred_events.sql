-- Append-only repair: applied lifecycle migrations remain unchanged.
CREATE OR REPLACE FUNCTION app.purge_workspace_payloads(target uuid) RETURNS text[]
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
 -- Validate the final deletion state and drain queued FK trigger events before
 -- ALTER TABLE restores immutable-history triggers. Any constraint failure
 -- rolls back both the deletes and trigger changes.
 SET CONSTRAINTS ALL IMMEDIATE;
 FOREACH table_name IN ARRAY changed LOOP EXECUTE format('ALTER TABLE %s ENABLE TRIGGER USER',table_name); END LOOP;
 DELETE FROM graphile_worker._private_jobs WHERE payload->>'workspaceId'=target::text;
 RETURN array_append(changed,'graphile_worker._private_jobs');
END $$;
