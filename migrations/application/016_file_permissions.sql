-- Mirror the additive signed custom-role catalogue in derived application rows.
-- This admits a new explicit snapshot; it does not expand any existing role/grant.
DO $$ DECLARE table_name text; constraint_name text;
BEGIN
  FOREACH table_name IN ARRAY ARRAY['roles','project_access'] LOOP
    FOR constraint_name IN SELECT c.conname FROM pg_catalog.pg_constraint c
      WHERE c.conrelid=format('app.%I',table_name)::regclass AND c.contype='c'
        AND pg_catalog.pg_get_constraintdef(c.oid) LIKE '%permissions <@%'
    LOOP EXECUTE format('ALTER TABLE app.%I DROP CONSTRAINT %I',table_name,constraint_name); END LOOP;
    EXECUTE format('ALTER TABLE app.%I ADD CONSTRAINT %I CHECK (permissions IS NOT NULL
      AND array_position(permissions,NULL) IS NULL
      AND permissions <@ ARRAY[''read_project'',''comment'',''create_tasks'',''edit_assigned_tasks'',''manage_tasks'',''approve_tasks'',''plan_projects'',''download_files'']::text[])',table_name,table_name||'_known_permissions');
  END LOOP;
END $$;
