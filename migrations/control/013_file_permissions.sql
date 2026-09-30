-- Additive catalogue extension. Existing rows and signed built-in roles stay
-- unchanged; download authority requires a newly signed custom role/grant.
CREATE OR REPLACE FUNCTION security.valid_permissions(value text[]) RETURNS boolean
LANGUAGE sql IMMUTABLE PARALLEL SAFE SET search_path=pg_catalog AS $$
  SELECT value IS NOT NULL AND array_position(value,NULL) IS NULL
    AND value <@ ARRAY['read_project','comment','create_tasks','edit_assigned_tasks','manage_tasks','approve_tasks','plan_projects','download_files']::text[]
    AND cardinality(value)=cardinality(ARRAY(SELECT DISTINCT unnest(value)))
$$;

DO $$ DECLARE constraint_name text;
BEGIN
  FOR constraint_name IN SELECT c.conname FROM pg_catalog.pg_constraint c
    WHERE c.conrelid='security.grants'::regclass AND c.contype='c'
      AND pg_catalog.pg_get_constraintdef(c.oid) LIKE '%permissions <@%'
  LOOP EXECUTE format('ALTER TABLE security.grants DROP CONSTRAINT %I',constraint_name); END LOOP;
END $$;
ALTER TABLE security.grants ADD CONSTRAINT grants_known_permissions CHECK (security.valid_permissions(permissions));
