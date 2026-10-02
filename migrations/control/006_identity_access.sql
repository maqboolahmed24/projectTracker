-- Current personal authority is independent of any one browser/device.
ALTER TABLE security.staged_objects DROP CONSTRAINT staged_objects_object_kind_check;
ALTER TABLE security.staged_objects ADD CONSTRAINT staged_objects_object_kind_check CHECK
  (object_kind IN ('genesis','encrypted_workspace','encrypted_profile','encrypted_role','key_envelope','custody_manifest','signed_grant'));

CREATE FUNCTION security.valid_permissions(value text[]) RETURNS boolean
LANGUAGE sql IMMUTABLE PARALLEL SAFE SET search_path=pg_catalog AS $$
  SELECT value IS NOT NULL AND array_position(value,NULL) IS NULL
    AND value <@ ARRAY['read_project','comment','create_tasks','edit_assigned_tasks','manage_tasks','approve_tasks','plan_projects']::text[]
    AND cardinality(value)=cardinality(ARRAY(SELECT DISTINCT unnest(value)))
$$;

CREATE TABLE security.roles (
  workspace_id uuid NOT NULL REFERENCES security.workspaces(workspace_id) ON DELETE CASCADE,
  role_id uuid NOT NULL,
  template text NOT NULL CHECK (template IN ('owner','manager','member','viewer','custom')),
  revision bigint NOT NULL DEFAULT 1 CHECK (revision>0),
  state text NOT NULL DEFAULT 'active' CHECK (state IN ('active','retired')),
  permissions text[] NOT NULL CHECK (security.valid_permissions(permissions) AND 'read_project'=ANY(permissions)),
  definition_object_id uuid NOT NULL,
  encrypted_role_object_id uuid,
  security_version bigint NOT NULL CHECK (security_version>0),
  PRIMARY KEY(workspace_id,role_id),
  FOREIGN KEY(workspace_id,definition_object_id) REFERENCES security.staged_objects(workspace_id,object_id) DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY(workspace_id,encrypted_role_object_id) REFERENCES security.staged_objects(workspace_id,object_id) DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY(workspace_id,security_version) REFERENCES security.security_transitions(workspace_id,sequence) DEFERRABLE INITIALLY DEFERRED,
  CHECK (template<>'custom' OR encrypted_role_object_id IS NOT NULL)
);
CREATE UNIQUE INDEX roles_one_builtin ON security.roles(workspace_id,template) WHERE template<>'custom';

CREATE TABLE security.scope_heads (
  workspace_id uuid NOT NULL REFERENCES security.workspaces(workspace_id) ON DELETE CASCADE,
  scope_kind text NOT NULL CHECK (scope_kind IN ('workspace','project')),
  scope_id uuid NOT NULL,
  key_epoch bigint NOT NULL CHECK (key_epoch>0),
  recovery_manifest_object_id uuid NOT NULL,
  security_version bigint NOT NULL CHECK (security_version>0),
  PRIMARY KEY(workspace_id,scope_kind,scope_id),
  FOREIGN KEY(workspace_id,recovery_manifest_object_id) REFERENCES security.staged_objects(workspace_id,object_id) DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY(workspace_id,security_version) REFERENCES security.security_transitions(workspace_id,sequence) DEFERRABLE INITIALLY DEFERRED,
  CHECK (scope_kind<>'workspace' OR scope_id=workspace_id)
);
ALTER TABLE security.workspaces ADD COLUMN current_custody_manifest_object_id uuid;
ALTER TABLE security.workspaces ADD CONSTRAINT workspaces_current_custody_fk
  FOREIGN KEY(workspace_id,current_custody_manifest_object_id) REFERENCES security.staged_objects(workspace_id,object_id) DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE security.grants DROP CONSTRAINT grants_grant_kind_check;
ALTER TABLE security.grants ADD CONSTRAINT grants_grant_kind_check CHECK (grant_kind IN ('owner','device','project','recovery','membership'));
ALTER TABLE security.grants ADD COLUMN key_epoch bigint NOT NULL DEFAULT 1 CHECK (key_epoch>0),
  ADD COLUMN role_id uuid, ADD COLUMN role_revision bigint CHECK (role_revision>0);
ALTER TABLE security.grants ADD CONSTRAINT grants_membership_person CHECK
  (grant_kind<>'membership' OR (scope_kind='workspace' AND device_id IS NULL));
ALTER TABLE security.grants ADD CONSTRAINT grants_role_pair CHECK
  ((role_id IS NULL)=(role_revision IS NULL) AND (role_id IS NULL OR scope_kind='project'));
ALTER TABLE security.grants ADD CONSTRAINT grants_role_fk
  FOREIGN KEY(workspace_id,role_id) REFERENCES security.roles(workspace_id,role_id) DEFERRABLE INITIALLY DEFERRED;
CREATE UNIQUE INDEX grants_one_active_membership ON security.grants(workspace_id,profile_id)
  WHERE grant_kind='membership' AND state='active';

-- Public Owner authority was already signed by genesis/recovery; its nullable
-- device relation must not make removal of that browser remove the person.
-- Immutable staged objects, signatures, transition rows and receipts are untouched.
UPDATE security.grants g SET device_id=NULL FROM security.profiles p
  WHERE p.workspace_id=g.workspace_id AND p.profile_id=g.profile_id
    AND p.state='active' AND p.is_owner AND g.grant_kind='owner' AND g.state='active' AND g.device_id IS NOT NULL;
UPDATE security.grants g SET key_epoch=(o.versioned_object->'header'->>'keyEpoch')::bigint
  FROM security.staged_objects o WHERE o.workspace_id=g.workspace_id AND o.object_id=g.key_manifest_object_id
    AND o.state='committed' AND o.versioned_object->'header'->>'keyEpoch' ~ '^[1-9][0-9]{0,17}$'
    AND o.versioned_object->'header'->>'scope'=g.scope_kind
    AND o.versioned_object->'header'->>'scopeId'=coalesce(g.scope_id,g.workspace_id)::text
    AND (o.object_kind='key_envelope' OR (g.grant_kind='owner' AND g.scope_kind='workspace' AND o.object_kind='custody_manifest'));
-- A content keyring encrypted under custody has the custody encryption epoch in
-- its outer header. It cannot establish a project's ordinary-content epoch.

CREATE FUNCTION security.guard_role_revision() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
  IF NEW.workspace_id IS DISTINCT FROM OLD.workspace_id OR NEW.role_id IS DISTINCT FROM OLD.role_id OR NEW.template IS DISTINCT FROM OLD.template
    OR NEW.revision<OLD.revision OR NEW.security_version<OLD.security_version
    OR ((NEW.permissions IS DISTINCT FROM OLD.permissions OR NEW.state IS DISTINCT FROM OLD.state
      OR NEW.definition_object_id IS DISTINCT FROM OLD.definition_object_id OR NEW.encrypted_role_object_id IS DISTINCT FROM OLD.encrypted_role_object_id)
      AND (NEW.revision<=OLD.revision OR NEW.security_version<=OLD.security_version)) THEN
    RAISE EXCEPTION 'role authority must advance its signed revision' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER roles_monotone BEFORE UPDATE ON security.roles FOR EACH ROW EXECUTE FUNCTION security.guard_role_revision();
CREATE FUNCTION security.guard_scope_epoch() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
  IF NEW.workspace_id IS DISTINCT FROM OLD.workspace_id OR NEW.scope_kind IS DISTINCT FROM OLD.scope_kind OR NEW.scope_id IS DISTINCT FROM OLD.scope_id
    OR NEW.key_epoch<OLD.key_epoch OR NEW.security_version<OLD.security_version
    OR ((NEW.key_epoch IS DISTINCT FROM OLD.key_epoch OR NEW.recovery_manifest_object_id IS DISTINCT FROM OLD.recovery_manifest_object_id)
      AND NEW.security_version<=OLD.security_version) THEN
    RAISE EXCEPTION 'scope epoch must advance under a new security transition' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER scope_heads_monotone BEFORE UPDATE ON security.scope_heads FOR EACH ROW EXECUTE FUNCTION security.guard_scope_epoch();

DO $$ DECLARE table_name text;
BEGIN
  FOREACH table_name IN ARRAY ARRAY['roles','scope_heads'] LOOP
    EXECUTE format('ALTER TABLE security.%I ENABLE ROW LEVEL SECURITY',table_name);
    EXECUTE format('ALTER TABLE security.%I FORCE ROW LEVEL SECURITY',table_name);
    EXECUTE format('CREATE POLICY tenant_workspace ON security.%I USING (workspace_id=nullif(current_setting(''ukda.workspace_id'',true),'''')::uuid) WITH CHECK (workspace_id=nullif(current_setting(''ukda.workspace_id'',true),'''')::uuid)',table_name);
  END LOOP;
END $$;

-- Bootstrap only an unambiguous retained epoch-1 genesis. Later custody epochs
-- require their current signed manifest; an old genesis must never reset them.
DO $$
DECLARE item record; role_entry record; role_permissions text[]; roles_valid boolean;
  previous_workspace text := current_setting('ukda.workspace_id',true);
BEGIN
  FOR item IN
    SELECT w.workspace_id,g.object_id AS genesis_id,g.versioned_object->'body' AS body,c.object_id AS custody_id
    FROM security.workspaces w
    JOIN security.staged_objects g ON g.workspace_id=w.workspace_id AND g.object_id=w.genesis_object_id AND g.object_kind='genesis' AND g.state='committed'
    JOIN security.security_transitions t ON t.workspace_id=w.workspace_id AND t.sequence=1 AND t.head=g.object_hash
    JOIN security.staged_objects c ON c.workspace_id=w.workspace_id AND c.object_id::text=g.versioned_object->'body'->>'custodyId'
      AND c.object_kind='custody_manifest' AND c.state='committed'
    JOIN security.staged_objects p ON p.workspace_id=w.workspace_id AND p.object_id=w.workspace_id AND p.object_kind='encrypted_workspace' AND p.state='committed'
    WHERE w.custody_epoch=1 AND g.versioned_object->'body'->>'purpose'='ukda.genesis.v1'
      AND g.versioned_object->'body'->>'workspaceId'=w.workspace_id::text AND g.versioned_object->'body'->>'genesisId'=g.object_id::text
      AND c.versioned_object->'header'->>'keyEpoch'='1' AND c.versioned_object->'header'->>'scope'='workspace'
      AND c.versioned_object->'header'->>'scopeId'=w.workspace_id::text AND p.versioned_object->'header'->>'keyEpoch'='1'
      AND jsonb_typeof(g.versioned_object->'body'->'roles')='object'
      AND EXISTS (SELECT 1 FROM jsonb_array_elements(CASE WHEN jsonb_typeof(g.versioned_object->'body'->'manifest')='array'
        THEN g.versioned_object->'body'->'manifest' ELSE '[]'::jsonb END) m
        WHERE m->>'id'=c.object_id::text AND m->>'kind'='custody_manifest' AND m->>'digest'=c.object_hash)
      AND EXISTS (SELECT 1 FROM jsonb_array_elements(CASE WHEN jsonb_typeof(g.versioned_object->'body'->'manifest')='array'
        THEN g.versioned_object->'body'->'manifest' ELSE '[]'::jsonb END) m
        WHERE m->>'id'=p.object_id::text AND m->>'kind'='encrypted_workspace' AND m->>'digest'=p.object_hash)
  LOOP
    SELECT count(*)=4 AND count(DISTINCT value)=4 AND bool_and(key IN ('owner','manager','member','viewer')
      AND value ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
      INTO roles_valid FROM jsonb_each_text(item.body->'roles');
    IF NOT coalesce(roles_valid,false) THEN CONTINUE; END IF;
    PERFORM set_config('ukda.workspace_id',item.workspace_id::text,true);
    UPDATE security.workspaces SET current_custody_manifest_object_id=item.custody_id WHERE workspace_id=item.workspace_id;
    INSERT INTO security.scope_heads(workspace_id,scope_kind,scope_id,key_epoch,recovery_manifest_object_id,security_version)
      VALUES(item.workspace_id,'workspace',item.workspace_id,1,item.custody_id,1);
    FOR role_entry IN SELECT key,value FROM jsonb_each_text(item.body->'roles')
      WHERE key IN ('owner','manager','member','viewer') AND value ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    LOOP
      role_permissions=CASE role_entry.key WHEN 'viewer' THEN ARRAY['read_project']::text[]
        WHEN 'member' THEN ARRAY['read_project','comment','create_tasks','edit_assigned_tasks']::text[]
        ELSE ARRAY['read_project','comment','create_tasks','edit_assigned_tasks','manage_tasks','approve_tasks','plan_projects']::text[] END;
      INSERT INTO security.roles(workspace_id,role_id,template,permissions,definition_object_id,security_version)
        VALUES(item.workspace_id,role_entry.value::uuid,role_entry.key,role_permissions,item.genesis_id,1);
    END LOOP;
  END LOOP;
  PERFORM set_config('ukda.workspace_id',coalesce(previous_workspace,''),true);
END $$;

REVOKE ALL ON security.roles,security.scope_heads FROM PUBLIC;
REVOKE ALL ON FUNCTION security.valid_permissions(text[]),security.guard_role_revision(),security.guard_scope_epoch() FROM PUBLIC;
