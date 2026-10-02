-- Effective access is an explicit signed grant snapshot; a role edit alone
-- cannot expand an existing person's project rights.
ALTER TABLE app.roles ADD COLUMN state text NOT NULL DEFAULT 'active' CHECK (state IN ('active','retired'));
ALTER TABLE app.project_access ADD COLUMN grant_id uuid,
  ADD COLUMN role_revision bigint NOT NULL DEFAULT 1 CHECK (role_revision>0),
  ADD COLUMN permissions text[] NOT NULL DEFAULT '{}'::text[] CHECK (
    permissions <@ ARRAY['read_project','comment','create_tasks','edit_assigned_tasks','manage_tasks','approve_tasks','plan_projects']::text[]
    AND array_position(permissions,NULL) IS NULL),
  ADD COLUMN key_epoch bigint NOT NULL DEFAULT 1 CHECK (key_epoch>0),
  ADD COLUMN expires_at timestamptz;
-- Preserve the former effective rights once during migration. New grants default
-- to no permissions and require the authoritative projection to populate them.
UPDATE app.project_access access SET permissions=role.permissions,role_revision=role.revision
  FROM app.roles role WHERE role.workspace_id=access.workspace_id AND role.id=access.role_id;

CREATE TABLE app.scope_heads (
  workspace_id uuid NOT NULL REFERENCES app.workspaces(workspace_id) ON DELETE CASCADE,
  scope_kind text NOT NULL CHECK (scope_kind IN ('workspace','project')),
  scope_id uuid NOT NULL,
  key_epoch bigint NOT NULL CHECK (key_epoch>0),
  security_version bigint NOT NULL CHECK (security_version>0),
  PRIMARY KEY(workspace_id,scope_kind,scope_id),
  CHECK (scope_kind<>'workspace' OR scope_id=workspace_id)
);
-- Scope identities can precede application project creation. This is a derived
-- workspace mirror and deliberately has no FK to app.projects.
ALTER TABLE app.scope_heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.scope_heads FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_scope ON app.scope_heads
  USING (workspace_id=app.current_workspace_id()) WITH CHECK (workspace_id=app.current_workspace_id());
REVOKE ALL ON app.scope_heads FROM PUBLIC;

CREATE OR REPLACE FUNCTION app.can_read_project(requested_project_id uuid) RETURNS boolean
LANGUAGE sql STABLE PARALLEL SAFE SET search_path=pg_catalog AS $$
  SELECT EXISTS (
    SELECT 1 FROM app.project_access access
    JOIN app.profiles profile ON profile.workspace_id=access.workspace_id AND profile.id=access.profile_id
    JOIN app.roles role ON role.workspace_id=access.workspace_id AND role.id=access.role_id
    WHERE access.workspace_id=app.current_workspace_id() AND access.project_id=requested_project_id
      AND access.profile_id=app.current_profile_id() AND access.state='active' AND profile.state='active'
      AND role.state='active' AND 'read_project'=ANY(access.permissions)
      AND (access.expires_at IS NULL OR access.expires_at>statement_timestamp())
  )
$$;

-- Historical notification references must not leak a project after its current
-- recipient access ends. Workspace notices also require an active account.
DROP POLICY recipient_scope ON app.notifications;
CREATE POLICY recipient_scope ON app.notifications
  USING (workspace_id=app.current_workspace_id() AND recipient_profile_id=app.current_profile_id()
    AND EXISTS (SELECT 1 FROM app.profiles profile WHERE profile.workspace_id=notifications.workspace_id
      AND profile.id=notifications.recipient_profile_id AND profile.state='active')
    AND (project_id IS NULL OR app.can_read_project(project_id)))
  WITH CHECK (workspace_id=app.current_workspace_id() AND recipient_profile_id=app.current_profile_id()
    AND EXISTS (SELECT 1 FROM app.profiles profile WHERE profile.workspace_id=notifications.workspace_id
      AND profile.id=notifications.recipient_profile_id AND profile.state='active')
    AND (project_id IS NULL OR app.can_read_project(project_id)));

-- Deferred integrity checks inspect the final effective grant, including expiry;
-- they retain the existing restricted migration-role read policy for cleanup.
CREATE OR REPLACE FUNCTION app.check_assignment_access() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  target_workspace uuid;
  target_member uuid;
  target_project uuid;
  target_role uuid;
BEGIN
  IF TG_TABLE_NAME = 'task_assignments' THEN
    target_workspace := NEW.workspace_id;
    target_member := NEW.member_id;
    target_project := NEW.project_id;
  ELSIF TG_TABLE_NAME = 'project_access' THEN
    IF TG_OP = 'DELETE' THEN
      target_workspace := OLD.workspace_id;
      target_member := OLD.profile_id;
      target_project := OLD.project_id;
    ELSE
      target_workspace := NEW.workspace_id;
      target_member := NEW.profile_id;
      target_project := NEW.project_id;
    END IF;
  ELSIF TG_TABLE_NAME = 'roles' THEN
    target_workspace := NEW.workspace_id;
    target_role := NEW.id;
  ELSE
    IF TG_OP = 'DELETE' THEN
      target_workspace := OLD.workspace_id;
      target_member := OLD.id;
    ELSE
      target_workspace := NEW.workspace_id;
      target_member := NEW.id;
    END IF;
  END IF;
  IF EXISTS (
    SELECT 1 FROM app.task_assignments AS assignment
    LEFT JOIN app.profiles AS profile
      ON profile.workspace_id = assignment.workspace_id AND profile.id = assignment.member_id
    LEFT JOIN app.project_access AS access
      ON access.workspace_id = assignment.workspace_id AND access.project_id = assignment.project_id AND access.profile_id = assignment.member_id
    LEFT JOIN app.roles AS role
      ON role.workspace_id = access.workspace_id AND role.id = access.role_id
    WHERE assignment.workspace_id = target_workspace
      AND (target_member IS NULL OR assignment.member_id = target_member)
      AND (target_project IS NULL OR assignment.project_id = target_project)
      AND (target_role IS NULL OR access.role_id = target_role)
      AND (profile.id IS NULL OR profile.state <> 'active' OR access.profile_id IS NULL OR access.state <> 'active'
        OR role.id IS NULL OR role.state <> 'active'
        OR (access.expires_at IS NOT NULL AND access.expires_at <= statement_timestamp())
        OR NOT coalesce('read_project' = ANY(access.permissions), false))
  ) THEN
    RAISE EXCEPTION 'Task assignments require an active profile and active project read access' USING ERRCODE = '23514';
  END IF;
  RETURN NULL;
END
$$;
