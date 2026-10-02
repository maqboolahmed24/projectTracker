-- Application data is a projection of authoritative security state plus encrypted
-- business records. Execute as the migration role, inside the migration transaction.
-- Runtime grants are applied by the migration runner, never by an HTTP endpoint.
CREATE SCHEMA IF NOT EXISTS app;
REVOKE ALL ON SCHEMA app FROM PUBLIC;

CREATE FUNCTION app.current_workspace_id() RETURNS uuid
LANGUAGE sql STABLE PARALLEL SAFE
SET search_path = pg_catalog
AS $$ SELECT nullif(current_setting('ukda.workspace_id', true), '')::uuid $$;

CREATE FUNCTION app.current_profile_id() RETURNS uuid
LANGUAGE sql STABLE PARALLEL SAFE
SET search_path = pg_catalog
AS $$ SELECT nullif(current_setting('ukda.profile_id', true), '')::uuid $$;

CREATE TABLE app.workspaces (
  workspace_id uuid PRIMARY KEY,
  security_head text NOT NULL DEFAULT repeat('0', 64) CHECK (security_head ~ '^[0-9a-f]{64}$'),
  security_version bigint NOT NULL DEFAULT 0 CHECK (security_version >= 0),
  data_generation bigint NOT NULL DEFAULT 1 CHECK (data_generation > 0),
  write_schema integer NOT NULL DEFAULT 1 CHECK (write_schema > 0),
  fence_closed boolean NOT NULL DEFAULT true,
  lifecycle text NOT NULL DEFAULT 'pending_activation' CHECK (lifecycle IN ('pending_activation', 'active', 'pending_deletion', 'deleted')),
  licence_state text NOT NULL DEFAULT 'active' CHECK (licence_state IN ('active', 'restricted', 'revoked')),
  content_maintenance boolean NOT NULL DEFAULT false,
  restore_quarantine boolean NOT NULL DEFAULT false,
  revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
  encrypted_envelope jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(encrypted_envelope) = 'object'),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE app.profiles (
  workspace_id uuid NOT NULL REFERENCES app.workspaces(workspace_id) DEFERRABLE INITIALLY DEFERRED,
  id uuid NOT NULL,
  state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'active', 'suspended', 'removed')),
  is_owner boolean NOT NULL DEFAULT false,
  revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
  schema_version integer NOT NULL DEFAULT 1 CHECK (schema_version > 0),
  key_epoch bigint NOT NULL DEFAULT 1 CHECK (key_epoch > 0),
  encrypted_envelope jsonb NOT NULL CHECK (jsonb_typeof(encrypted_envelope) = 'object'),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (workspace_id, id)
);

CREATE TABLE app.roles (
  workspace_id uuid NOT NULL REFERENCES app.workspaces(workspace_id) DEFERRABLE INITIALLY DEFERRED,
  id uuid NOT NULL,
  template text NOT NULL DEFAULT 'custom' CHECK (template IN ('owner', 'manager', 'member', 'viewer', 'custom')),
  permissions text[] NOT NULL DEFAULT '{}'::text[] CHECK (
    permissions <@ ARRAY['read_project', 'comment', 'create_tasks', 'edit_assigned_tasks', 'manage_tasks', 'approve_tasks', 'plan_projects']::text[]
    AND array_position(permissions, NULL) IS NULL
  ),
  revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
  schema_version integer NOT NULL DEFAULT 1 CHECK (schema_version > 0),
  key_epoch bigint NOT NULL DEFAULT 1 CHECK (key_epoch > 0),
  encrypted_envelope jsonb NOT NULL CHECK (jsonb_typeof(encrypted_envelope) = 'object'),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (workspace_id, id)
);

CREATE TABLE app.teams (
  workspace_id uuid NOT NULL REFERENCES app.workspaces(workspace_id) DEFERRABLE INITIALLY DEFERRED,
  id uuid NOT NULL,
  revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
  schema_version integer NOT NULL DEFAULT 1 CHECK (schema_version > 0),
  key_epoch bigint NOT NULL DEFAULT 1 CHECK (key_epoch > 0),
  encrypted_envelope jsonb NOT NULL CHECK (jsonb_typeof(encrypted_envelope) = 'object'),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (workspace_id, id)
);

CREATE TABLE app.team_members (
  workspace_id uuid NOT NULL,
  team_id uuid NOT NULL,
  profile_id uuid NOT NULL,
  revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (workspace_id, team_id, profile_id),
  FOREIGN KEY (workspace_id, team_id) REFERENCES app.teams(workspace_id, id) DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY (workspace_id, profile_id) REFERENCES app.profiles(workspace_id, id) DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE app.projects (
  workspace_id uuid NOT NULL REFERENCES app.workspaces(workspace_id) DEFERRABLE INITIALLY DEFERRED,
  id uuid NOT NULL,
  state text NOT NULL DEFAULT 'planned' CHECK (state IN ('planned', 'active', 'complete', 'cancelled')),
  archived boolean NOT NULL DEFAULT false CHECK (NOT archived OR state IN ('complete', 'cancelled')),
  phase_label text NOT NULL DEFAULT 'wave' CHECK (phase_label IN ('phase', 'wave')),
  manager_profile_id uuid,
  team_id uuid,
  revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
  schema_version integer NOT NULL DEFAULT 1 CHECK (schema_version > 0),
  key_epoch bigint NOT NULL DEFAULT 1 CHECK (key_epoch > 0),
  encrypted_envelope jsonb NOT NULL CHECK (jsonb_typeof(encrypted_envelope) = 'object'),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (workspace_id, id),
  FOREIGN KEY (workspace_id, manager_profile_id) REFERENCES app.profiles(workspace_id, id) DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY (workspace_id, team_id) REFERENCES app.teams(workspace_id, id) DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE app.project_access (
  workspace_id uuid NOT NULL,
  project_id uuid NOT NULL,
  profile_id uuid NOT NULL,
  role_id uuid NOT NULL,
  state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'active', 'revoked')),
  revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (workspace_id, project_id, profile_id),
  FOREIGN KEY (workspace_id, project_id) REFERENCES app.projects(workspace_id, id) DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY (workspace_id, profile_id) REFERENCES app.profiles(workspace_id, id) DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY (workspace_id, role_id) REFERENCES app.roles(workspace_id, id) DEFERRABLE INITIALLY DEFERRED
);

-- SECURITY INVOKER deliberately uses workspace-only profile/grant policies, so
-- domain-table RLS has no recursion. An Owner is not a project-access bypass.
CREATE FUNCTION app.can_read_project(requested_project_id uuid) RETURNS boolean
LANGUAGE sql STABLE PARALLEL SAFE
SET search_path = pg_catalog
AS $$
  SELECT EXISTS (
    SELECT 1 FROM app.project_access AS access
    JOIN app.profiles AS profile
      ON profile.workspace_id = access.workspace_id AND profile.id = access.profile_id
    JOIN app.roles AS role
      ON role.workspace_id = access.workspace_id AND role.id = access.role_id
    WHERE access.workspace_id = app.current_workspace_id()
      AND access.project_id = requested_project_id
      AND access.profile_id = app.current_profile_id()
      AND access.state = 'active' AND profile.state = 'active'
      AND 'read_project' = ANY(role.permissions)
  )
$$;

CREATE TABLE app.project_phases (
  workspace_id uuid NOT NULL,
  id uuid NOT NULL,
  project_id uuid NOT NULL,
  state text NOT NULL DEFAULT 'planned' CHECK (state IN ('planned', 'active', 'complete', 'cancelled')),
  archived boolean NOT NULL DEFAULT false CHECK (NOT archived OR state IN ('complete', 'cancelled')),
  display_order integer NOT NULL DEFAULT 0 CHECK (display_order >= 0),
  lead_profile_id uuid,
  revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
  schema_version integer NOT NULL DEFAULT 1 CHECK (schema_version > 0),
  key_epoch bigint NOT NULL DEFAULT 1 CHECK (key_epoch > 0),
  encrypted_envelope jsonb NOT NULL CHECK (jsonb_typeof(encrypted_envelope) = 'object'),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (workspace_id, id),
  UNIQUE (workspace_id, project_id, id),
  FOREIGN KEY (workspace_id, project_id) REFERENCES app.projects(workspace_id, id) DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY (workspace_id, lead_profile_id) REFERENCES app.profiles(workspace_id, id) DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE app.milestones (
  workspace_id uuid NOT NULL,
  id uuid NOT NULL,
  project_id uuid NOT NULL,
  phase_id uuid,
  owner_profile_id uuid,
  state text NOT NULL DEFAULT 'open' CHECK (state IN ('open', 'accepted', 'cancelled')),
  revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
  schema_version integer NOT NULL DEFAULT 1 CHECK (schema_version > 0),
  key_epoch bigint NOT NULL DEFAULT 1 CHECK (key_epoch > 0),
  encrypted_envelope jsonb NOT NULL CHECK (jsonb_typeof(encrypted_envelope) = 'object'),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (workspace_id, id),
  UNIQUE (workspace_id, project_id, id),
  FOREIGN KEY (workspace_id, project_id) REFERENCES app.projects(workspace_id, id) DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY (workspace_id, project_id, phase_id) REFERENCES app.project_phases(workspace_id, project_id, id) DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY (workspace_id, owner_profile_id) REFERENCES app.profiles(workspace_id, id) DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE app.tasks (
  workspace_id uuid NOT NULL,
  id uuid NOT NULL,
  project_id uuid NOT NULL,
  phase_id uuid,
  milestone_id uuid,
  team_id uuid,
  lead_profile_id uuid,
  reviewer_profile_id uuid,
  submitted_revision bigint CHECK (submitted_revision > 0),
  state text NOT NULL DEFAULT 'todo' CHECK (state IN ('todo', 'in_progress', 'review', 'done', 'cancelled')),
  revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
  schema_version integer NOT NULL DEFAULT 1 CHECK (schema_version > 0),
  key_epoch bigint NOT NULL DEFAULT 1 CHECK (key_epoch > 0),
  encrypted_envelope jsonb NOT NULL CHECK (jsonb_typeof(encrypted_envelope) = 'object'),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (workspace_id, id),
  UNIQUE (workspace_id, project_id, id),
  FOREIGN KEY (workspace_id, project_id) REFERENCES app.projects(workspace_id, id) DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY (workspace_id, project_id, phase_id) REFERENCES app.project_phases(workspace_id, project_id, id) DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY (workspace_id, project_id, milestone_id) REFERENCES app.milestones(workspace_id, project_id, id) DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY (workspace_id, team_id) REFERENCES app.teams(workspace_id, id) DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY (workspace_id, reviewer_profile_id) REFERENCES app.profiles(workspace_id, id) DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE app.task_assignments (
  workspace_id uuid NOT NULL,
  task_id uuid NOT NULL,
  project_id uuid NOT NULL,
  member_id uuid NOT NULL,
  assigned_by uuid NOT NULL,
  assigned_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
  PRIMARY KEY (workspace_id, task_id, member_id),
  FOREIGN KEY (workspace_id, project_id, task_id) REFERENCES app.tasks(workspace_id, project_id, id) DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY (workspace_id, project_id, member_id) REFERENCES app.project_access(workspace_id, project_id, profile_id) DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY (workspace_id, member_id) REFERENCES app.profiles(workspace_id, id) DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY (workspace_id, assigned_by) REFERENCES app.profiles(workspace_id, id) DEFERRABLE INITIALLY DEFERRED
);

ALTER TABLE app.tasks ADD CONSTRAINT task_lead_is_assignee
  FOREIGN KEY (workspace_id, id, lead_profile_id)
  REFERENCES app.task_assignments(workspace_id, task_id, member_id)
  DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE app.blockers (
  workspace_id uuid NOT NULL,
  id uuid NOT NULL,
  project_id uuid NOT NULL,
  task_id uuid NOT NULL,
  responsible_profile_id uuid,
  created_by uuid NOT NULL,
  resolved_by uuid,
  state text NOT NULL DEFAULT 'open' CHECK (state IN ('open', 'resolved')),
  resolved_at timestamptz,
  revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
  schema_version integer NOT NULL DEFAULT 1 CHECK (schema_version > 0),
  key_epoch bigint NOT NULL DEFAULT 1 CHECK (key_epoch > 0),
  encrypted_envelope jsonb NOT NULL CHECK (jsonb_typeof(encrypted_envelope) = 'object'),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (workspace_id, id),
  FOREIGN KEY (workspace_id, project_id, task_id) REFERENCES app.tasks(workspace_id, project_id, id) DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY (workspace_id, responsible_profile_id) REFERENCES app.profiles(workspace_id, id) DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY (workspace_id, created_by) REFERENCES app.profiles(workspace_id, id) DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY (workspace_id, resolved_by) REFERENCES app.profiles(workspace_id, id) DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE app.comments (
  workspace_id uuid NOT NULL,
  id uuid NOT NULL,
  project_id uuid NOT NULL,
  task_id uuid NOT NULL,
  author_profile_id uuid NOT NULL,
  hidden boolean NOT NULL DEFAULT false,
  moderated_by uuid,
  moderated_at timestamptz,
  revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
  schema_version integer NOT NULL DEFAULT 1 CHECK (schema_version > 0),
  key_epoch bigint NOT NULL DEFAULT 1 CHECK (key_epoch > 0),
  encrypted_envelope jsonb NOT NULL CHECK (jsonb_typeof(encrypted_envelope) = 'object'),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (workspace_id, id),
  FOREIGN KEY (workspace_id, project_id, task_id) REFERENCES app.tasks(workspace_id, project_id, id) DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY (workspace_id, author_profile_id) REFERENCES app.profiles(workspace_id, id) DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY (workspace_id, moderated_by) REFERENCES app.profiles(workspace_id, id) DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE app.updates (
  workspace_id uuid NOT NULL,
  id uuid NOT NULL,
  project_id uuid NOT NULL,
  phase_id uuid,
  author_profile_id uuid NOT NULL,
  hidden boolean NOT NULL DEFAULT false,
  moderated_by uuid,
  moderated_at timestamptz,
  revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
  schema_version integer NOT NULL DEFAULT 1 CHECK (schema_version > 0),
  key_epoch bigint NOT NULL DEFAULT 1 CHECK (key_epoch > 0),
  encrypted_envelope jsonb NOT NULL CHECK (jsonb_typeof(encrypted_envelope) = 'object'),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (workspace_id, id),
  FOREIGN KEY (workspace_id, project_id) REFERENCES app.projects(workspace_id, id) DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY (workspace_id, project_id, phase_id) REFERENCES app.project_phases(workspace_id, project_id, id) DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY (workspace_id, author_profile_id) REFERENCES app.profiles(workspace_id, id) DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY (workspace_id, moderated_by) REFERENCES app.profiles(workspace_id, id) DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE app.record_versions (
  workspace_id uuid NOT NULL REFERENCES app.workspaces(workspace_id) DEFERRABLE INITIALLY DEFERRED,
  id uuid NOT NULL,
  project_id uuid,
  record_type text NOT NULL CHECK (record_type ~ '^[a-z_]+$'),
  record_id uuid NOT NULL,
  record_revision bigint NOT NULL CHECK (record_revision > 0),
  actor_profile_id uuid NOT NULL,
  operation_id uuid NOT NULL,
  schema_version integer NOT NULL DEFAULT 1 CHECK (schema_version > 0),
  key_epoch bigint NOT NULL DEFAULT 1 CHECK (key_epoch > 0),
  encrypted_envelope jsonb NOT NULL CHECK (jsonb_typeof(encrypted_envelope) = 'object'),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (workspace_id, id),
  UNIQUE (workspace_id, record_type, record_id, record_revision),
  FOREIGN KEY (workspace_id, project_id) REFERENCES app.projects(workspace_id, id) DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY (workspace_id, actor_profile_id) REFERENCES app.profiles(workspace_id, id) DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE app.audit_events (
  workspace_id uuid NOT NULL REFERENCES app.workspaces(workspace_id) DEFERRABLE INITIALLY DEFERRED,
  id uuid NOT NULL,
  project_id uuid,
  actor_profile_id uuid,
  operation_id uuid NOT NULL,
  action text NOT NULL CHECK (action ~ '^[a-z][a-z0-9_.]*$'),
  record_type text NOT NULL CHECK (record_type ~ '^[a-z_]+$'),
  record_id uuid,
  schema_version integer NOT NULL DEFAULT 1 CHECK (schema_version > 0),
  key_epoch bigint NOT NULL DEFAULT 1 CHECK (key_epoch > 0),
  encrypted_envelope jsonb NOT NULL CHECK (jsonb_typeof(encrypted_envelope) = 'object'),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (workspace_id, id),
  FOREIGN KEY (workspace_id, project_id) REFERENCES app.projects(workspace_id, id) DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY (workspace_id, actor_profile_id) REFERENCES app.profiles(workspace_id, id) DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE app.notifications (
  workspace_id uuid NOT NULL REFERENCES app.workspaces(workspace_id) DEFERRABLE INITIALLY DEFERRED,
  id uuid NOT NULL,
  recipient_profile_id uuid NOT NULL,
  project_id uuid,
  event_id uuid NOT NULL,
  event_type text NOT NULL CHECK (event_type ~ '^[a-z][a-z0-9_.]*$'),
  record_id uuid,
  read_at timestamptz,
  revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
  encrypted_envelope jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(encrypted_envelope) = 'object'),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (workspace_id, id),
  UNIQUE (workspace_id, recipient_profile_id, event_id),
  FOREIGN KEY (workspace_id, recipient_profile_id) REFERENCES app.profiles(workspace_id, id) DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY (workspace_id, project_id) REFERENCES app.projects(workspace_id, id) DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE app.notification_preferences (
  workspace_id uuid NOT NULL,
  id uuid NOT NULL,
  profile_id uuid NOT NULL,
  project_id uuid NOT NULL,
  muted boolean NOT NULL DEFAULT false,
  revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (workspace_id, id),
  UNIQUE (workspace_id, profile_id, project_id),
  FOREIGN KEY (workspace_id, profile_id) REFERENCES app.profiles(workspace_id, id) DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY (workspace_id, project_id) REFERENCES app.projects(workspace_id, id) DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE app.summaries (
  workspace_id uuid NOT NULL,
  id uuid NOT NULL,
  project_id uuid NOT NULL,
  scope_type text NOT NULL CHECK (scope_type IN ('project', 'phase', 'milestone', 'filtered')),
  scope_id uuid,
  scope_fingerprint text NOT NULL,
  permission_revision bigint NOT NULL CHECK (permission_revision > 0),
  source_revision bigint NOT NULL CHECK (source_revision > 0),
  calculation_version text NOT NULL,
  calculated_by_profile_id uuid NOT NULL,
  calculated_at timestamptz NOT NULL,
  complete boolean NOT NULL DEFAULT false,
  revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
  schema_version integer NOT NULL DEFAULT 1 CHECK (schema_version > 0),
  key_epoch bigint NOT NULL DEFAULT 1 CHECK (key_epoch > 0),
  encrypted_envelope jsonb NOT NULL CHECK (jsonb_typeof(encrypted_envelope) = 'object'),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (workspace_id, id),
  UNIQUE (workspace_id, project_id, scope_fingerprint, calculation_version),
  FOREIGN KEY (workspace_id, project_id) REFERENCES app.projects(workspace_id, id) DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY (workspace_id, calculated_by_profile_id) REFERENCES app.profiles(workspace_id, id) DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE app.operation_receipts (
  workspace_id uuid NOT NULL REFERENCES app.workspaces(workspace_id) DEFERRABLE INITIALLY DEFERRED,
  id uuid NOT NULL,
  data_generation bigint NOT NULL CHECK (data_generation > 0),
  operation_id uuid NOT NULL,
  actor_profile_id uuid NOT NULL,
  project_id uuid,
  action text NOT NULL CHECK (action ~ '^[a-z][a-z0-9_.]*$'),
  request_digest text NOT NULL,
  encrypted_envelope jsonb NOT NULL CHECK (jsonb_typeof(encrypted_envelope) = 'object'),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (workspace_id, id),
  UNIQUE (workspace_id, data_generation, operation_id),
  FOREIGN KEY (workspace_id, actor_profile_id) REFERENCES app.profiles(workspace_id, id) DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY (workspace_id, project_id) REFERENCES app.projects(workspace_id, id) DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE app.outbox (
  workspace_id uuid NOT NULL REFERENCES app.workspaces(workspace_id) DEFERRABLE INITIALLY DEFERRED,
  id uuid NOT NULL,
  data_generation bigint NOT NULL CHECK (data_generation > 0),
  operation_id uuid NOT NULL,
  project_id uuid,
  event_type text NOT NULL CHECK (event_type ~ '^[a-z][a-z0-9_.]*$'),
  deduplication_key text NOT NULL,
  state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'processing', 'complete', 'failed')),
  attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  max_attempts integer NOT NULL DEFAULT 10 CHECK (max_attempts > 0),
  available_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
  encrypted_envelope jsonb NOT NULL CHECK (jsonb_typeof(encrypted_envelope) = 'object'),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (workspace_id, id),
  UNIQUE (workspace_id, data_generation, deduplication_key),
  FOREIGN KEY (workspace_id, project_id) REFERENCES app.projects(workspace_id, id) DEFERRABLE INITIALLY DEFERRED
);

-- Composite keys cover foreign-key lookups; these indexes cover scope/member reads
-- and the deferred integrity checks made during membership and milestone changes.
CREATE INDEX project_access_profile ON app.project_access(workspace_id, profile_id, state);
CREATE INDEX project_access_role ON app.project_access(workspace_id, role_id);
CREATE INDEX phases_project ON app.project_phases(workspace_id, project_id, display_order);
CREATE INDEX milestones_project ON app.milestones(workspace_id, project_id, phase_id);
CREATE INDEX tasks_project ON app.tasks(workspace_id, project_id, state);
CREATE INDEX tasks_milestone ON app.tasks(workspace_id, milestone_id);
CREATE INDEX assignments_member ON app.task_assignments(workspace_id, member_id, project_id);
CREATE INDEX blockers_task ON app.blockers(workspace_id, task_id, state);
CREATE INDEX comments_task ON app.comments(workspace_id, task_id, created_at);
CREATE INDEX updates_project ON app.updates(workspace_id, project_id, created_at);
CREATE INDEX audit_project ON app.audit_events(workspace_id, project_id, created_at);
CREATE INDEX notifications_recipient ON app.notifications(workspace_id, recipient_profile_id, created_at);
CREATE INDEX outbox_pending ON app.outbox(workspace_id, available_at) WHERE state IN ('pending', 'failed');

-- All RLS expressions keep the tenant predicate, including migration-role-only
-- integrity reads. Empty/unset context is NULL and cannot match any workspace.
DO $policies$
DECLARE
  table_name text;
BEGIN
  FOREACH table_name IN ARRAY ARRAY['workspaces', 'profiles', 'roles', 'teams', 'team_members', 'project_access', 'outbox'] LOOP
    EXECUTE format('ALTER TABLE app.%I ENABLE ROW LEVEL SECURITY', table_name);
    EXECUTE format('ALTER TABLE app.%I FORCE ROW LEVEL SECURITY', table_name);
    EXECUTE format('CREATE POLICY tenant_scope ON app.%I USING (workspace_id = app.current_workspace_id()) WITH CHECK (workspace_id = app.current_workspace_id())', table_name);
  END LOOP;
  FOREACH table_name IN ARRAY ARRAY['project_phases', 'milestones', 'tasks', 'task_assignments', 'blockers', 'comments', 'updates', 'summaries'] LOOP
    EXECUTE format('ALTER TABLE app.%I ENABLE ROW LEVEL SECURITY', table_name);
    EXECUTE format('ALTER TABLE app.%I FORCE ROW LEVEL SECURITY', table_name);
    EXECUTE format('CREATE POLICY project_scope ON app.%I USING (workspace_id = app.current_workspace_id() AND app.can_read_project(project_id)) WITH CHECK (workspace_id = app.current_workspace_id() AND app.can_read_project(project_id))', table_name);
    -- Constraint functions execute as the migration role and need to find rows
    -- after access has been removed in the same deferred transaction. This policy
    -- never belongs to the runtime role and grants no INSERT/UPDATE/DELETE bypass.
    EXECUTE format('CREATE POLICY integrity_read ON app.%I FOR SELECT TO %I USING (workspace_id = app.current_workspace_id())', table_name, current_user);
  END LOOP;
  FOREACH table_name IN ARRAY ARRAY['record_versions', 'audit_events'] LOOP
    EXECUTE format('ALTER TABLE app.%I ENABLE ROW LEVEL SECURITY', table_name);
    EXECUTE format('ALTER TABLE app.%I FORCE ROW LEVEL SECURITY', table_name);
    EXECUTE format('CREATE POLICY history_scope ON app.%I USING (workspace_id = app.current_workspace_id() AND (project_id IS NULL OR app.can_read_project(project_id))) WITH CHECK (workspace_id = app.current_workspace_id() AND (project_id IS NULL OR app.can_read_project(project_id)))', table_name);
  END LOOP;
END
$policies$;

ALTER TABLE app.projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.projects FORCE ROW LEVEL SECURITY;
CREATE POLICY project_scope ON app.projects
  USING (workspace_id = app.current_workspace_id() AND app.can_read_project(id))
  WITH CHECK (workspace_id = app.current_workspace_id() AND app.can_read_project(id));

ALTER TABLE app.notifications ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.notifications FORCE ROW LEVEL SECURITY;
CREATE POLICY recipient_scope ON app.notifications
  USING (workspace_id = app.current_workspace_id() AND recipient_profile_id = app.current_profile_id())
  WITH CHECK (workspace_id = app.current_workspace_id() AND recipient_profile_id = app.current_profile_id());

ALTER TABLE app.notification_preferences ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.notification_preferences FORCE ROW LEVEL SECURITY;
CREATE POLICY recipient_project_scope ON app.notification_preferences
  USING (workspace_id = app.current_workspace_id() AND profile_id = app.current_profile_id() AND app.can_read_project(project_id))
  WITH CHECK (workspace_id = app.current_workspace_id() AND profile_id = app.current_profile_id() AND app.can_read_project(project_id));

ALTER TABLE app.operation_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.operation_receipts FORCE ROW LEVEL SECURITY;
CREATE POLICY actor_scope ON app.operation_receipts
  USING (workspace_id = app.current_workspace_id() AND actor_profile_id = app.current_profile_id() AND (project_id IS NULL OR app.can_read_project(project_id)))
  WITH CHECK (workspace_id = app.current_workspace_id() AND actor_profile_id = app.current_profile_id() AND (project_id IS NULL OR app.can_read_project(project_id)));

CREATE FUNCTION app.reject_history_mutation() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
  RAISE EXCEPTION 'Historical records are immutable' USING ERRCODE = '55000';
END
$$;

CREATE TRIGGER record_versions_immutable BEFORE UPDATE OR DELETE ON app.record_versions
  FOR EACH ROW EXECUTE FUNCTION app.reject_history_mutation();
CREATE TRIGGER audit_events_immutable BEFORE UPDATE OR DELETE ON app.audit_events
  FOR EACH ROW EXECUTE FUNCTION app.reject_history_mutation();
CREATE TRIGGER operation_receipts_immutable BEFORE UPDATE OR DELETE ON app.operation_receipts
  FOR EACH ROW EXECUTE FUNCTION app.reject_history_mutation();

-- Validate final transaction state, not a stale NEW image from an earlier update.
CREATE FUNCTION app.check_assignment_access() RETURNS trigger
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
        OR NOT coalesce('read_project' = ANY(role.permissions), false))
  ) THEN
    RAISE EXCEPTION 'Task assignments require an active profile and active project read access' USING ERRCODE = '23514';
  END IF;
  RETURN NULL;
END
$$;

CREATE CONSTRAINT TRIGGER assignment_access_valid AFTER INSERT OR UPDATE ON app.task_assignments
  DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION app.check_assignment_access();
CREATE CONSTRAINT TRIGGER grant_assignment_access_valid AFTER UPDATE OR DELETE ON app.project_access
  DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION app.check_assignment_access();
CREATE CONSTRAINT TRIGGER profile_assignment_access_valid AFTER UPDATE OR DELETE ON app.profiles
  DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION app.check_assignment_access();
CREATE CONSTRAINT TRIGGER role_assignment_access_valid AFTER UPDATE ON app.roles
  DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION app.check_assignment_access();

CREATE FUNCTION app.check_task_milestone_phase() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  target_workspace uuid;
  target_task uuid;
  target_milestone uuid;
BEGIN
  target_workspace := NEW.workspace_id;
  IF TG_TABLE_NAME = 'tasks' THEN
    target_task := NEW.id;
  ELSE
    target_milestone := NEW.id;
  END IF;
  IF EXISTS (
    SELECT 1 FROM app.tasks AS task
    JOIN app.milestones AS milestone
      ON milestone.workspace_id = task.workspace_id AND milestone.project_id = task.project_id AND milestone.id = task.milestone_id
    WHERE task.workspace_id = target_workspace
      AND (target_task IS NULL OR task.id = target_task)
      AND (target_milestone IS NULL OR milestone.id = target_milestone)
      AND milestone.phase_id IS NOT NULL AND task.phase_id IS DISTINCT FROM milestone.phase_id
  ) THEN
    RAISE EXCEPTION 'Tasks linked to a phase milestone must belong to that phase' USING ERRCODE = '23514';
  END IF;
  RETURN NULL;
END
$$;

CREATE CONSTRAINT TRIGGER task_milestone_phase_valid AFTER INSERT OR UPDATE ON app.tasks
  DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION app.check_task_milestone_phase();
CREATE CONSTRAINT TRIGGER milestone_task_phases_valid AFTER INSERT OR UPDATE ON app.milestones
  DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION app.check_task_milestone_phase();

REVOKE ALL ON ALL TABLES IN SCHEMA app FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA app FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA app FROM PUBLIC;
