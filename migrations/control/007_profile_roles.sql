-- A person's current role is independent of the invitation that first enrolled
-- them. Keep its signed assignment reference, including for suspended profiles.
ALTER TABLE security.profiles
  ADD COLUMN role_id uuid,
  ADD COLUMN role_revision bigint CHECK (role_revision > 0),
  ADD COLUMN role_assignment_object_id uuid,
  ADD CONSTRAINT profiles_role_assignment_complete CHECK (
    (role_id IS NULL AND role_revision IS NULL AND role_assignment_object_id IS NULL) OR
    (role_id IS NOT NULL AND role_revision IS NOT NULL AND role_assignment_object_id IS NOT NULL)),
  ADD CONSTRAINT profiles_role_fk FOREIGN KEY(workspace_id,role_id)
    REFERENCES security.roles(workspace_id,role_id) DEFERRABLE INITIALLY DEFERRED,
  ADD CONSTRAINT profiles_role_assignment_fk FOREIGN KEY(workspace_id,role_assignment_object_id)
    REFERENCES security.staged_objects(workspace_id,object_id) DEFERRABLE INITIALLY DEFERRED;

-- Backfill only from already committed authority. An arbitrary grant or staged
-- invitation cannot establish a role. Newer enrolment/promotion takes priority
-- over genesis, and signature bytes, immutable objects and history stay intact.
DO $$
DECLARE item record;
  previous_workspace text := current_setting('ukda.workspace_id',true);
BEGIN
  FOR item IN
    SELECT DISTINCT ON (o.workspace_id,p.profile_id)
      o.workspace_id,p.profile_id,o.object_id,r.role_id,
      (o.versioned_object->'body'->'transcript'->'binding'->'role'->>'revision')::bigint AS role_revision
    FROM security.staged_objects o
    JOIN security.security_transitions t ON t.workspace_id=o.workspace_id
      AND t.sequence=o.committed_security_version AND t.head=o.object_hash AND t.signed_transition=o.versioned_object
    JOIN security.profiles p ON p.workspace_id=o.workspace_id
      AND p.profile_id::text=o.versioned_object->'body'->'transcript'->'binding'->>'accountId'
    JOIN security.roles r ON r.workspace_id=o.workspace_id
      AND r.role_id::text=o.versioned_object->'body'->'transcript'->'binding'->'role'->>'id'
    WHERE o.object_kind='signed_grant' AND o.state='committed'
      AND o.versioned_object->'body'->>'purpose' IN ('ukda.profile-enrolment.v1','ukda.owner-promotion.v1')
      AND o.versioned_object->'body'->'transcript'->'binding'->>'workspaceId'=o.workspace_id::text
      AND o.versioned_object->'body'->'transcript'->'binding'->'role'->>'revision' ~ '^[1-9][0-9]{0,17}$'
    ORDER BY o.workspace_id,p.profile_id,o.committed_security_version DESC
  LOOP
    PERFORM set_config('ukda.workspace_id',item.workspace_id::text,true);
    UPDATE security.profiles SET role_id=item.role_id,role_revision=item.role_revision,role_assignment_object_id=item.object_id
      WHERE workspace_id=item.workspace_id AND profile_id=item.profile_id
        AND item.role_revision <= (SELECT revision FROM security.roles WHERE workspace_id=item.workspace_id AND role_id=item.role_id);
  END LOOP;
  FOR item IN
    SELECT o.workspace_id,p.profile_id,o.object_id,r.role_id
    FROM security.workspaces w
    JOIN security.staged_objects o ON o.workspace_id=w.workspace_id AND o.object_id=w.genesis_object_id
    JOIN security.security_transitions t ON t.workspace_id=o.workspace_id AND t.sequence=1
      AND t.head=o.object_hash AND t.signed_transition->'genesis'=o.versioned_object
    JOIN security.profiles p ON p.workspace_id=o.workspace_id AND p.role_id IS NULL
      AND p.profile_id::text=o.versioned_object->'body'->>'accountId'
    JOIN security.roles r ON r.workspace_id=o.workspace_id AND r.template='owner'
      AND r.role_id::text=o.versioned_object->'body'->'roles'->>'owner'
    WHERE o.object_kind='genesis' AND o.state='committed' AND o.committed_security_version=1
      AND o.versioned_object->'body'->>'purpose'='ukda.genesis.v1'
      AND o.versioned_object->'body'->>'workspaceId'=o.workspace_id::text
      AND o.versioned_object->'body'->>'genesisId'=o.object_id::text
  LOOP
    PERFORM set_config('ukda.workspace_id',item.workspace_id::text,true);
    UPDATE security.profiles SET role_id=item.role_id,role_revision=1,role_assignment_object_id=item.object_id
      WHERE workspace_id=item.workspace_id AND profile_id=item.profile_id;
  END LOOP;
  PERFORM set_config('ukda.workspace_id',coalesce(previous_workspace,''),true);
END $$;
