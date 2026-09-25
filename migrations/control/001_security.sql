-- Security authority lives in this database. Application rows are projections.
-- Run as the migration role; the request-serving role must not own these tables
-- or have BYPASSRLS. Global entitlement tables are service-only: they cannot
-- require tenant context before activation. Backend operations must validate
-- the entitlement/resume verifier and reservation generation; no generic API
-- exposes these tables. Runtime DML privileges do not constitute user access.
CREATE SCHEMA IF NOT EXISTS security;

CREATE TABLE security.licences (
    licence_id uuid PRIMARY KEY,
    verification_digest bytea NOT NULL CHECK (octet_length(verification_digest) = 32),
    verification_key_id text NOT NULL CHECK (verification_key_id <> ''),
    state text NOT NULL DEFAULT 'available'
        CHECK (state IN ('available', 'reserved', 'activated', 'revoked', 'legacy_expired')),
    reservation_generation bigint NOT NULL DEFAULT 0 CHECK (reservation_generation >= 0),
    activated_workspace_id uuid,
    activated_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (verification_key_id, verification_digest),
    UNIQUE (activated_workspace_id),
    CHECK ((activated_workspace_id IS NULL) = (activated_at IS NULL)),
    CHECK (state <> 'activated' OR activated_workspace_id IS NOT NULL),
    CHECK (state NOT IN ('available', 'reserved') OR activated_workspace_id IS NULL)
);

CREATE TABLE security.activation_attempts (
    activation_id uuid PRIMARY KEY,
    licence_id uuid NOT NULL REFERENCES security.licences (licence_id),
    operation_id uuid NOT NULL UNIQUE,
    workspace_id uuid NOT NULL,
    reservation_generation bigint NOT NULL CHECK (reservation_generation > 0),
    resume_digest bytea NOT NULL CHECK (octet_length(resume_digest) = 32),
    resume_key_id text NOT NULL CHECK (resume_key_id <> ''),
    state text NOT NULL DEFAULT 'reserved'
        CHECK (state IN ('reserved', 'completed', 'expired', 'cancelled')),
    staged_public_state jsonb NOT NULL DEFAULT '{}'::jsonb
        CHECK (jsonb_typeof(staged_public_state) = 'object'),
    request_hash text CHECK (request_hash ~ '^[0-9a-f]{64}$'),
    completion_receipt jsonb CHECK (jsonb_typeof(completion_receipt) = 'object'),
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    completed_at timestamptz,
    resume_expires_at timestamptz NOT NULL,
    UNIQUE (licence_id, reservation_generation),
    UNIQUE (resume_key_id, resume_digest),
    CHECK (expires_at > created_at),
    CHECK (resume_expires_at > created_at),
    CHECK (state <> 'completed' OR
        (completed_at IS NOT NULL AND request_hash IS NOT NULL AND completion_receipt IS NOT NULL))
);
CREATE UNIQUE INDEX activation_attempts_one_reservation
    ON security.activation_attempts (licence_id) WHERE state = 'reserved';

CREATE TABLE security.workspaces (
    workspace_id uuid PRIMARY KEY,
    licence_id uuid NOT NULL UNIQUE REFERENCES security.licences (licence_id),
    lifecycle text NOT NULL DEFAULT 'pending_activation'
        CHECK (lifecycle IN ('pending_activation', 'active', 'pending_deletion', 'deleted')),
    licence_state text NOT NULL DEFAULT 'active'
        CHECK (licence_state IN ('active', 'restricted', 'revoked')),
    security_head text NOT NULL DEFAULT repeat('0', 64)
        CHECK (security_head ~ '^[0-9a-f]{64}$'),
    security_version bigint NOT NULL DEFAULT 0 CHECK (security_version >= 0),
    data_generation bigint NOT NULL DEFAULT 1 CHECK (data_generation > 0),
    ownership_version bigint NOT NULL DEFAULT 0 CHECK (ownership_version >= 0),
    custody_epoch bigint NOT NULL DEFAULT 0 CHECK (custody_epoch >= 0),
    write_schema integer NOT NULL DEFAULT 1 CHECK (write_schema > 0),
    content_maintenance boolean NOT NULL DEFAULT false,
    restore_quarantine boolean NOT NULL DEFAULT false,
    genesis_object_id uuid,
    activated_at timestamptz,
    deletion_requested_at timestamptz,
    delete_after timestamptz,
    deleted_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CHECK ((security_version = 0 AND security_head = repeat('0', 64)) OR
           (security_version > 0 AND security_head <> repeat('0', 64))),
    CHECK (lifecycle <> 'active' OR activated_at IS NOT NULL),
    CHECK (lifecycle <> 'pending_deletion' OR
        (deletion_requested_at IS NOT NULL AND delete_after IS NOT NULL AND delete_after > deletion_requested_at)),
    CHECK (lifecycle <> 'deleted' OR deleted_at IS NOT NULL)
);

CREATE TABLE security.staged_objects (
    workspace_id uuid NOT NULL REFERENCES security.workspaces (workspace_id) ON DELETE CASCADE,
    object_id uuid NOT NULL,
    object_kind text NOT NULL
        CHECK (object_kind IN ('genesis', 'encrypted_profile', 'key_envelope', 'custody_manifest', 'signed_grant')),
    object_hash text NOT NULL CHECK (object_hash ~ '^[0-9a-f]{64}$'),
    versioned_object jsonb NOT NULL CHECK (jsonb_typeof(versioned_object) = 'object'),
    staged_operation_id uuid NOT NULL,
    state text NOT NULL DEFAULT 'staged' CHECK (state IN ('staged', 'committed')),
    committed_security_version bigint CHECK (committed_security_version > 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz,
    PRIMARY KEY (workspace_id, object_id),
    UNIQUE (workspace_id, object_hash),
    CHECK (state <> 'committed' OR committed_security_version IS NOT NULL),
    CHECK (expires_at IS NULL OR expires_at > created_at)
);
ALTER TABLE security.workspaces ADD CONSTRAINT workspaces_genesis_object_fk
    FOREIGN KEY (workspace_id, genesis_object_id)
    REFERENCES security.staged_objects (workspace_id, object_id)
    DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE security.profiles (
    workspace_id uuid NOT NULL REFERENCES security.workspaces (workspace_id) ON DELETE CASCADE,
    profile_id uuid NOT NULL,
    state text NOT NULL DEFAULT 'pending'
        CHECK (state IN ('pending', 'active', 'suspended', 'removed')),
    is_owner boolean NOT NULL DEFAULT false,
    owner_ready_at timestamptz,
    profile_object_id uuid,
    credential_generation bigint NOT NULL DEFAULT 0 CHECK (credential_generation >= 0),
    session_generation bigint NOT NULL DEFAULT 1 CHECK (session_generation > 0),
    invitation_generation bigint NOT NULL DEFAULT 0 CHECK (invitation_generation >= 0),
    reset_generation bigint NOT NULL DEFAULT 0 CHECK (reset_generation >= 0),
    recovery_generation bigint NOT NULL DEFAULT 0 CHECK (recovery_generation >= 0),
    opaque_registration_record text CHECK (opaque_registration_record ~ '^[A-Za-z0-9_-]+$'),
    opaque_setup_id text,
    opaque_config_id text,
    opaque_identifiers jsonb CHECK (jsonb_typeof(opaque_identifiers) = 'object'),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    removed_at timestamptz,
    PRIMARY KEY (workspace_id, profile_id),
    FOREIGN KEY (workspace_id, profile_object_id)
        REFERENCES security.staged_objects (workspace_id, object_id)
        DEFERRABLE INITIALLY DEFERRED,
    CHECK (is_owner = (owner_ready_at IS NOT NULL)),
    CHECK (state <> 'removed' OR removed_at IS NOT NULL),
    CHECK ((opaque_registration_record IS NULL AND opaque_setup_id IS NULL AND
            opaque_config_id IS NULL AND opaque_identifiers IS NULL) OR
           (opaque_registration_record IS NOT NULL AND opaque_setup_id IS NOT NULL AND opaque_setup_id <> '' AND
            opaque_config_id IS NOT NULL AND opaque_config_id <> '' AND opaque_identifiers IS NOT NULL AND credential_generation > 0)),
    CHECK (state <> 'active' OR opaque_registration_record IS NOT NULL)
);

CREATE TABLE security.devices (
    workspace_id uuid NOT NULL,
    device_id uuid NOT NULL,
    profile_id uuid NOT NULL,
    key_generation bigint NOT NULL CHECK (key_generation > 0),
    signing_public_key bytea NOT NULL CHECK (octet_length(signing_public_key) = 32),
    recipient_public_key bytea NOT NULL CHECK (octet_length(recipient_public_key) = 32),
    state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'active', 'revoked')),
    approval_security_version bigint CHECK (approval_security_version > 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    approved_at timestamptz,
    revoked_at timestamptz,
    PRIMARY KEY (workspace_id, device_id),
    UNIQUE (workspace_id, device_id, profile_id),
    FOREIGN KEY (workspace_id, profile_id)
        REFERENCES security.profiles (workspace_id, profile_id) ON DELETE CASCADE,
    CHECK (state <> 'active' OR (approved_at IS NOT NULL AND revoked_at IS NULL)),
    CHECK (state <> 'revoked' OR revoked_at IS NOT NULL)
);
CREATE INDEX devices_by_profile ON security.devices (workspace_id, profile_id, state);

CREATE TABLE security.recovery_authorities (
    workspace_id uuid NOT NULL,
    profile_id uuid NOT NULL,
    generation bigint NOT NULL CHECK (generation > 0),
    proof_public_key bytea NOT NULL CHECK (octet_length(proof_public_key) = 32),
    recipient_public_key bytea NOT NULL CHECK (octet_length(recipient_public_key) = 32),
    custody_envelope_object_id uuid NOT NULL,
    custody_epoch bigint NOT NULL CHECK (custody_epoch > 0),
    state text NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'revoked')),
    kit_verified_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz,
    PRIMARY KEY (workspace_id, profile_id, generation),
    FOREIGN KEY (workspace_id, profile_id)
        REFERENCES security.profiles (workspace_id, profile_id) ON DELETE CASCADE,
    FOREIGN KEY (workspace_id, custody_envelope_object_id)
        REFERENCES security.staged_objects (workspace_id, object_id)
        DEFERRABLE INITIALLY DEFERRED,
    CHECK (state <> 'revoked' OR revoked_at IS NOT NULL),
    CHECK (state <> 'active' OR revoked_at IS NULL)
);
CREATE UNIQUE INDEX recovery_authorities_one_active
    ON security.recovery_authorities (workspace_id, profile_id) WHERE state = 'active';

CREATE TABLE security.grants (
    workspace_id uuid NOT NULL,
    grant_id uuid NOT NULL,
    profile_id uuid NOT NULL,
    device_id uuid,
    grant_kind text NOT NULL CHECK (grant_kind IN ('owner', 'device', 'project', 'recovery')),
    scope_kind text NOT NULL CHECK (scope_kind IN ('workspace', 'project')),
    scope_id uuid,
    generation bigint NOT NULL CHECK (generation > 0),
    permissions text[] NOT NULL DEFAULT ARRAY[]::text[],
    state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'active', 'revoked')),
    signed_grant_object_id uuid NOT NULL,
    key_manifest_object_id uuid,
    security_version bigint CHECK (security_version > 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    activated_at timestamptz,
    revoked_at timestamptz,
    expires_at timestamptz,
    PRIMARY KEY (workspace_id, grant_id),
    FOREIGN KEY (workspace_id, profile_id)
        REFERENCES security.profiles (workspace_id, profile_id) ON DELETE CASCADE,
    FOREIGN KEY (workspace_id, device_id, profile_id)
        REFERENCES security.devices (workspace_id, device_id, profile_id),
    FOREIGN KEY (workspace_id, signed_grant_object_id)
        REFERENCES security.staged_objects (workspace_id, object_id)
        DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (workspace_id, key_manifest_object_id)
        REFERENCES security.staged_objects (workspace_id, object_id)
        DEFERRABLE INITIALLY DEFERRED,
    CHECK ((scope_kind = 'workspace' AND scope_id IS NULL) OR
           (scope_kind = 'project' AND scope_id IS NOT NULL)),
    CHECK (grant_kind <> 'owner' OR scope_kind = 'workspace'),
    CHECK (grant_kind <> 'device' OR device_id IS NOT NULL),
    CHECK (permissions <@ ARRAY['read_project', 'comment', 'create_tasks',
        'edit_assigned_tasks', 'manage_tasks', 'approve_tasks', 'plan_projects']::text[]),
    CHECK (state <> 'active' OR (activated_at IS NOT NULL AND security_version IS NOT NULL AND revoked_at IS NULL)),
    CHECK (state <> 'revoked' OR revoked_at IS NOT NULL),
    CHECK (expires_at IS NULL OR expires_at > created_at)
);
CREATE INDEX grants_by_subject_scope
    ON security.grants (workspace_id, profile_id, scope_kind, scope_id, state);

CREATE TABLE security.ceremonies (
    workspace_id uuid NOT NULL,
    ceremony_id uuid NOT NULL,
    profile_id uuid NOT NULL,
    kind text NOT NULL CHECK (kind IN ('invitation', 'member_reset', 'owner_reset',
        'owner_promotion', 'device_pair', 'owner_recovery', 'password_change',
        'opaque_login', 'device_challenge')),
    generation bigint NOT NULL CHECK (generation > 0),
    state text NOT NULL DEFAULT 'issued'
        CHECK (state IN ('issued', 'waiting_approval', 'completed', 'expired', 'cancelled', 'revoked')),
    verification_digest bytea CHECK (octet_length(verification_digest) = 32),
    verification_key_id text,
    device_id uuid,
    approving_profile_id uuid,
    approving_device_id uuid,
    expected_credential_generation bigint NOT NULL CHECK (expected_credential_generation >= 0),
    expected_ownership_version bigint NOT NULL CHECK (expected_ownership_version >= 0),
    expected_security_version bigint NOT NULL CHECK (expected_security_version >= 0),
    expected_custody_epoch bigint NOT NULL CHECK (expected_custody_epoch >= 0),
    transcript_hash text CHECK (transcript_hash ~ '^[0-9a-f]{64}$'),
    public_state jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(public_state) = 'object'),
    server_state_ciphertext bytea,
    server_state_key_id text,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    completed_at timestamptz,
    PRIMARY KEY (workspace_id, ceremony_id),
    FOREIGN KEY (workspace_id, profile_id)
        REFERENCES security.profiles (workspace_id, profile_id) ON DELETE CASCADE,
    FOREIGN KEY (workspace_id, device_id, profile_id)
        REFERENCES security.devices (workspace_id, device_id, profile_id),
    FOREIGN KEY (workspace_id, approving_profile_id)
        REFERENCES security.profiles (workspace_id, profile_id),
    FOREIGN KEY (workspace_id, approving_device_id, approving_profile_id)
        REFERENCES security.devices (workspace_id, device_id, profile_id),
    CHECK ((verification_digest IS NULL) = (verification_key_id IS NULL)),
    CHECK ((server_state_ciphertext IS NULL) = (server_state_key_id IS NULL)),
    CHECK (approving_device_id IS NULL OR approving_profile_id IS NOT NULL),
    CHECK (expires_at > created_at),
    CHECK (state <> 'completed' OR completed_at IS NOT NULL)
);
CREATE UNIQUE INDEX ceremonies_one_invitation
    ON security.ceremonies (workspace_id, profile_id) WHERE
        kind = 'invitation' AND state IN ('issued', 'waiting_approval');
CREATE UNIQUE INDEX ceremonies_one_reset
    ON security.ceremonies (workspace_id, profile_id) WHERE
        kind IN ('member_reset', 'owner_reset') AND state IN ('issued', 'waiting_approval');
CREATE INDEX ceremonies_expiry ON security.ceremonies (workspace_id, expires_at)
    WHERE state IN ('issued', 'waiting_approval');

CREATE TABLE security.sessions (
    workspace_id uuid NOT NULL,
    session_id uuid NOT NULL,
    profile_id uuid NOT NULL,
    device_id uuid,
    token_digest bytea NOT NULL CHECK (octet_length(token_digest) = 32),
    token_key_id text NOT NULL CHECK (token_key_id <> ''),
    csrf_digest bytea NOT NULL CHECK (octet_length(csrf_digest) = 32),
    access_level text NOT NULL CHECK (access_level IN ('setup', 'restricted', 'device_approved', 'recovery', 'restore')),
    credential_generation bigint NOT NULL CHECK (credential_generation >= 0),
    session_generation bigint NOT NULL CHECK (session_generation > 0),
    data_generation bigint NOT NULL CHECK (data_generation > 0),
    authenticated_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    idle_expires_at timestamptz NOT NULL,
    absolute_expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    PRIMARY KEY (workspace_id, session_id),
    UNIQUE (token_key_id, token_digest),
    FOREIGN KEY (workspace_id, profile_id)
        REFERENCES security.profiles (workspace_id, profile_id) ON DELETE CASCADE,
    FOREIGN KEY (workspace_id, device_id, profile_id)
        REFERENCES security.devices (workspace_id, device_id, profile_id),
    CHECK (access_level <> 'device_approved' OR device_id IS NOT NULL),
    CHECK (created_at < absolute_expires_at AND idle_expires_at <= absolute_expires_at),
    CHECK (idle_expires_at > created_at)
);
CREATE INDEX sessions_by_profile ON security.sessions (workspace_id, profile_id) WHERE revoked_at IS NULL;

CREATE TABLE security.security_transitions (
    workspace_id uuid NOT NULL REFERENCES security.workspaces (workspace_id) ON DELETE CASCADE,
    sequence bigint NOT NULL CHECK (sequence > 0),
    operation_id uuid NOT NULL,
    previous_head text NOT NULL CHECK (previous_head ~ '^[0-9a-f]{64}$'),
    head text NOT NULL CHECK (head ~ '^[0-9a-f]{64}$'),
    action text NOT NULL CHECK (action <> ''),
    actor_kind text NOT NULL CHECK (actor_kind IN ('device', 'recovery', 'service')),
    actor_profile_id uuid,
    actor_device_id uuid,
    signed_transition jsonb NOT NULL CHECK (jsonb_typeof(signed_transition) = 'object'),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (workspace_id, sequence),
    UNIQUE (workspace_id, operation_id),
    UNIQUE (workspace_id, sequence, operation_id),
    UNIQUE (workspace_id, head),
    CHECK (actor_kind <> 'device' OR (actor_profile_id IS NOT NULL AND actor_device_id IS NOT NULL)),
    CHECK (actor_kind <> 'recovery' OR actor_profile_id IS NOT NULL)
);

CREATE TABLE security.operation_receipts (
    workspace_id uuid NOT NULL,
    operation_id uuid NOT NULL,
    request_hash text NOT NULL CHECK (request_hash ~ '^[0-9a-f]{64}$'),
    operation_kind text NOT NULL CHECK (operation_kind <> ''),
    security_version bigint NOT NULL CHECK (security_version > 0),
    outcome jsonb NOT NULL CHECK (jsonb_typeof(outcome) = 'object'),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (workspace_id, operation_id),
    FOREIGN KEY (workspace_id, security_version, operation_id)
        REFERENCES security.security_transitions (workspace_id, sequence, operation_id) ON DELETE CASCADE
);

ALTER TABLE security.staged_objects ADD CONSTRAINT staged_objects_commit_transition_fk
    FOREIGN KEY (workspace_id, committed_security_version)
    REFERENCES security.security_transitions (workspace_id, sequence)
    DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE security.devices ADD CONSTRAINT devices_approval_transition_fk
    FOREIGN KEY (workspace_id, approval_security_version)
    REFERENCES security.security_transitions (workspace_id, sequence)
    DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE security.grants ADD CONSTRAINT grants_transition_fk
    FOREIGN KEY (workspace_id, security_version)
    REFERENCES security.security_transitions (workspace_id, sequence)
    DEFERRABLE INITIALLY DEFERRED;

-- Deliberately no workspace FK: these opaque markers outlive erased tenants.
CREATE TABLE security.deletion_tombstones (
    workspace_id uuid NOT NULL,
    entity_kind text NOT NULL CHECK (entity_kind IN ('workspace', 'profile')),
    entity_id uuid NOT NULL,
    deleted_at timestamptz NOT NULL,
    security_version bigint NOT NULL CHECK (security_version > 0),
    PRIMARY KEY (workspace_id, entity_kind, entity_id),
    CHECK (entity_kind <> 'workspace' OR entity_id = workspace_id)
);

CREATE FUNCTION security.reject_immutable_update() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    RAISE EXCEPTION 'immutable security record cannot be updated' USING ERRCODE = '23514';
END;
$$;
CREATE TRIGGER security_transitions_immutable BEFORE UPDATE ON security.security_transitions
    FOR EACH ROW EXECUTE FUNCTION security.reject_immutable_update();
CREATE TRIGGER operation_receipts_immutable BEFORE UPDATE ON security.operation_receipts
    FOR EACH ROW EXECUTE FUNCTION security.reject_immutable_update();
CREATE TRIGGER deletion_tombstones_immutable BEFORE UPDATE OR DELETE ON security.deletion_tombstones
    FOR EACH ROW EXECUTE FUNCTION security.reject_immutable_update();

CREATE FUNCTION security.guard_object_identity() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    IF NEW.workspace_id IS DISTINCT FROM OLD.workspace_id OR
       NEW.object_id IS DISTINCT FROM OLD.object_id OR
       NEW.object_kind IS DISTINCT FROM OLD.object_kind OR
       NEW.object_hash IS DISTINCT FROM OLD.object_hash OR
       NEW.versioned_object IS DISTINCT FROM OLD.versioned_object OR
       NEW.staged_operation_id IS DISTINCT FROM OLD.staged_operation_id THEN
        RAISE EXCEPTION 'staged security object content is immutable' USING ERRCODE = '23514';
    END IF;
    IF OLD.state = 'committed' AND (NEW.state <> 'committed' OR
       NEW.committed_security_version IS DISTINCT FROM OLD.committed_security_version) THEN
        RAISE EXCEPTION 'committed security object cannot be restaged' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER staged_objects_immutable_content BEFORE UPDATE ON security.staged_objects
    FOR EACH ROW EXECUTE FUNCTION security.guard_object_identity();

CREATE FUNCTION security.guard_monotone_workspace() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    IF NEW.workspace_id IS DISTINCT FROM OLD.workspace_id OR
       NEW.licence_id IS DISTINCT FROM OLD.licence_id OR
       NEW.security_version < OLD.security_version OR
       NEW.data_generation < OLD.data_generation OR
       NEW.ownership_version < OLD.ownership_version OR
       NEW.custody_epoch < OLD.custody_epoch OR
       NEW.write_schema < OLD.write_schema OR
       (OLD.genesis_object_id IS NOT NULL AND NEW.genesis_object_id IS DISTINCT FROM OLD.genesis_object_id) OR
       (NEW.security_head IS DISTINCT FROM OLD.security_head AND NEW.security_version <= OLD.security_version) OR
       (OLD.lifecycle = 'deleted' AND NEW.lifecycle <> 'deleted') THEN
        RAISE EXCEPTION 'security state cannot regress or change identity' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER workspaces_monotone BEFORE UPDATE ON security.workspaces
    FOR EACH ROW EXECUTE FUNCTION security.guard_monotone_workspace();

CREATE FUNCTION security.guard_profile_generations() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    IF NEW.workspace_id IS DISTINCT FROM OLD.workspace_id OR
       NEW.profile_id IS DISTINCT FROM OLD.profile_id OR
       NEW.credential_generation < OLD.credential_generation OR
       NEW.session_generation < OLD.session_generation OR
       NEW.invitation_generation < OLD.invitation_generation OR
       NEW.reset_generation < OLD.reset_generation OR
       NEW.recovery_generation < OLD.recovery_generation OR
       (OLD.state = 'removed' AND NEW.state <> 'removed') THEN
        RAISE EXCEPTION 'profile identity or generations cannot regress' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER profiles_monotone BEFORE UPDATE ON security.profiles
    FOR EACH ROW EXECUTE FUNCTION security.guard_profile_generations();

CREATE FUNCTION security.guard_device_identity() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    IF NEW.workspace_id IS DISTINCT FROM OLD.workspace_id OR
       NEW.device_id IS DISTINCT FROM OLD.device_id OR
       NEW.profile_id IS DISTINCT FROM OLD.profile_id OR
       NEW.key_generation IS DISTINCT FROM OLD.key_generation OR
       NEW.signing_public_key IS DISTINCT FROM OLD.signing_public_key OR
       NEW.recipient_public_key IS DISTINCT FROM OLD.recipient_public_key OR
       (OLD.state = 'revoked' AND NEW.state <> 'revoked') OR
       (OLD.state = 'active' AND NEW.state = 'pending') THEN
        RAISE EXCEPTION 'device identity and retired grants are immutable' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER devices_identity_immutable BEFORE UPDATE ON security.devices
    FOR EACH ROW EXECUTE FUNCTION security.guard_device_identity();

CREATE FUNCTION security.guard_recovery_identity() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    IF NEW.workspace_id IS DISTINCT FROM OLD.workspace_id OR
       NEW.profile_id IS DISTINCT FROM OLD.profile_id OR
       NEW.generation IS DISTINCT FROM OLD.generation OR
       NEW.proof_public_key IS DISTINCT FROM OLD.proof_public_key OR
       NEW.recipient_public_key IS DISTINCT FROM OLD.recipient_public_key OR
       NEW.custody_epoch < OLD.custody_epoch OR
       (OLD.state = 'revoked' AND NEW.state <> 'revoked') THEN
        RAISE EXCEPTION 'recovery identity or custody epoch cannot regress' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER recovery_authorities_identity_immutable BEFORE UPDATE ON security.recovery_authorities
    FOR EACH ROW EXECUTE FUNCTION security.guard_recovery_identity();

CREATE FUNCTION security.guard_consumed_licence() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    IF NEW.reservation_generation < OLD.reservation_generation OR
       (OLD.activated_workspace_id IS NOT NULL AND
        (NEW.activated_workspace_id IS DISTINCT FROM OLD.activated_workspace_id OR
         NEW.activated_at IS DISTINCT FROM OLD.activated_at)) THEN
        RAISE EXCEPTION 'consumed licence or reservation generation cannot regress' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER licences_consumption_immutable BEFORE UPDATE ON security.licences
    FOR EACH ROW EXECUTE FUNCTION security.guard_consumed_licence();

-- Every tenant table denies access with an absent/empty tenant context. Invalid
-- UUID context is an error, never a permissive fallback. The application binds
-- this setting transaction-locally after authentication, never from an unchecked
-- request header. FORCE RLS also applies to non-BYPASSRLS table owners.
DO $$
DECLARE table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY['workspaces', 'staged_objects', 'profiles',
        'devices', 'recovery_authorities', 'grants', 'ceremonies', 'sessions',
        'security_transitions', 'operation_receipts', 'deletion_tombstones'] LOOP
        EXECUTE format('ALTER TABLE security.%I ENABLE ROW LEVEL SECURITY', table_name);
        EXECUTE format('ALTER TABLE security.%I FORCE ROW LEVEL SECURITY', table_name);
        EXECUTE format(
            'CREATE POLICY tenant_workspace ON security.%I USING (workspace_id = nullif(current_setting(''ukda.workspace_id'', true), '''')::uuid) WITH CHECK (workspace_id = nullif(current_setting(''ukda.workspace_id'', true), '''')::uuid)',
            table_name
        );
    END LOOP;
END;
$$;

REVOKE ALL ON ALL TABLES IN SCHEMA security FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA security FROM PUBLIC;
