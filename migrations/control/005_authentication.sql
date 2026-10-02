-- Pre-authentication attempts are service-global because an unknown account
-- must produce the same OPAQUE exchange without creating a fake profile.
-- No HTTP route may expose this table or select arbitrary attempt metadata.
CREATE TABLE security.auth_attempts (
    login_id uuid PRIMARY KEY,
    purpose text NOT NULL CHECK (purpose IN ('login', 'reauthentication')),
    workspace_id uuid NOT NULL,
    profile_id uuid NOT NULL,
    eligible boolean NOT NULL,
    expected_credential_generation bigint NOT NULL CHECK (expected_credential_generation >= 0),
    expected_session_generation bigint NOT NULL CHECK (expected_session_generation >= 0),
    expected_data_generation bigint NOT NULL CHECK (expected_data_generation >= 0),
    source_session_id uuid,
    source_device_id uuid,
    state text NOT NULL DEFAULT 'issued' CHECK (state IN ('issued', 'consumed')),
    server_state_ciphertext text,
    server_state_key_id text,
    outcome text CHECK (outcome IN ('verified', 'failed')),
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    CHECK (expires_at > created_at AND expires_at <= created_at + interval '2 minutes'),
    CHECK ((purpose = 'login' AND source_session_id IS NULL AND source_device_id IS NULL) OR
           (purpose = 'reauthentication' AND source_session_id IS NOT NULL AND source_device_id IS NOT NULL AND eligible)),
    CHECK (NOT eligible OR (expected_credential_generation > 0 AND expected_session_generation > 0 AND expected_data_generation > 0)),
    CHECK ((state = 'issued' AND server_state_ciphertext IS NOT NULL AND server_state_key_id IS NOT NULL AND
            outcome IS NULL AND consumed_at IS NULL) OR
           (state = 'consumed' AND server_state_ciphertext IS NULL AND server_state_key_id IS NULL AND
            outcome IS NOT NULL AND consumed_at IS NOT NULL))
);
CREATE INDEX auth_attempts_expiry ON security.auth_attempts (expires_at);
CREATE INDEX auth_attempts_account ON security.auth_attempts (workspace_id, profile_id, expires_at)
    WHERE state = 'issued';

-- Bind encrypted state to immutable context; a consumed proof never becomes usable again.
CREATE FUNCTION security.guard_auth_attempt() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    IF ROW(NEW.login_id, NEW.purpose, NEW.workspace_id, NEW.profile_id, NEW.eligible,
           NEW.expected_credential_generation, NEW.expected_session_generation, NEW.expected_data_generation,
           NEW.source_session_id, NEW.source_device_id, NEW.created_at, NEW.expires_at)
       IS DISTINCT FROM
       ROW(OLD.login_id, OLD.purpose, OLD.workspace_id, OLD.profile_id, OLD.eligible,
           OLD.expected_credential_generation, OLD.expected_session_generation, OLD.expected_data_generation,
           OLD.source_session_id, OLD.source_device_id, OLD.created_at, OLD.expires_at) OR
       OLD.state = 'consumed' OR NEW.state <> 'consumed' THEN
        RAISE EXCEPTION 'authentication proof identity cannot change or be reused' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER auth_attempts_single_use BEFORE UPDATE ON security.auth_attempts
    FOR EACH ROW EXECUTE FUNCTION security.guard_auth_attempt();

-- Password changes stage a registration separately from public ceremony state.
ALTER TABLE security.ceremonies ADD COLUMN staged_registration_record text
    CHECK (staged_registration_record ~ '^[A-Za-z0-9_-]+$');
