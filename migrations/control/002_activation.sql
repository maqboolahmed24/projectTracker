ALTER TABLE security.activation_attempts
  ADD COLUMN draft_generation bigint NOT NULL DEFAULT 1 CHECK (draft_generation > 0),
  ADD COLUMN staged_payload_hash text CHECK (staged_payload_hash ~ '^[a-f0-9]{64}$'),
  ADD COLUMN proof_id uuid,
  ADD COLUMN proof_server_state text,
  ADD COLUMN proof_expires_at timestamptz,
  ADD COLUMN proof_verified_at timestamptz;

ALTER TABLE security.staged_objects DROP CONSTRAINT staged_objects_object_kind_check;
ALTER TABLE security.staged_objects ADD CONSTRAINT staged_objects_object_kind_check
  CHECK (object_kind IN ('genesis', 'encrypted_workspace', 'encrypted_profile', 'key_envelope', 'custody_manifest', 'signed_grant'));

-- Rate-limit counters contain service HMAC digests, never source addresses or keys.
-- This service-only operational table spans preactivation requests with no tenant.
CREATE TABLE security.request_budgets (
  bucket_digest bytea PRIMARY KEY CHECK (octet_length(bucket_digest) = 32),
  window_started_at timestamptz NOT NULL,
  attempts integer NOT NULL CHECK (attempts > 0),
  expires_at timestamptz NOT NULL
);
