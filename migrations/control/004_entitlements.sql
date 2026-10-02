-- Global service-only receipts also cover unused licences, which have no workspace.
-- Access is through the operational service/CLI, never a generic customer endpoint.
CREATE TABLE security.entitlement_operations (
    operation_id uuid PRIMARY KEY,
    licence_id uuid NOT NULL REFERENCES security.licences(licence_id),
    request_hash text NOT NULL CHECK (request_hash ~ '^[a-f0-9]{64}$'),
    action text NOT NULL CHECK (action IN ('revoke', 'legacy_expire', 'reinstate')),
    operator_id uuid NOT NULL,
    outcome jsonb NOT NULL CHECK (jsonb_typeof(outcome) = 'object'),
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX entitlement_operations_by_licence ON security.entitlement_operations(licence_id,created_at);
CREATE TRIGGER entitlement_operations_immutable BEFORE UPDATE ON security.entitlement_operations
    FOR EACH ROW EXECUTE FUNCTION security.reject_immutable_update();
-- As with workspace operation receipts, privileged retention/purge may delete rows;
-- it must preserve consumed licence markers and retired workspace identifiers.
