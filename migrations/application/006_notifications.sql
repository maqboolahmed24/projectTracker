-- Notification details retain project RLS. A separate content-free receipt lets
-- a recipient see that an older notice exists after its details become unavailable.
CREATE TABLE app.notification_receipts (
  workspace_id uuid NOT NULL,
  id uuid NOT NULL,
  recipient_profile_id uuid NOT NULL,
  event_id uuid NOT NULL,
  read_at timestamptz,
  revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (workspace_id,id),
  UNIQUE (workspace_id,recipient_profile_id,event_id),
  FOREIGN KEY (workspace_id,id) REFERENCES app.notifications(workspace_id,id) ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY (workspace_id,recipient_profile_id) REFERENCES app.profiles(workspace_id,id) DEFERRABLE INITIALLY DEFERRED
);
INSERT INTO app.notification_receipts(workspace_id,id,recipient_profile_id,event_id,read_at,revision,created_at)
  SELECT workspace_id,id,recipient_profile_id,event_id,read_at,revision,created_at FROM app.notifications;
ALTER TABLE app.notification_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.notification_receipts FORCE ROW LEVEL SECURITY;
CREATE POLICY notification_receipt_scope ON app.notification_receipts
  USING (workspace_id=app.current_workspace_id() AND recipient_profile_id=app.current_profile_id()
    AND EXISTS (SELECT 1 FROM app.profiles p WHERE p.workspace_id=notification_receipts.workspace_id
      AND p.id=notification_receipts.recipient_profile_id AND p.state='active'))
  WITH CHECK (workspace_id=app.current_workspace_id() AND recipient_profile_id=app.current_profile_id()
    AND EXISTS (SELECT 1 FROM app.profiles p WHERE p.workspace_id=notification_receipts.workspace_id
      AND p.id=notification_receipts.recipient_profile_id AND p.state='active'));
CREATE INDEX notification_receipt_recipient ON app.notification_receipts(workspace_id,recipient_profile_id,created_at,id);

ALTER TABLE app.outbox ADD COLUMN notification_events jsonb NOT NULL DEFAULT '[]'::jsonb
  CHECK (jsonb_typeof(notification_events)='array');
ALTER TABLE app.outbox ADD COLUMN notification_version integer NOT NULL DEFAULT 0 CHECK (notification_version IN (0,1));

-- Keep every producer (including security projection) atomic with its Inbox receipt.
-- This is a normal invoker trigger: it does not bypass recipient RLS.
CREATE FUNCTION app.record_notification_receipt() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
  INSERT INTO app.notification_receipts(workspace_id,id,recipient_profile_id,event_id,read_at,revision,created_at)
    VALUES(NEW.workspace_id,NEW.id,NEW.recipient_profile_id,NEW.event_id,NEW.read_at,NEW.revision,NEW.created_at)
    ON CONFLICT(workspace_id,recipient_profile_id,event_id) DO NOTHING;
  RETURN NEW;
END
$$;
CREATE TRIGGER notification_receipt_insert AFTER INSERT ON app.notifications
  FOR EACH ROW EXECUTE FUNCTION app.record_notification_receipt();

CREATE TABLE app.inbox_operations (
  workspace_id uuid NOT NULL,
  operation_id uuid NOT NULL,
  actor_profile_id uuid NOT NULL,
  data_generation bigint NOT NULL CHECK(data_generation>0),
  request_digest text NOT NULL,
  signed_change jsonb NOT NULL,
  before_state jsonb NOT NULL,
  receipt jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(workspace_id,operation_id),
  FOREIGN KEY(workspace_id,actor_profile_id) REFERENCES app.profiles(workspace_id,id) DEFERRABLE INITIALLY DEFERRED
);
ALTER TABLE app.inbox_operations ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.inbox_operations FORCE ROW LEVEL SECURITY;
CREATE POLICY inbox_operation_scope ON app.inbox_operations
  USING(workspace_id=app.current_workspace_id() AND actor_profile_id=app.current_profile_id())
  WITH CHECK(workspace_id=app.current_workspace_id() AND actor_profile_id=app.current_profile_id());
CREATE TRIGGER inbox_operations_immutable BEFORE UPDATE OR DELETE ON app.inbox_operations
  FOR EACH ROW EXECUTE FUNCTION app.reject_history_mutation();
