-- Review is a single optional project policy. Task content has its own revision
-- so a metadata-only review action cannot replace the submitted ciphertext.
ALTER TABLE app.projects
  ADD COLUMN review_enabled boolean NOT NULL DEFAULT false,
  ADD COLUMN review_policy_revision bigint NOT NULL DEFAULT 1 CHECK (review_policy_revision > 0);

ALTER TABLE app.tasks
  ADD COLUMN content_revision bigint,
  ADD COLUMN submitted_policy_revision bigint CHECK (submitted_policy_revision > 0),
  ADD COLUMN approval_operation_id uuid,
  ADD CONSTRAINT task_approval_operation FOREIGN KEY (workspace_id,approval_operation_id)
    REFERENCES app.planning_operations(workspace_id,operation_id) DEFERRABLE INITIALLY DEFERRED;

-- Existing CP07 task operations advanced content and metadata together.
UPDATE app.tasks SET content_revision=revision;
ALTER TABLE app.tasks
  ALTER COLUMN content_revision SET NOT NULL,
  ALTER COLUMN content_revision SET DEFAULT 1,
  ADD CONSTRAINT task_content_revision_valid CHECK (content_revision > 0 AND content_revision <= revision);

ALTER TABLE app.blockers ADD COLUMN content_revision bigint;
UPDATE app.blockers SET content_revision=revision;
ALTER TABLE app.blockers
  ALTER COLUMN content_revision SET NOT NULL,
  ALTER COLUMN content_revision SET DEFAULT 1,
  ADD CONSTRAINT blocker_content_revision_valid CHECK (content_revision > 0 AND content_revision <= revision);
