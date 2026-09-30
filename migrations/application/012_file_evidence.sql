-- Exact immutable file versions are reviewed independently of the legacy signed
-- planning protocol. Hash proofs remain inside project-key ciphertext.
CREATE TABLE app.file_submissions (
 workspace_id uuid NOT NULL,project_id uuid NOT NULL,id uuid NOT NULL,task_id uuid NOT NULL,
 data_generation bigint NOT NULL CHECK(data_generation>0),signed_submission jsonb NOT NULL CHECK(jsonb_typeof(signed_submission)='object'),
 payload_digest text NOT NULL CHECK(payload_digest ~ '^[a-f0-9]{64}$'),created_at timestamptz NOT NULL,
 PRIMARY KEY(workspace_id,id),UNIQUE(workspace_id,project_id,id),
 FOREIGN KEY(workspace_id,project_id,task_id) REFERENCES app.tasks(workspace_id,project_id,id) DEFERRABLE INITIALLY DEFERRED
);
CREATE TABLE app.file_reviews (
 workspace_id uuid NOT NULL,project_id uuid NOT NULL,id uuid NOT NULL,submission_id uuid,task_id uuid,
 data_generation bigint NOT NULL CHECK(data_generation>0),signed_review jsonb NOT NULL CHECK(jsonb_typeof(signed_review)='object'),
 payload_digest text NOT NULL CHECK(payload_digest ~ '^[a-f0-9]{64}$'),created_at timestamptz NOT NULL,
 CHECK((submission_id IS NULL)=(task_id IS NULL)),PRIMARY KEY(workspace_id,id),UNIQUE(workspace_id,project_id,id),
 FOREIGN KEY(workspace_id,project_id,submission_id) REFERENCES app.file_submissions(workspace_id,project_id,id) DEFERRABLE INITIALLY DEFERRED,
 FOREIGN KEY(workspace_id,project_id,task_id) REFERENCES app.tasks(workspace_id,project_id,id) DEFERRABLE INITIALLY DEFERRED
);
CREATE TABLE app.file_review_items (
 workspace_id uuid NOT NULL,project_id uuid NOT NULL,approval_id uuid NOT NULL,file_id uuid NOT NULL,version_id uuid NOT NULL,
 manifest_digest text NOT NULL CHECK(manifest_digest ~ '^[a-f0-9]{64}$'),PRIMARY KEY(workspace_id,approval_id,version_id),
 FOREIGN KEY(workspace_id,project_id,approval_id) REFERENCES app.file_reviews(workspace_id,project_id,id) DEFERRABLE INITIALLY DEFERRED,
 FOREIGN KEY(workspace_id,project_id,file_id,version_id) REFERENCES app.file_versions(workspace_id,project_id,file_id,id) DEFERRABLE INITIALLY DEFERRED
);
CREATE INDEX file_review_versions ON app.file_review_items(workspace_id,project_id,version_id);
CREATE TABLE app.file_approval_revocations (
 workspace_id uuid NOT NULL,project_id uuid NOT NULL,operation_id uuid NOT NULL,approval_id uuid NOT NULL,
 data_generation bigint NOT NULL CHECK(data_generation>0),signed_revocation jsonb NOT NULL CHECK(jsonb_typeof(signed_revocation)='object'),created_at timestamptz NOT NULL,
 PRIMARY KEY(workspace_id,operation_id),UNIQUE(workspace_id,approval_id),
 FOREIGN KEY(workspace_id,project_id,approval_id) REFERENCES app.file_reviews(workspace_id,project_id,id) DEFERRABLE INITIALLY DEFERRED
);
CREATE TABLE app.file_evidence_operations (
 workspace_id uuid NOT NULL,project_id uuid NOT NULL,operation_id uuid NOT NULL,data_generation bigint NOT NULL CHECK(data_generation>0),
 actor_profile_id uuid NOT NULL,request_digest text NOT NULL CHECK(request_digest ~ '^[a-f0-9]{64}$'),payload jsonb NOT NULL CHECK(jsonb_typeof(payload)='object'),
 receipt jsonb NOT NULL CHECK(jsonb_typeof(receipt)='object'),created_at timestamptz NOT NULL,PRIMARY KEY(workspace_id,operation_id),
 FOREIGN KEY(workspace_id,project_id) REFERENCES app.projects(workspace_id,id) DEFERRABLE INITIALLY DEFERRED
);
CREATE INDEX file_task_submissions ON app.file_submissions(workspace_id,project_id,task_id,created_at);
DO $policies$
DECLARE name text;
BEGIN
 FOREACH name IN ARRAY ARRAY['file_submissions','file_reviews','file_review_items','file_approval_revocations','file_evidence_operations'] LOOP
  EXECUTE format('ALTER TABLE app.%I ENABLE ROW LEVEL SECURITY',name);
  EXECUTE format('ALTER TABLE app.%I FORCE ROW LEVEL SECURITY',name);
  EXECUTE format('CREATE POLICY project_scope ON app.%I USING(workspace_id=app.current_workspace_id() AND app.can_read_project(project_id)) WITH CHECK(workspace_id=app.current_workspace_id() AND app.can_read_project(project_id))',name);
  EXECUTE format('REVOKE ALL ON app.%I FROM PUBLIC',name);
  EXECUTE format('CREATE TRIGGER %I BEFORE UPDATE OR DELETE ON app.%I FOR EACH ROW EXECUTE FUNCTION app.reject_history_mutation()',name||'_immutable',name);
 END LOOP;
END $policies$;
