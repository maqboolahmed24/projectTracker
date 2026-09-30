-- Append-only integrity refinement after the initial file protocol migration.
ALTER TABLE app.file_versions ADD CONSTRAINT file_version_project_identity UNIQUE(workspace_id,project_id,id);
ALTER TABLE app.file_chunks ADD CONSTRAINT file_chunk_same_project FOREIGN KEY(workspace_id,project_id,version_id)
 REFERENCES app.file_versions(workspace_id,project_id,id) ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE app.file_upload_reservations ADD CONSTRAINT file_reservation_same_project FOREIGN KEY(workspace_id,project_id,version_id)
 REFERENCES app.file_versions(workspace_id,project_id,id) ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;
CREATE OR REPLACE FUNCTION app.protect_file_version() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF OLD.state<>'staged' OR (TG_OP='UPDATE' AND (NEW.state NOT IN('ready','cancelled') OR
   (to_jsonb(NEW)-'state'-'completed_at')<>(to_jsonb(OLD)-'state'-'completed_at'))) THEN
  RAISE EXCEPTION 'File versions are immutable' USING ERRCODE='55000';
 END IF;
 IF TG_OP='DELETE' THEN RETURN OLD; END IF;RETURN NEW;
END $$;
