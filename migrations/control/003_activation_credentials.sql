-- OPAQUE registration files are sensitive authentication material, not public draft metadata.
ALTER TABLE security.activation_attempts ADD COLUMN staged_registration_record text
  CHECK (staged_registration_record ~ '^[A-Za-z0-9_-]+$');
