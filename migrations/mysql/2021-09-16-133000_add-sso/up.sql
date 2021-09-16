ALTER TABLE organizations ADD COLUMN identifier               TEXT NOT NULL;
ALTER TABLE organizations ADD COLUMN use_sso                  BOOLEAN NOT NULL;
ALTER TABLE organizations ADD COLUMN callback_path            TEXT NOT NULL;
ALTER TABLE organizations ADD COLUMN signed_out_callback_path TEXT NOT NULL;
ALTER TABLE organizations ADD COLUMN authority                TEXT NOT NULL;
ALTER TABLE organizations ADD COLUMN client_id                TEXT NOT NULL;
ALTER TABLE organizations ADD COLUMN client_secret            TEXT NOT NULL;
