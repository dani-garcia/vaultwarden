ALTER TABLE auth_requests
ALTER COLUMN master_password_hash DROP NOT NULL;

ALTER TABLE auth_requests
ALTER COLUMN enc_key DROP NOT NULL;
