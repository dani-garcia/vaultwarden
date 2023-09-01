ALTER TABLE auth_requests
MODIFY master_password_hash TEXT;

ALTER TABLE auth_requests
MODIFY enc_key TEXT;
