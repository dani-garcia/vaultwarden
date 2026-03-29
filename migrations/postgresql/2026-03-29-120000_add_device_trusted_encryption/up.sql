ALTER TABLE devices
    ADD COLUMN encrypted_private_key TEXT NULL,
    ADD COLUMN encrypted_public_key TEXT NULL,
    ADD COLUMN encrypted_user_key TEXT NULL;
