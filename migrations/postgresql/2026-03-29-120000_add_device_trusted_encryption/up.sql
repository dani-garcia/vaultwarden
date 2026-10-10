ALTER TABLE devices
    ADD COLUMN IF NOT EXISTS encrypted_private_key TEXT NULL,
    ADD COLUMN IF NOT EXISTS encrypted_public_key TEXT NULL,
    ADD COLUMN IF NOT EXISTS encrypted_user_key TEXT NULL;
