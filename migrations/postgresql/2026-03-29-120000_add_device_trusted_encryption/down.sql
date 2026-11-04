ALTER TABLE devices
    DROP COLUMN IF EXISTS encrypted_private_key,
    DROP COLUMN IF EXISTS encrypted_public_key,
    DROP COLUMN IF EXISTS encrypted_user_key;
