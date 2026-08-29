DROP TABLE IF EXISTS user_signature_key_pairs;

ALTER TABLE users DROP COLUMN signed_public_key;
ALTER TABLE users DROP COLUMN security_state;
ALTER TABLE users DROP COLUMN security_version;
ALTER TABLE users DROP COLUMN v2_upgrade_token;
