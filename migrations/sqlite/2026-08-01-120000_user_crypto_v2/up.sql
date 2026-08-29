ALTER TABLE users ADD COLUMN signed_public_key TEXT;
ALTER TABLE users ADD COLUMN security_state TEXT;
ALTER TABLE users ADD COLUMN security_version INTEGER;
ALTER TABLE users ADD COLUMN v2_upgrade_token TEXT;

DROP TABLE IF EXISTS user_signature_key_pairs;

CREATE TABLE user_signature_key_pairs (
    uuid                TEXT     NOT NULL PRIMARY KEY,
    user_uuid           TEXT     NOT NULL UNIQUE REFERENCES users (uuid) ON DELETE CASCADE,
    signature_algorithm INTEGER  NOT NULL, -- 0 = ed25519, 1 = mldsa44
    signing_key         TEXT     NOT NULL,
    verifying_key       TEXT     NOT NULL,
    created_at          DATETIME NOT NULL,
    updated_at          DATETIME NOT NULL
);
