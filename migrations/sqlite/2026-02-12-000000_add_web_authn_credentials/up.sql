CREATE TABLE web_authn_credentials (
    uuid              TEXT    NOT NULL PRIMARY KEY,
    user_uuid         TEXT    NOT NULL REFERENCES users(uuid) ON DELETE CASCADE,
    name              TEXT    NOT NULL,
    credential        TEXT    NOT NULL,
    supports_prf      BOOLEAN NOT NULL DEFAULT 0,
    encrypted_user_key    TEXT,
    encrypted_public_key  TEXT,
    encrypted_private_key TEXT
);

CREATE INDEX idx_web_authn_credentials_user_uuid ON web_authn_credentials (user_uuid);
