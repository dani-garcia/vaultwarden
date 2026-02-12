CREATE TABLE web_authn_credentials (
    uuid              TEXT    NOT NULL PRIMARY KEY,
    user_uuid         TEXT    NOT NULL REFERENCES users(uuid),
    name              TEXT    NOT NULL,
    credential        TEXT    NOT NULL,
    supports_prf      BOOLEAN NOT NULL DEFAULT 0,
    encrypted_user_key    TEXT,
    encrypted_public_key  TEXT,
    encrypted_private_key TEXT
);
