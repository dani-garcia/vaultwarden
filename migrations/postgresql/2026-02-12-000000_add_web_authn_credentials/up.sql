CREATE TABLE web_authn_credentials (
    uuid              VARCHAR(40)  NOT NULL PRIMARY KEY,
    user_uuid         VARCHAR(40)  NOT NULL REFERENCES users(uuid),
    name              TEXT         NOT NULL,
    credential        TEXT         NOT NULL,
    supports_prf      BOOLEAN      NOT NULL DEFAULT FALSE,
    encrypted_user_key    TEXT,
    encrypted_public_key  TEXT,
    encrypted_private_key TEXT
);
