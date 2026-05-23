CREATE TABLE web_authn_credentials (
    uuid              CHAR(36)     NOT NULL PRIMARY KEY,
    user_uuid         CHAR(36)     NOT NULL REFERENCES users(uuid) ON DELETE CASCADE,
    name              TEXT         NOT NULL,
    credential        TEXT         NOT NULL,
    credential_id_hash VARCHAR(64) NOT NULL,
    supports_prf      BOOLEAN      NOT NULL DEFAULT FALSE,
    encrypted_user_key    TEXT,
    encrypted_public_key  TEXT,
    encrypted_private_key TEXT
);

CREATE INDEX idx_web_authn_credentials_user_uuid ON web_authn_credentials (user_uuid);
CREATE UNIQUE INDEX idx_web_authn_credentials_credential_id_hash ON web_authn_credentials (credential_id_hash);
