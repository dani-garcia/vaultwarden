CREATE TABLE webauthn_credentials (
    uuid                     CHAR(36)     NOT NULL PRIMARY KEY,
    user_uuid                CHAR(36)     NOT NULL,
    name                     TEXT         NOT NULL,
    credential_id            VARCHAR(256) NOT NULL,
    credential               TEXT         NOT NULL,
    supports_prf             BOOLEAN      NOT NULL,
    encrypted_user_key       TEXT,
    encrypted_public_key     TEXT,
    encrypted_private_key    TEXT,
    last_challenge_issued_at BIGINT,
    created_at               DATETIME     NOT NULL,
    updated_at               DATETIME     NOT NULL,
    UNIQUE (user_uuid, credential_id),
    FOREIGN KEY (user_uuid) REFERENCES users (uuid) ON DELETE CASCADE
);
