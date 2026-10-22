CREATE TABLE web_authn_credentials (
    uuid CHAR(36) PRIMARY KEY NOT NULL,
    user_uuid CHAR(36) NOT NULL,
    name TEXT NOT NULL,
    credential TEXT NOT NULL,
    credential_id_hash VARCHAR(64) NOT NULL,
    supports_prf BOOLEAN NOT NULL,
    encrypted_user_key TEXT,
    encrypted_public_key TEXT,
    encrypted_private_key TEXT,
    FOREIGN KEY (user_uuid) REFERENCES users(uuid) ON DELETE CASCADE,
    UNIQUE (credential_id_hash)
);

CREATE TABLE web_authn_login_challenges (
    token_hash VARCHAR(64) PRIMARY KEY NOT NULL,
    state TEXT NOT NULL,
    created_at BIGINT NOT NULL
);
