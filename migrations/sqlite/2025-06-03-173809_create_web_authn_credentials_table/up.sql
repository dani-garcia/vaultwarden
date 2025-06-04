CREATE TABLE web_authn_credentials (
    uuid         TEXT NOT NULL PRIMARY KEY,
    user_uuid         TEXT NOT NULL,
    name         TEXT NOT NULL,
    credential           TEXT NOT NULL,
    supports_prf         BOOLEAN NOT NULL,
    encrypted_user_key         TEXT,
    encrypted_public_key         TEXT,
    encrypted_private_key         TEXT,
    FOREIGN KEY(user_uuid) REFERENCES users(uuid)
);
