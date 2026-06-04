DROP TABLE IF EXISTS archives;

CREATE TABLE archives (
    user_uuid   CHAR(36) NOT NULL REFERENCES users (uuid) ON DELETE CASCADE,
    cipher_uuid CHAR(36) NOT NULL REFERENCES ciphers (uuid) ON DELETE CASCADE,
    archived_at TIMESTAMP NOT NULL DEFAULT now(),
    PRIMARY KEY (user_uuid, cipher_uuid)
);
