DROP TABLE IF EXISTS archives;

CREATE TABLE archives (
    user_uuid   CHAR(36) NOT NULL,
    cipher_uuid CHAR(36) NOT NULL,
    archived_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_uuid, cipher_uuid),
    FOREIGN KEY (user_uuid) REFERENCES users (uuid) ON DELETE CASCADE,
    FOREIGN KEY (cipher_uuid) REFERENCES ciphers (uuid) ON DELETE CASCADE
);
