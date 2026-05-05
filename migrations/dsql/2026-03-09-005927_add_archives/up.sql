CREATE TABLE archives (
    user_uuid character(36) NOT NULL,
    cipher_uuid character(36) NOT NULL,
    archived_at timestamp without time zone NOT NULL DEFAULT now(),
    PRIMARY KEY (user_uuid, cipher_uuid)
);
