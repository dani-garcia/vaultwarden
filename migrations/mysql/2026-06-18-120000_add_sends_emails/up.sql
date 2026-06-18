ALTER TABLE sends ADD COLUMN emails TEXT;

CREATE TABLE sends_otp (
    send_uuid       CHAR(36) NOT NULL REFERENCES sends(uuid) ON DELETE CASCADE ON UPDATE CASCADE,
    email           VARCHAR(255) NOT NULL,
    code            TEXT NOT NULL,

    creation_date     DATETIME NOT NULL,
    revision_date     DATETIME NOT NULL,
    expiration_date   DATETIME NOT NULL,

    PRIMARY KEY(send_uuid, email)
);
