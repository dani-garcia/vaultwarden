ALTER TABLE sends ADD COLUMN emails TEXT;

CREATE TABLE sends_otp (
    send_uuid       TEXT NOT NULL   REFERENCES sends(uuid) ON DELETE CASCADE ON UPDATE CASCADE,
    email           TEXT NOT NULL,
    code            TEXT NOT NULL,

    creation_date     TIMESTAMP NOT NULL,
    revision_date     TIMESTAMP NOT NULL,
    expiration_date   TIMESTAMP NOT NULL,

    PRIMARY KEY(send_uuid, email)
);
