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


DELETE FROM sends where user_uuid IS NULL;
UPDATE sends SET hide_email = false WHERE hide_email IS NULL;
ALTER TABLE sends DROP COLUMN organization_uuid;
ALTER TABLE sends ALTER COLUMN user_uuid SET NOT NULL;
ALTER TABLE sends ALTER COLUMN hide_email SET NOT NULL;
