DROP TABLE sends_otp;

ALTER TABLE sends RENAME TO sends_old;

CREATE TABLE sends (
  uuid              TEXT NOT NULL   PRIMARY KEY,
  user_uuid         TEXT REFERENCES users (uuid),
  organization_uuid TEXT REFERENCES organizations (uuid),

  name              TEXT    NOT NULL,
  notes             TEXT,

  atype             INTEGER NOT NULL,
  data              TEXT    NOT NULL,
  akey              TEXT    NOT NULL,
  password_hash     BLOB,
  password_salt     BLOB,
  password_iter     INTEGER,

  max_access_count  INTEGER,
  access_count      INTEGER NOT NULL,

  creation_date     DATETIME NOT NULL,
  revision_date     DATETIME NOT NULL,
  expiration_date   DATETIME,
  deletion_date     DATETIME NOT NULL,

  disabled          BOOLEAN NOT NULL,
  hide_email        BOOLEAN
);

INSERT INTO sends(
        uuid, user_uuid, name, notes, atype, data, akey, password_hash, password_salt, password_iter,
        max_access_count, access_count, creation_date, revision_date, expiration_date, deletion_date,
        disabled, hide_email
) SELECT uuid, user_uuid, name, notes, atype, data, akey, password_hash, password_salt, password_iter,
        max_access_count, access_count, creation_date, revision_date, expiration_date, deletion_date,
        disabled, hide_email
    FROM sends_old WHERE user_uuid IS NOT NULL;

DROP TABLE sends_old;
