CREATE TABLE sends (
  uuid              TEXT NOT NULL   PRIMARY KEY,
  user_uuid         TEXT            REFERENCES users (uuid),
  organization_uuid TEXT            REFERENCES organizations (uuid),

  name              TEXT    NOT NULL,
  notes             TEXT,

  atype             INTEGER NOT NULL,
  data              TEXT    NOT NULL,
  key               TEXT    NOT NULL,
  password_hash     BLOB,
  password_salt     BLOB,
  password_iter     INTEGER,

  max_access_count  INTEGER,
  access_count      INTEGER NOT NULL,

  creation_date     DATETIME NOT NULL,
  revision_date     DATETIME NOT NULL,
  expiration_date   DATETIME,
  deletion_date     DATETIME NOT NULL,

  disabled          BOOLEAN NOT NULL
);