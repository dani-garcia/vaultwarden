CREATE TABLE sends (
  uuid              CHAR(36) NOT NULL   PRIMARY KEY,
  user_uuid         CHAR(36)            REFERENCES users (uuid),
  organization_uuid CHAR(36)            REFERENCES organizations (uuid),

  name              TEXT    NOT NULL,
  notes             TEXT,

  atype             INTEGER NOT NULL,
  data              TEXT    NOT NULL,
  key               TEXT    NOT NULL,
  password_hash     BYTEA,
  password_salt     BYTEA,
  password_iter     INTEGER,

  max_access_count  INTEGER,
  access_count      INTEGER NOT NULL,

  creation_date     TIMESTAMP NOT NULL,
  revision_date     TIMESTAMP NOT NULL,
  expiration_date   TIMESTAMP,
  deletion_date     TIMESTAMP NOT NULL,

  disabled          BOOLEAN NOT NULL
);