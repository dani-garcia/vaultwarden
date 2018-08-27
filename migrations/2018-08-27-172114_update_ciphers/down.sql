ALTER TABLE ciphers RENAME TO oldCiphers;

CREATE TABLE ciphers (
  uuid              TEXT     NOT NULL PRIMARY KEY,
  created_at        DATETIME NOT NULL,
  updated_at        DATETIME NOT NULL,
  user_uuid         TEXT     REFERENCES users (uuid),
  organization_uuid TEXT     REFERENCES organizations (uuid),
  type              INTEGER  NOT NULL,
  name              TEXT     NOT NULL,
  notes             TEXT,
  fields            TEXT,
  data              TEXT     NOT NULL,
  favorite          BOOLEAN  NOT NULL
);

INSERT INTO ciphers (uuid, created_at, updated_at, user_uuid, organization_uuid, type, name, notes, fields, data, favorite) 
SELECT uuid, created_at, updated_at, user_uuid, organization_uuid, type, name, notes, fields, data, favorite FROM oldCiphers;

DROP TABLE oldCiphers;