ALTER TABLE ciphers RENAME TO oldCiphers;

CREATE TABLE ciphers (
  uuid              TEXT     NOT NULL PRIMARY KEY,
  created_at        DATETIME NOT NULL,
  updated_at        DATETIME NOT NULL,
  user_uuid         TEXT     REFERENCES users (uuid), -- Make this optional
  organization_uuid TEXT     REFERENCES organizations (uuid), -- Add reference to orgs table
  -- Remove folder_uuid
  type              INTEGER  NOT NULL,
  name              TEXT     NOT NULL,
  notes             TEXT,
  fields            TEXT,
  data              TEXT     NOT NULL,
  favorite          BOOLEAN  NOT NULL
);

CREATE TABLE folders_ciphers (
  cipher_uuid TEXT NOT NULL REFERENCES ciphers (uuid),
  folder_uuid TEXT NOT NULL REFERENCES folders (uuid),

  PRIMARY KEY (cipher_uuid, folder_uuid)
);

INSERT INTO ciphers (uuid, created_at, updated_at, user_uuid, organization_uuid, type, name, notes, fields, data, favorite) 
SELECT uuid, created_at, updated_at, user_uuid, organization_uuid, type, name, notes, fields, data, favorite FROM oldCiphers;

INSERT INTO folders_ciphers (cipher_uuid, folder_uuid)
SELECT uuid, folder_uuid FROM oldCiphers WHERE folder_uuid IS NOT NULL;


DROP TABLE oldCiphers;

ALTER TABLE users_collections ADD COLUMN read_only BOOLEAN NOT NULL DEFAULT 0; -- False
