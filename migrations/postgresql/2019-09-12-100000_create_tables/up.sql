CREATE TABLE users (
  uuid                CHAR(36) NOT NULL PRIMARY KEY,
  created_at          TIMESTAMP NOT NULL,
  updated_at          TIMESTAMP NOT NULL,
  email               VARCHAR(255) NOT NULL UNIQUE,
  name                TEXT     NOT NULL,
  password_hash       BYTEA     NOT NULL,
  salt                BYTEA     NOT NULL,
  password_iterations INTEGER  NOT NULL,
  password_hint       TEXT,
  akey                TEXT     NOT NULL,
  private_key         TEXT,
  public_key          TEXT,
  totp_secret         TEXT,
  totp_recover        TEXT,
  security_stamp      TEXT     NOT NULL,
  equivalent_domains  TEXT     NOT NULL,
  excluded_globals    TEXT     NOT NULL,
  client_kdf_type     INTEGER NOT NULL DEFAULT 0,
  client_kdf_iter INTEGER NOT NULL DEFAULT 100000
);

CREATE TABLE devices (
  uuid          CHAR(36) NOT NULL PRIMARY KEY,
  created_at    TIMESTAMP NOT NULL,
  updated_at    TIMESTAMP NOT NULL,
  user_uuid     CHAR(36) NOT NULL REFERENCES users (uuid),
  name          TEXT     NOT NULL,
  atype         INTEGER  NOT NULL,
  push_token    TEXT,
  refresh_token TEXT     NOT NULL,
  twofactor_remember TEXT
);

CREATE TABLE organizations (
  uuid          VARCHAR(40) NOT NULL PRIMARY KEY,
  name          TEXT NOT NULL,
  billing_email TEXT NOT NULL
);

CREATE TABLE ciphers (
  uuid              CHAR(36) NOT NULL PRIMARY KEY,
  created_at        TIMESTAMP NOT NULL,
  updated_at        TIMESTAMP NOT NULL,
  user_uuid         CHAR(36) REFERENCES users (uuid),
  organization_uuid CHAR(36) REFERENCES organizations (uuid),
  atype             INTEGER  NOT NULL,
  name              TEXT     NOT NULL,
  notes             TEXT,
  fields            TEXT,
  data              TEXT     NOT NULL,
  favorite          BOOLEAN  NOT NULL,
  password_history  TEXT
);

CREATE TABLE attachments (
  id          CHAR(36) NOT NULL PRIMARY KEY,
  cipher_uuid CHAR(36) NOT NULL REFERENCES ciphers (uuid),
  file_name   TEXT    NOT NULL,
  file_size   INTEGER NOT NULL,
  akey        TEXT
);

CREATE TABLE folders (
  uuid       CHAR(36) NOT NULL PRIMARY KEY,
  created_at TIMESTAMP NOT NULL,
  updated_at TIMESTAMP NOT NULL,
  user_uuid  CHAR(36) NOT NULL REFERENCES users (uuid),
  name       TEXT     NOT NULL
);

CREATE TABLE collections (
  uuid     VARCHAR(40) NOT NULL PRIMARY KEY,
  org_uuid VARCHAR(40) NOT NULL REFERENCES organizations (uuid),
  name     TEXT NOT NULL
);

CREATE TABLE users_collections (
  user_uuid       CHAR(36) NOT NULL REFERENCES users (uuid),
  collection_uuid CHAR(36) NOT NULL REFERENCES collections (uuid),
  read_only       BOOLEAN NOT NULL DEFAULT false,
  PRIMARY KEY (user_uuid, collection_uuid)
);

CREATE TABLE users_organizations (
  uuid       CHAR(36) NOT NULL PRIMARY KEY,
  user_uuid  CHAR(36) NOT NULL REFERENCES users (uuid),
  org_uuid   CHAR(36) NOT NULL REFERENCES organizations (uuid),

  access_all BOOLEAN NOT NULL,
  akey       TEXT    NOT NULL,
  status     INTEGER NOT NULL,
  atype      INTEGER NOT NULL,

  UNIQUE (user_uuid, org_uuid)
);

CREATE TABLE folders_ciphers (
  cipher_uuid CHAR(36) NOT NULL REFERENCES ciphers (uuid),
  folder_uuid CHAR(36) NOT NULL REFERENCES folders (uuid),
  PRIMARY KEY (cipher_uuid, folder_uuid)
);

CREATE TABLE ciphers_collections (
  cipher_uuid       CHAR(36) NOT NULL REFERENCES ciphers (uuid),
  collection_uuid CHAR(36) NOT NULL REFERENCES collections (uuid),
  PRIMARY KEY (cipher_uuid, collection_uuid)
);

CREATE TABLE twofactor (
  uuid      CHAR(36) NOT NULL PRIMARY KEY,
  user_uuid CHAR(36) NOT NULL REFERENCES users (uuid),
  atype     INTEGER  NOT NULL,
  enabled   BOOLEAN  NOT NULL,
  data      TEXT     NOT NULL,
  UNIQUE (user_uuid, atype)
);

CREATE TABLE invitations (
    email   VARCHAR(255) NOT NULL PRIMARY KEY
);