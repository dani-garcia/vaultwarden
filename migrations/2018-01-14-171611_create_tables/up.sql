CREATE TABLE users (
  uuid                VARCHAR(40) NOT NULL PRIMARY KEY,
  created_at          DATETIME NOT NULL,
  updated_at          DATETIME NOT NULL,
  email               VARCHAR(255) NOT NULL UNIQUE,
  name                TEXT     NOT NULL,
  password_hash       BLOB     NOT NULL,
  salt                BLOB     NOT NULL,
  password_iterations INTEGER  NOT NULL,
  password_hint       TEXT,
  akey                TEXT     NOT NULL,
  private_key         TEXT,
  public_key          TEXT,
  totp_secret         TEXT,
  totp_recover        TEXT,
  security_stamp      TEXT     NOT NULL,
  equivalent_domains  TEXT     NOT NULL,
  excluded_globals    TEXT     NOT NULL
);

CREATE TABLE devices (
  uuid          VARCHAR(40) NOT NULL PRIMARY KEY,
  created_at    DATETIME NOT NULL,
  updated_at    DATETIME NOT NULL,
  user_uuid     VARCHAR(40) NOT NULL REFERENCES users (uuid),
  name          TEXT     NOT NULL,
  atype         INTEGER  NOT NULL,
  push_token    TEXT,
  refresh_token TEXT     NOT NULL
);

CREATE TABLE ciphers (
  uuid              VARCHAR(40) NOT NULL PRIMARY KEY,
  created_at        DATETIME NOT NULL,
  updated_at        DATETIME NOT NULL,
  user_uuid         VARCHAR(40) NOT NULL REFERENCES users (uuid),
  folder_uuid       VARCHAR(40) REFERENCES folders (uuid),
  organization_uuid VARCHAR(40),
  atype             INTEGER  NOT NULL,
  name              TEXT     NOT NULL,
  notes             TEXT,
  fields            TEXT,
  data              TEXT     NOT NULL,
  favorite          BOOLEAN  NOT NULL
);

CREATE TABLE attachments (
  id          VARCHAR(40) NOT NULL PRIMARY KEY,
  cipher_uuid VARCHAR(40) NOT NULL REFERENCES ciphers (uuid),
  file_name   TEXT    NOT NULL,
  file_size   INTEGER NOT NULL

);

CREATE TABLE folders (
  uuid       VARCHAR(40) NOT NULL PRIMARY KEY,
  created_at DATETIME NOT NULL,
  updated_at DATETIME NOT NULL,
  user_uuid  VARCHAR(40) NOT NULL REFERENCES users (uuid),
  name       TEXT     NOT NULL
);
  
