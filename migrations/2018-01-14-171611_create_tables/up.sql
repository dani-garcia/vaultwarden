CREATE TABLE users (
  uuid                TEXT        NOT NULL PRIMARY KEY,
  created_at          DATETIME    NOT NULL,
  updated_at          DATETIME    NOT NULL,
  email               TEXT UNIQUE NOT NULL,
  name                TEXT        NOT NULL,
  password_hash       BLOB        NOT NULL,
  salt                BLOB        NOT NULL,
  password_iterations INTEGER     NOT NULL,
  password_hint       TEXT,
  key                 TEXT        NOT NULL,
  private_key         TEXT,
  public_key          TEXT,
  totp_secret         TEXT,
  totp_recover        TEXT,
  security_stamp      TEXT        NOT NULL
);

CREATE TABLE devices (
  uuid          TEXT        NOT NULL PRIMARY KEY,
  created_at    DATETIME    NOT NULL,
  updated_at    DATETIME    NOT NULL,
  user_uuid     TEXT        NOT NULL REFERENCES users (uuid),
  name          TEXT        NOT NULL,
  type          INTEGER     NOT NULL,
  push_token    TEXT UNIQUE,
  refresh_token TEXT UNIQUE NOT NULL
);

CREATE TABLE ciphers (
  uuid              TEXT     NOT NULL PRIMARY KEY,
  created_at        DATETIME NOT NULL,
  updated_at        DATETIME NOT NULL,
  user_uuid         TEXT     NOT NULL REFERENCES users (uuid),
  folder_uuid       TEXT REFERENCES folders (uuid),
  organization_uuid TEXT,
  type              INTEGER  NOT NULL,
  data              TEXT     NOT NULL,
  favorite          BOOLEAN  NOT NULL,
  attachments       BLOB
);

CREATE TABLE folders (
  uuid       TEXT     NOT NULL PRIMARY KEY,
  created_at DATETIME NOT NULL,
  updated_at DATETIME NOT NULL,
  user_uuid  TEXT     NOT NULL REFERENCES users (uuid),
  name       TEXT     NOT NULL
);
  