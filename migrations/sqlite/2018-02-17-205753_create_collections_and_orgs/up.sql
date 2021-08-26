CREATE TABLE collections (
  uuid     TEXT NOT NULL PRIMARY KEY,
  org_uuid TEXT NOT NULL REFERENCES organizations (uuid),
  name     TEXT NOT NULL
);

CREATE TABLE organizations (
  uuid                     TEXT NOT NULL PRIMARY KEY,
  name                     TEXT NOT NULL,
  billing_email            TEXT NOT NULL,
  identifier               TEXT NOT NULL,
  use_sso                  BOOLEAN NOT NULL,
  callback_path            TEXT NOT NULL,
  signed_out_callback_path TEXT NOT NULL,
  authority                TEXT NOT NULL,
  client_id                TEXT NOT NULL,
  client_secret            TEXT NOT NULL,
  metadata_address         TEXT NOT NULL,
  oidc_redirect_behavior   TEXT NOT NULL
);


CREATE TABLE users_collections (
  user_uuid       TEXT NOT NULL REFERENCES users (uuid),
  collection_uuid TEXT NOT NULL REFERENCES collections (uuid),
  PRIMARY KEY (user_uuid, collection_uuid)
);

CREATE TABLE users_organizations (
  uuid       TEXT    NOT NULL PRIMARY KEY,
  user_uuid  TEXT    NOT NULL REFERENCES users (uuid),
  org_uuid   TEXT    NOT NULL REFERENCES organizations (uuid),

  access_all BOOLEAN NOT NULL,
  key        TEXT    NOT NULL,
  status     INTEGER NOT NULL,
  type       INTEGER NOT NULL,

  UNIQUE (user_uuid, org_uuid)
);
