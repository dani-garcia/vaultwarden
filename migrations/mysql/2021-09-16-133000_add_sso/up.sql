ALTER TABLE organizations ADD COLUMN identifier TEXT;

CREATE TABLE sso_nonce (
  uuid     CHAR(36) NOT NULL PRIMARY KEY,
  org_uuid CHAR(36) NOT NULL REFERENCES organizations (uuid),
  nonce    CHAR(36) NOT NULL
);

CREATE TABLE sso_config (
  uuid                     CHAR(36) NOT NULL PRIMARY KEY,
  org_uuid                 CHAR(36) NOT NULL REFERENCES organizations(uuid),
  use_sso                  BOOLEAN NOT NULL,
  callback_path            TEXT NOT NULL,
  signed_out_callback_path TEXT NOT NULL,
  authority                TEXT,
  client_id                TEXT,
  client_secret            TEXT
);
