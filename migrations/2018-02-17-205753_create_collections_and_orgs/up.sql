CREATE TABLE collections (
  uuid     VARCHAR(40) NOT NULL PRIMARY KEY,
  org_uuid VARCHAR(40) NOT NULL REFERENCES organizations (uuid),
  name     TEXT NOT NULL
);

CREATE TABLE organizations (
  uuid          VARCHAR(40) NOT NULL PRIMARY KEY,
  name          TEXT NOT NULL,
  billing_email TEXT NOT NULL
);

CREATE TABLE users_collections (
  user_uuid       VARCHAR(40) NOT NULL REFERENCES users (uuid),
  collection_uuid VARCHAR(40) NOT NULL REFERENCES collections (uuid),
  PRIMARY KEY (user_uuid, collection_uuid)
);

CREATE TABLE users_organizations (
  uuid       VARCHAR(40) NOT NULL PRIMARY KEY,
  user_uuid  VARCHAR(40) NOT NULL REFERENCES users (uuid),
  org_uuid   VARCHAR(40) NOT NULL REFERENCES organizations (uuid),

  access_all BOOLEAN NOT NULL,
  akey       TEXT    NOT NULL,
  status     INTEGER NOT NULL,
  atype      INTEGER NOT NULL,

  UNIQUE (user_uuid, org_uuid)
);
