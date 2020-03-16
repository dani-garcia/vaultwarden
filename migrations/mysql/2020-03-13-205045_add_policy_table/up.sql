CREATE TABLE org_policies (
  uuid      CHAR(36) NOT NULL PRIMARY KEY,
  org_uuid  CHAR(36) NOT NULL REFERENCES organizations (uuid),
  atype     INTEGER  NOT NULL,
  enabled   BOOLEAN  NOT NULL,
  data      TEXT     NOT NULL,

  UNIQUE (org_uuid, atype)
);
