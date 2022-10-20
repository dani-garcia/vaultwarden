CREATE TABLE groups (
  uuid                              CHAR(36) NOT NULL PRIMARY KEY,
  organizations_uuid                 VARCHAR(40) NOT NULL REFERENCES organizations (uuid),
  name                              VARCHAR(100) NOT NULL,
  access_all                        BOOLEAN NOT NULL,
  external_id                       VARCHAR(300) NULL,
  creation_date                     TIMESTAMP NOT NULL,
  revision_date                     TIMESTAMP NOT NULL
);

CREATE TABLE groups_users (
  groups_uuid                       CHAR(36) NOT NULL REFERENCES groups (uuid),
  users_organizations_uuid          VARCHAR(36) NOT NULL REFERENCES users_organizations (uuid),
  PRIMARY KEY (groups_uuid, users_organizations_uuid)
);

CREATE TABLE collections_groups (
  collections_uuid                  VARCHAR(40) NOT NULL REFERENCES collections (uuid),
  groups_uuid                       CHAR(36) NOT NULL REFERENCES groups (uuid),
  read_only                         BOOLEAN NOT NULL,
  hide_passwords                    BOOLEAN NOT NULL,
  PRIMARY KEY (collections_uuid, groups_uuid)
);