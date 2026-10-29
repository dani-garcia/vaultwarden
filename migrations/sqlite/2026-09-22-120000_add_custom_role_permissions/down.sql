-- Downgrade is lossy because the legacy role model cannot represent arbitrary Custom permissions.
-- Custom memberships are mapped to User to avoid granting additional privileges. Restore a
-- pre-upgrade database backup if exact state preservation is required.
CREATE TABLE users_organizations_old (
  uuid       TEXT    NOT NULL PRIMARY KEY,
  user_uuid  TEXT    NOT NULL REFERENCES users (uuid),
  org_uuid   TEXT    NOT NULL REFERENCES organizations (uuid),

  access_all BOOLEAN NOT NULL,
  akey        TEXT    NOT NULL,
  status     INTEGER NOT NULL,
  atype       INTEGER NOT NULL,
  reset_password_key TEXT,
  external_id TEXT,
  invited_by_email TEXT DEFAULT NULL,

  UNIQUE (user_uuid, org_uuid)
);

INSERT INTO users_organizations_old (
  uuid, user_uuid, org_uuid, access_all, akey, status, atype,
  reset_password_key, external_id, invited_by_email
)
SELECT
  uuid, user_uuid, org_uuid,
  CASE WHEN atype IN (0, 1) THEN TRUE ELSE FALSE END,
  akey, status,
  CASE WHEN atype = 4 THEN 2 ELSE atype END,
  reset_password_key, external_id, invited_by_email
FROM users_organizations;

DROP TABLE users_organizations;

ALTER TABLE users_organizations_old RENAME TO users_organizations;
