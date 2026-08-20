-- The membership `access_all` flag was Vaultwarden's pre-permissions patch for "this member can
-- reach every collection". It is now fully represented by the role model: Owners/Admins hold it
-- implicitly, and a Custom member holds it via `edit_any_collection`. Drop the redundant column.
-- This only concerns users_organizations; groups.access_all is a separate, still-supported feature.
--
-- `ALTER TABLE ... DROP COLUMN` is deliberately NOT used here: it only exists since SQLite 3.35.0,
-- while a `sqlite_system` build links whatever the host provides and libsqlite3-sys accepts 3.34.1
-- (which is what Debian 11 ships). Forward migrations have to run on every supported build, so use
-- the portable table rebuild instead -- the same pattern as
-- 2022-03-02-210038_update_devices_primary_key. Vaultwarden runs SQLite migrations with
-- `PRAGMA foreign_keys = OFF`, so dropping the old table does not cascade into groups_users.
CREATE TABLE users_organizations_new (
  uuid       TEXT    NOT NULL PRIMARY KEY,
  user_uuid  TEXT    NOT NULL REFERENCES users (uuid),
  org_uuid   TEXT    NOT NULL REFERENCES organizations (uuid),

  akey        TEXT    NOT NULL,
  status     INTEGER NOT NULL,
  atype       INTEGER NOT NULL,
  reset_password_key TEXT,
  external_id TEXT,
  invited_by_email TEXT DEFAULT NULL,
  manage_users BOOLEAN NOT NULL DEFAULT FALSE,
  manage_groups BOOLEAN NOT NULL DEFAULT FALSE,
  manage_policies BOOLEAN NOT NULL DEFAULT FALSE,
  create_new_collections BOOLEAN NOT NULL DEFAULT FALSE,
  edit_any_collection BOOLEAN NOT NULL DEFAULT FALSE,
  delete_any_collection BOOLEAN NOT NULL DEFAULT FALSE,

  UNIQUE (user_uuid, org_uuid)
);

INSERT INTO users_organizations_new (
  uuid, user_uuid, org_uuid, akey, status, atype, reset_password_key, external_id,
  invited_by_email, manage_users, manage_groups, manage_policies,
  create_new_collections, edit_any_collection, delete_any_collection
)
SELECT
  uuid, user_uuid, org_uuid, akey, status, atype, reset_password_key, external_id,
  invited_by_email, manage_users, manage_groups, manage_policies,
  create_new_collections, edit_any_collection, delete_any_collection
FROM users_organizations;

DROP TABLE users_organizations;

ALTER TABLE users_organizations_new RENAME TO users_organizations;
