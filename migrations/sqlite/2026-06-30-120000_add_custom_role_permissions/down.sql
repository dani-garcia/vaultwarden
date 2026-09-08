-- Lossy revert: the legacy role/`access_all` schema cannot represent the nine Custom permissions or
-- the Custom role. Two explicit operator decisions are required before anything is touched, and both
-- are consumed at the end, so one decision covers one downgrade. Operators who only need the older
-- binary to start again can use the self-contained script per backend in tools/custom_role_rollback/.

-- 1) Acknowledge the loss. Create this table with every Vaultwarden instance stopped:
--
--        CREATE TABLE __vw_allow_custom_role_downgrade (acknowledged INTEGER NOT NULL PRIMARY KEY);
--
--    The duplicate key aborts the revert. It is only inserted while the acknowledgement is absent.
CREATE TEMPORARY TABLE __vw_custom_role_downgrade_guard (
    blocked INTEGER NOT NULL PRIMARY KEY
);
INSERT INTO __vw_custom_role_downgrade_guard (blocked) VALUES (1);
INSERT INTO __vw_custom_role_downgrade_guard (blocked)
SELECT 1
WHERE NOT EXISTS (
    SELECT 1 FROM sqlite_master
    WHERE type = 'table' AND name = '__vw_allow_custom_role_downgrade'
);
DROP TABLE __vw_custom_role_downgrade_guard;

-- 2) Decide which Custom memberships come back as Manager. The legacy role is not a subset of what a
--    Custom member holds, so handing it out automatically would *grant* authority during a
--    downgrade; it takes a current, deliberate list. An empty list is a valid answer and maps every
--    Custom member to plain User. See README.md in tools/custom_role_rollback/.
--
--        CREATE TABLE __vw_rollback_manager_allowlist (users_organizations_uuid TEXT NOT NULL PRIMARY KEY);
--        INSERT INTO __vw_rollback_manager_allowlist (users_organizations_uuid) VALUES ('<MEMBERSHIP_UUID>');
--
--    The duplicate key aborts the revert. It is only inserted while the list is absent.
CREATE TEMPORARY TABLE __vw_rollback_allowlist_guard (
    blocked INTEGER NOT NULL PRIMARY KEY
);
INSERT INTO __vw_rollback_allowlist_guard (blocked) VALUES (1);
INSERT INTO __vw_rollback_allowlist_guard (blocked)
SELECT 1
WHERE NOT EXISTS (
    SELECT 1 FROM sqlite_master
    WHERE type = 'table' AND name = '__vw_rollback_manager_allowlist'
);
DROP TABLE __vw_rollback_allowlist_guard;

-- Roles and `access_all` are recomputed together, because in the old schema they are not independent:
--
--   * Owners and Admins always carried the bit and it grants them nothing extra;
--   * an allowlisted Custom member becomes a Manager, keeping the bit only with all three collection
--     permissions -- `access_all` also carried collection deletion there, so an Edit-only member must
--     not silently gain it;
--   * everything else becomes a plain User without the bit. `User + access_all` is the one legacy
--     state the upgrade refuses, so leaving it set would strand the database.
--
-- Group-derived Manager authority needs no restoring: `groups.access_all` was never modified, so the
-- older binary derives it again for whoever comes back as Manager.
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
  uo.uuid, uo.user_uuid, uo.org_uuid,
  CASE
    WHEN uo.atype IN (0, 1) THEN TRUE
    WHEN uo.atype = 4
     AND uo.uuid IN (SELECT users_organizations_uuid FROM __vw_rollback_manager_allowlist)
     AND uo.create_new_collections = TRUE
     AND uo.edit_any_collection = TRUE
     AND uo.delete_any_collection = TRUE THEN TRUE
    ELSE FALSE
  END,
  uo.akey, uo.status,
  CASE
    WHEN uo.atype = 4
     AND uo.uuid IN (SELECT users_organizations_uuid FROM __vw_rollback_manager_allowlist) THEN 3
    WHEN uo.atype = 4 THEN 2
    ELSE uo.atype
  END,
  uo.reset_password_key, uo.external_id, uo.invited_by_email
FROM users_organizations AS uo;

DROP TABLE users_organizations;

ALTER TABLE users_organizations_old RENAME TO users_organizations;

-- Both decisions authorized *this* downgrade, not the next one.
DROP TABLE IF EXISTS __vw_allow_custom_role_downgrade;
DROP TABLE IF EXISTS __vw_rollback_manager_allowlist;
