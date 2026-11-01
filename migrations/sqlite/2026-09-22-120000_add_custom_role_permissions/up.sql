-- Replace the membership-level `access_all` flag with the persisted Custom role and its nine
-- granular permissions.
--
-- Two different columns are called `access_all`, and everything below depends on keeping them apart:
--
--   * `users_organizations.access_all` -- the MEMBERSHIP-level bit this migration replaces. Dropped
--     at the end of this file.
--   * `groups.access_all` -- the GROUP-level flag, a separate and still-supported feature. It is not
--     read or written here and keeps granting group members access dynamically.
--
-- Only the membership bit is going away. While this file runs it still exists and `atype = 3` still
-- unambiguously means "legacy Manager".
--
-- One state cannot be converted and is refused before the first mutation; `src/db/mod.rs` evaluates
-- the same condition at startup and prints the recovery text, because Diesel would surface the abort
-- below as nothing but a driver-level duplicate-key error.

-- A plain User carrying membership `access_all`, reachable only on databases written before the web
-- vault stopped sending the flag. The bit gave read/write reach over every collection, present and
-- future, with no management authority, and the new model has no permission for that:
-- `edit_any_collection` would add management authority, dropping the bit would take the reach away.
-- Refuse and let an owner choose. The duplicate key aborts the migration, and is only inserted when
-- such a membership exists.
CREATE TEMPORARY TABLE __vw_legacy_user_access_all_guard (
    blocked INTEGER NOT NULL PRIMARY KEY
);
INSERT INTO __vw_legacy_user_access_all_guard (blocked) VALUES (1);
INSERT INTO __vw_legacy_user_access_all_guard (blocked)
SELECT 1
FROM users_organizations
WHERE atype = 2
  AND access_all = TRUE
LIMIT 1;
DROP TABLE __vw_legacy_user_access_all_guard;

-- Schema and data change in one table rebuild, which also keeps the conversion unambiguous:
-- `atype = 3` still means Manager while the permission values are computed from it.
--
-- `ALTER TABLE ... DROP COLUMN` is deliberately not used -- it needs SQLite 3.35.0, while a
-- `sqlite_system` build links whatever the host provides and libsqlite3-sys accepts 3.34.1. The
-- rebuild follows the existing 2022-03-02-210038_update_devices_primary_key pattern; Vaultwarden runs
-- SQLite migrations with `PRAGMA foreign_keys = OFF`, so the drop does not cascade into groups_users.
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
  access_event_logs BOOLEAN NOT NULL DEFAULT FALSE,
  access_import_export BOOLEAN NOT NULL DEFAULT FALSE,
  access_reports BOOLEAN NOT NULL DEFAULT FALSE,

  UNIQUE (user_uuid, org_uuid)
);

-- Owners and Admins are not touched: they carried `access_all` implicitly and the new model gives
-- them every permission by role. A plain User cannot reach this point carrying the bit (the guard
-- above), so only a Manager becomes Custom:
--
--   * membership `access_all` -- the "Manage all collections" checkbox -- covered all three
--     collection permissions, including creating collections;
--   * a Manager without membership `access_all` keeps all three at FALSE. In particular,
--     `groups.access_all` is not materialized into persistent membership permissions: it remains a
--     separate, dynamic group grant that ends when the group relationship or flag ends.
--
-- The management (manage_users / manage_groups / manage_policies) and access (event logs /
-- import-export / reports) permissions start out FALSE for everyone. Nothing they unlock was a Manager
-- capability -- every member mutation, every policy write, the organization export and both
-- event-log routes were gated on Admin/Owner -- so granting one here would be a new privilege.
--
-- `manage_users` is not granted to restore legacy read-only member-list behavior, because it also
-- carries invite, confirm, revoke, restore and delete, which the Manager role never had.
--
-- Status is deliberately not part of the predicate: an invited, accepted or revoked membership is
-- converted like a confirmed one, since none holds authority in that state and the permissions are
-- what it would come back with -- the same thing `access_all` would have done.
INSERT INTO users_organizations_new (
  uuid, user_uuid, org_uuid, akey, status, atype, reset_password_key, external_id,
  invited_by_email, manage_users, manage_groups, manage_policies,
  create_new_collections, edit_any_collection, delete_any_collection,
  access_event_logs, access_import_export, access_reports
)
SELECT
  uo.uuid, uo.user_uuid, uo.org_uuid, uo.akey, uo.status,
  CASE WHEN uo.atype = 3 THEN 4 ELSE uo.atype END,
  uo.reset_password_key, uo.external_id, uo.invited_by_email,
  FALSE, FALSE, FALSE,
  CASE WHEN uo.atype = 3 AND uo.access_all = TRUE THEN TRUE ELSE FALSE END,
  CASE WHEN uo.atype = 3 AND uo.access_all = TRUE THEN TRUE ELSE FALSE END,
  CASE WHEN uo.atype = 3 AND uo.access_all = TRUE THEN TRUE ELSE FALSE END,
  FALSE, FALSE, FALSE
FROM users_organizations AS uo;

DROP TABLE users_organizations;

ALTER TABLE users_organizations_new RENAME TO users_organizations;
