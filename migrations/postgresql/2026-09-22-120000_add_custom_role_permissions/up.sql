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

ALTER TABLE users_organizations
    ADD COLUMN manage_users BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN manage_groups BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN manage_policies BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN create_new_collections BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN edit_any_collection BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN delete_any_collection BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN access_event_logs BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN access_import_export BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN access_reports BOOLEAN NOT NULL DEFAULT FALSE;

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
-- import-export / reports) permissions keep their FALSE default. Nothing they unlock was a Manager
-- capability -- every member mutation, every policy write, the organization export and both
-- event-log routes were gated on Admin/Owner -- so granting one here would be a new privilege.
--
-- `manage_users` is not granted to restore legacy read-only member-list behavior, because it also
-- carries invite, confirm, revoke, restore and delete, which the Manager role never had.
--
-- Role conversion and permission values are one statement, so `atype = 3` unambiguously still means
-- Manager everywhere it is read.
--
-- Status is deliberately not part of the predicate: an invited, accepted or revoked membership is
-- converted like a confirmed one, since none holds authority in that state and the permissions are
-- what it would come back with -- the same thing `access_all` would have done.
UPDATE users_organizations
SET create_new_collections = access_all,
    edit_any_collection = access_all,
    delete_any_collection = access_all,
    atype = 4
WHERE atype = 3;

-- The membership flag is now represented by the role model: Owners/Admins hold it implicitly and a
-- Custom member that held it has all three collection permissions. `groups.access_all` stays separate.
ALTER TABLE users_organizations DROP COLUMN access_all;
