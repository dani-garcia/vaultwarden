-- Replace the membership-level `access_all` flag with the persisted Custom role and its nine
-- granular permissions.
--
-- Two different columns are called `access_all`, and everything below depends on keeping them apart:
--
--   * `users_organizations.access_all` -- the MEMBERSHIP-level bit this migration replaces. Dropped
--     at the end of this file.
--   * `groups.access_all` -- the GROUP-level flag, a separate and still-supported feature. Only read
--     here, to decide a legacy Manager's permissions; never written, and it keeps granting group
--     members access to every collection afterwards exactly as before.
--
-- Base `Collection::is_coll_manageable_by_user` accepts either, so a Manager reached every collection
-- through either. Only the membership bit is going away, but the capability an owner configured
-- through either route is preserved, so both are read below. While this file runs the membership
-- column still exists and `atype = 3` still unambiguously means "legacy Manager".
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
-- above), so only a Manager becomes Custom, keeping the organization-wide collection-management
-- capability it is configured with right now:
--
--   * membership `access_all` -- the "Manage all collections" checkbox -- covered all three
--     collection permissions, including creating collections;
--   * an organization-local `access_all` group covered editing and deleting every collection, but
--     never creation -- that always required the membership bit;
--   * a Manager with neither keeps all three at FALSE.
--
-- The second case is a deliberate policy choice. That capability was dynamic: it ended with the
-- group, with the group's own `access_all`, and with the member leaving it. It was never gated on
-- ORG_GROUPS_ENABLED -- `Collection::is_coll_manageable_by_user` reads `groups.access_all` in SQL
-- with no configuration check -- so it applied even where groups were never enabled. Nothing in the
-- new model is bound to a group, so it becomes a membership permission and no longer lapses on its
-- own. The alternative is silently revoking access these members have today, or refusing an ordinary
-- upgrade; the permission is visible in the member's permission list and an owner can clear it.
--
-- The management (manage_users / manage_groups / manage_policies) and access (event logs /
-- import-export / reports) permissions keep their FALSE default. Nothing they unlock was a Manager
-- capability -- every member mutation, every policy write, the organization export and both
-- event-log routes were gated on Admin/Owner -- so granting one here would be a new privilege.
--
-- One read is not carried over, and only for members who held the MEMBERSHIP bit: `has_full_access()`
-- read `self.access_all` and the role, never `groups.access_all`, so it gated the full member list
-- (`GET /organizations/<org>/users`) for them and for nobody whose reach came from a group.
-- `manage_users` is not granted to restore it, because it also carries invite, confirm, revoke,
-- restore and delete, which the Manager role never had; such members keep `/users/mini-details`, and
-- an owner can grant `manage_users` deliberately. In the other direction `edit_any_collection`
-- satisfies `has_full_access()`, which opens the organization collection list and
-- `GET /ciphers/organization-details` to the group-derived class -- data they could already reach
-- through the group, so only the route is new.
--
-- Role conversion and permission values are one statement, so `atype = 3` unambiguously still means
-- Manager everywhere it is read.
--
-- Status is deliberately not part of the predicate: an invited, accepted or revoked membership is
-- converted like a confirmed one, since none holds authority in that state and the permissions are
-- what it would come back with -- the same thing `access_all` would have done.
--
-- The group lookup is bound to the membership's own organization: a `groups_users` row pointing at
-- another organization's `access_all` group conveys nothing, exactly as it conveys nothing today.
UPDATE users_organizations
SET create_new_collections = access_all,
    edit_any_collection = access_all
        OR EXISTS (
            SELECT 1
            FROM groups_users AS gu
            INNER JOIN "groups" AS g ON g.uuid = gu.groups_uuid
            WHERE gu.users_organizations_uuid = users_organizations.uuid
              AND g.organizations_uuid = users_organizations.org_uuid
              AND g.access_all = TRUE
        ),
    delete_any_collection = access_all
        OR EXISTS (
            SELECT 1
            FROM groups_users AS gu
            INNER JOIN "groups" AS g ON g.uuid = gu.groups_uuid
            WHERE gu.users_organizations_uuid = users_organizations.uuid
              AND g.organizations_uuid = users_organizations.org_uuid
              AND g.access_all = TRUE
        ),
    atype = 4
WHERE atype = 3;

-- The flag is now fully represented by the role model: Owners/Admins hold it implicitly, a Custom
-- member holds it through `edit_any_collection`. Drop the redundant column. This only concerns
-- users_organizations; `groups.access_all` stays.
ALTER TABLE users_organizations DROP COLUMN access_all;

-- Never inherit a downgrade acknowledgement left behind by an earlier revert.
DROP TABLE IF EXISTS __vw_allow_custom_role_downgrade;
