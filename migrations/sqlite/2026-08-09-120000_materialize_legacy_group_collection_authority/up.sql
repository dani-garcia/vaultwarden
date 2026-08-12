-- Follow-up repair for databases that already recorded 2026-07-23-120000.
--
-- That migration originally *removed* the direct 0/1/1 collection permissions of a legacy Manager
-- whose authority came from an organization-local `access_all` group, because the runtime derived the
-- authority from the group instead. Deriving it turned out to be unsound -- "Custom, none of the three
-- collection permissions, member of such a group" is also the shape of every newly created flagless
-- Custom member -- so the runtime fallback is gone and 2026-07-23-120000 now materializes the
-- authority into the permission columns.
--
-- Rewriting that file is not enough on its own: a database whose ledger already carries
-- 20260723120000 never runs it again, and would silently lose the capability. Repeat the
-- materialization here, in its own version, so both paths converge on the same state.
--
-- Unlike an earlier revision of this file, the repair is driven by the legacy-Manager record written
-- by 2026-06-30-120000 rather than by role and group membership alone. Those two are the same shape,
-- so matching on them blanket-granted organization-wide collection edit and delete to modern Custom
-- members -- turning Create-only into Create+Edit+Delete, Edit-only into Edit+Delete, and a flagless
-- Custom into Edit+Delete, the last of which also implies `has_full_access()`.
--
-- What this materialization *means* -- a group-bound capability becoming a permanent membership
-- permission -- is confirmed by an owner in 2026-08-10-120000, which runs immediately after it.
--
-- Idempotent: on a database that ran the rewritten 2026-07-23-120000 every affected row already
-- holds these values. It only reads `groups` / `groups_users` and the record table and writes the two
-- permission columns, so it is also safe after `access_all` has been dropped.
--
-- Deliberately not `create_new_collections`: collection creation historically required
-- membership-level `access_all`.

-- The legacy-Manager record has to exist already; see 2026-07-23-120000 for why this refuses rather
-- than creating it.
--
-- The duplicate key aborts the migration. It is only inserted while the record table is absent.
CREATE TEMPORARY TABLE __vw_legacy_manager_record_guard (
    blocked INTEGER NOT NULL PRIMARY KEY
);
INSERT INTO __vw_legacy_manager_record_guard (blocked) VALUES (1);
INSERT INTO __vw_legacy_manager_record_guard (blocked)
SELECT 1
WHERE NOT EXISTS (
    SELECT 1 FROM sqlite_master
    WHERE type = 'table' AND name = '__vw_custom_role_legacy_manager'
);
DROP TABLE __vw_legacy_manager_record_guard;

-- Fail closed on a database whose legacy provenance was never recorded.
--
-- If a Custom member sits in an organization-local `access_all` group but is not on record as a
-- legacy Manager, one of two things is true and this file cannot tell them apart: either the
-- membership really is a converted legacy Manager whose record was never written (a ledger from an
-- earlier revision of this feature branch), or it is an ordinary modern Custom member who must not
-- gain anything. Granting is a silent privilege escalation; skipping silently drops a real
-- capability.
--
-- `__vw_custom_role_history_verified` settles it: 2026-06-30-120000 creates it, and an operator
-- creates it after auditing an older history, so its presence means the unrecorded memberships below
-- are unrecorded *on purpose*. Its absence means nobody has looked, and this stops. The startup
-- preflight refuses that state before any migration runs; this guard is the backstop for a bare
-- migration runner. `src/db/mod.rs` prints the full recovery, which lists these memberships:
--
--     SELECT uo.uuid, uo.org_uuid, uo.status,
--            uo.create_new_collections, uo.edit_any_collection, uo.delete_any_collection
--     FROM users_organizations uo
--     INNER JOIN groups_users gu ON gu.users_organizations_uuid = uo.uuid
--     INNER JOIN "groups" g ON g.uuid = gu.groups_uuid AND g.organizations_uuid = uo.org_uuid
--     WHERE uo.atype = 4 AND g.access_all = 1
--       AND uo.uuid NOT IN (SELECT users_organizations_uuid FROM __vw_custom_role_legacy_manager);
--
-- The marker never grants anything by itself: the update below is always driven by the record table,
-- so an unrecorded membership keeps exactly the permissions it has.
CREATE TEMPORARY TABLE __vw_legacy_group_authority_guard (
    blocked INTEGER NOT NULL PRIMARY KEY
);
INSERT INTO __vw_legacy_group_authority_guard (blocked) VALUES (1);
INSERT INTO __vw_legacy_group_authority_guard (blocked)
SELECT 1
FROM users_organizations AS uo
WHERE uo.atype = 4
  AND uo.uuid NOT IN (SELECT users_organizations_uuid FROM __vw_custom_role_legacy_manager)
  AND EXISTS (
    SELECT 1
    FROM groups_users AS gu
    INNER JOIN "groups" AS g ON g.uuid = gu.groups_uuid
    WHERE gu.users_organizations_uuid = uo.uuid
      AND g.organizations_uuid = uo.org_uuid
      AND g.access_all = TRUE
  )
  AND NOT EXISTS (
    SELECT 1 FROM sqlite_master
    WHERE type = 'table' AND name = '__vw_custom_role_history_verified'
  )
LIMIT 1;
DROP TABLE __vw_legacy_group_authority_guard;

UPDATE users_organizations
SET edit_any_collection = TRUE,
    delete_any_collection = TRUE
WHERE atype = 4
  AND uuid IN (SELECT users_organizations_uuid FROM __vw_custom_role_legacy_manager)
  AND EXISTS (
    SELECT 1
    FROM groups_users AS gu
    INNER JOIN "groups" AS g ON g.uuid = gu.groups_uuid
    WHERE gu.users_organizations_uuid = users_organizations.uuid
      AND g.organizations_uuid = users_organizations.org_uuid
      AND g.access_all = TRUE
  );
