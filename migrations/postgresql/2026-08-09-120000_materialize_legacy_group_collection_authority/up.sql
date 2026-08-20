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
DO $$
DECLARE
    undecidable int := 0;
BEGIN
    -- The legacy-Manager record has to exist already; see 2026-07-23-120000 for why this refuses
    -- rather than creating it.
    IF to_regclass('__vw_custom_role_legacy_manager') IS NULL THEN
        RAISE EXCEPTION
            'Upgrade refused, nothing was changed: __vw_custom_role_legacy_manager does not exist, '
            'so which memberships were legacy Managers before the upgrade is unknown. Start '
            'Vaultwarden once to get the full recovery instructions, or see '
            'tools/custom_role_rollback/README.md.';
    END IF;

    -- Fail closed on a database whose legacy provenance was never recorded.
    --
    -- If a Custom member sits in an organization-local `access_all` group but is not on record as a
    -- legacy Manager, one of two things is true and this file cannot tell them apart: either the
    -- membership really is a converted legacy Manager whose record was never written (a ledger from
    -- an earlier revision of this feature branch), or it is an ordinary modern Custom member who must
    -- not gain anything. Granting is a silent privilege escalation; skipping silently drops a real
    -- capability.
    --
    -- `__vw_custom_role_history_verified` settles it: 2026-06-30-120000 creates it, and an operator
    -- creates it after auditing an older history, so its presence means the unrecorded memberships
    -- are unrecorded *on purpose*. Its absence means nobody has looked, and this stops. The startup
    -- preflight refuses that state before any migration runs; this is the backstop for a bare
    -- migration runner.
    --
    -- The marker never grants anything by itself: the update below is always driven by the record
    -- table, so an unrecorded membership keeps exactly the permissions it has.
    IF to_regclass('__vw_custom_role_history_verified') IS NULL THEN
        SELECT count(*) INTO undecidable
        FROM users_organizations uo
        WHERE uo.atype = 4
          AND uo.uuid NOT IN (SELECT users_organizations_uuid FROM __vw_custom_role_legacy_manager)
          AND EXISTS (
            SELECT 1
            FROM groups_users gu
            INNER JOIN "groups" g ON g.uuid = gu.groups_uuid
            WHERE gu.users_organizations_uuid = uo.uuid
              AND g.organizations_uuid = uo.org_uuid
              AND g.access_all = TRUE
          );
    END IF;

    IF undecidable <> 0 THEN
        RAISE EXCEPTION
            'Upgrade refused, nothing was changed: % Custom membership(s) belong to an access_all '
            'group but are not on record as legacy Managers, and this database''s Custom-role '
            'history has never been audited, so a converted legacy Manager cannot be told from an '
            'ordinary Custom member. Review them with: SELECT uo.uuid, uo.org_uuid, uo.status, '
            'uo.create_new_collections, uo.edit_any_collection, uo.delete_any_collection FROM '
            'users_organizations uo JOIN groups_users gu ON gu.users_organizations_uuid = uo.uuid '
            'JOIN "groups" g ON g.uuid = gu.groups_uuid AND g.organizations_uuid = uo.org_uuid '
            'WHERE uo.atype = 4 AND g.access_all AND uo.uuid NOT IN (SELECT '
            'users_organizations_uuid FROM __vw_custom_role_legacy_manager); Start Vaultwarden once '
            'for the full recovery instructions.',
            undecidable;
    END IF;
END $$;

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
