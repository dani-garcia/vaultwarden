-- Roll a PostgreSQL database back to the schema the Vaultwarden version *before* the Custom-role
-- change expects, so that older binary starts again. Read README.md in this directory first --
-- it lists exactly what is lost and how to run this safely.
--
-- PostgreSQL DDL is transactional, so this whole script either applies or it does not.
--
-- Everything runs inside one DO block against schema-qualified names. An unqualified relation is
-- resolved per statement through `search_path`, i.e. to the first schema that happens to contain a
-- matching name -- so a session with `search_path = decoy, real` could have the checks and the table
-- rewrite land in `decoy` while the ledger delete hits `real`, leaving the real database with a new
-- schema and a ledger claiming the old one. Resolving each relation once, requiring all of them to
-- live in the *same* namespace, and then addressing that namespace explicitly removes the ambiguity.

BEGIN;

DO $$
DECLARE
    memberships regclass := to_regclass('users_organizations');
    ledger      regclass := to_regclass('__diesel_schema_migrations');
    allowlist   regclass := to_regclass('__vw_rollback_manager_allowlist');
    history     regclass := to_regclass('__vw_custom_role_history_verified');
    ns oid;
    ns_name text;
    access_all_present int;
    permission_columns int;
    allowlist_columns int;
    ledger_rows int;
    future_rows int;
BEGIN
    -- ---------------------------------------------------------------------------------------------
    -- Bind the target. Read-only: this inspects the catalog and the migration ledger and changes
    -- nothing, so a database this script does not fit keeps its exact state. The transaction would
    -- roll back a mismatch anyway; this turns a raw "column does not exist" into a message that says
    -- what to do, and it keeps all three backends' scripts symmetrical.
    -- ---------------------------------------------------------------------------------------------
    IF memberships IS NULL THEN
        RAISE EXCEPTION 'Rollback refused, nothing was changed: no users_organizations table is '
                        'reachable through the current search_path. Connect to the database and '
                        'schema Vaultwarden uses.';
    END IF;

    IF ledger IS NULL THEN
        RAISE EXCEPTION 'Rollback refused, nothing was changed: no __diesel_schema_migrations table '
                        'is reachable through the current search_path.';
    END IF;

    IF history IS NULL THEN
        RAISE EXCEPTION 'Rollback refused, nothing was changed: __vw_custom_role_history_verified '
                        'does not exist, so this database was migrated by an earlier revision of the '
                        'Custom-role change, whose migrations had different effects. Start '
                        'Vaultwarden once and follow the recovery it prints before rolling back.';
    END IF;

    IF allowlist IS NULL THEN
        RAISE EXCEPTION 'Rollback refused, nothing was changed: __vw_rollback_manager_allowlist does '
                        'not exist. Which memberships come back as legacy Manager has to be decided '
                        'for this rollback -- an empty list is a valid answer and maps every Custom '
                        'member to plain User. See README.md, section "Choosing which members come '
                        'back as Manager".';
    END IF;

    SELECT relnamespace INTO ns FROM pg_class WHERE oid = memberships;

    IF (SELECT relnamespace FROM pg_class WHERE oid = ledger) <> ns
       OR (SELECT relnamespace FROM pg_class WHERE oid = allowlist) <> ns
       OR (SELECT relnamespace FROM pg_class WHERE oid = history) <> ns THEN
        RAISE EXCEPTION 'Rollback refused, nothing was changed: the tables this script needs resolve '
                        'to different schemas through the current search_path -- '
                        'users_organizations in "%", __diesel_schema_migrations in "%", '
                        '__vw_rollback_manager_allowlist in "%", '
                        '__vw_custom_role_history_verified in "%". Set search_path to exactly the '
                        'schema Vaultwarden uses and run this again.',
                        (SELECT nspname FROM pg_namespace WHERE oid = ns),
                        (SELECT n.nspname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                          WHERE c.oid = ledger),
                        (SELECT n.nspname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                          WHERE c.oid = allowlist),
                        (SELECT n.nspname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                          WHERE c.oid = history);
    END IF;

    SELECT nspname INTO ns_name FROM pg_namespace WHERE oid = ns;

    SELECT count(*) INTO access_all_present
    FROM pg_attribute
    WHERE attrelid = memberships
      AND attnum > 0
      AND NOT attisdropped
      AND attname = 'access_all';

    SELECT count(*) INTO permission_columns
    FROM pg_attribute
    WHERE attrelid = memberships
      AND attnum > 0
      AND NOT attisdropped
      AND attname IN (
          'manage_users', 'manage_groups', 'manage_policies',
          'create_new_collections', 'edit_any_collection', 'delete_any_collection',
          'access_event_logs', 'access_import_export', 'access_reports'
      );

    -- The allowlist is read by the role mapping below, so a hand-written table of the right name but
    -- the wrong shape has to be caught here rather than mid-rewrite.
    SELECT count(*) INTO allowlist_columns
    FROM pg_attribute
    WHERE attrelid = allowlist
      AND attnum > 0
      AND NOT attisdropped
      AND attname = 'users_organizations_uuid';

    EXECUTE format(
        'SELECT count(*) FROM %I.__diesel_schema_migrations WHERE version IN ('
        '''20260630120000'', ''20260715120000'', ''20260716120000'', ''20260723120000'','
        '''20260724120000'', ''20260724130000'', ''20260724140000'', ''20260809120000'','
        '''20260810120000'')',
        ns_name
    ) INTO ledger_rows;

    EXECUTE format(
        'SELECT count(*) FROM %I.__diesel_schema_migrations WHERE version > ''20260810120000''',
        ns_name
    ) INTO future_rows;

    IF access_all_present <> 0 THEN
        RAISE EXCEPTION 'Rollback refused, nothing was changed: users_organizations.access_all still '
                        'exists. This database was either never upgraded past the Custom-role '
                        'migrations, or this script already ran.';
    END IF;

    IF permission_columns <> 9 THEN
        RAISE EXCEPTION 'Rollback refused, nothing was changed: expected all nine Custom-role '
                        'permission columns on users_organizations, found %. The upgrade is '
                        'incomplete, so restore the backup taken before it and start over.',
                        permission_columns;
    END IF;

    IF allowlist_columns <> 1 THEN
        RAISE EXCEPTION 'Rollback refused, nothing was changed: __vw_rollback_manager_allowlist has '
                        'no users_organizations_uuid column. Create it as documented in README.md.';
    END IF;

    IF ledger_rows <> 9 THEN
        RAISE EXCEPTION 'Rollback refused, nothing was changed: expected all nine Custom-role '
                        'migrations in __diesel_schema_migrations, found %. Schema and ledger '
                        'disagree, so restore the backup taken before the upgrade and start over.',
                        ledger_rows;
    END IF;

    IF future_rows <> 0 THEN
        RAISE EXCEPTION 'Rollback refused, nothing was changed: % migration(s) newer than the '
                        'Custom-role change are recorded. This script does not know what they '
                        'changed, and removing only the nine Custom-role versions would leave the '
                        'ledger inconsistent. Use the rollback script shipped with that newer '
                        'version.',
                        future_rows;
    END IF;

    -- ---------------------------------------------------------------------------------------------
    -- From here on the database is known to be in the state this script converts *from*, and every
    -- statement addresses the one namespace bound above.
    -- ---------------------------------------------------------------------------------------------
    EXECUTE format(
        'ALTER TABLE %I.users_organizations ADD COLUMN access_all BOOLEAN NOT NULL DEFAULT FALSE',
        ns_name
    );

    -- Only a membership on the allowlist comes back as Manager. The legacy Manager role is not a
    -- subset of what a Custom member holds -- it manages, and deletes, every collection reachable
    -- through `users_collections.manage`, `collections_groups.manage` or `groups.access_all`, and
    -- reads member and collection ACL details through `ManagerHeadersLoose`, none of which needs a
    -- permission flag in the old schema -- so handing it out on anything less than a current,
    -- deliberate decision would *grant* authority during a downgrade.
    -- `__vw_custom_role_legacy_manager` is not that decision: it records who was a Manager before the
    -- first upgrade and is never updated afterwards, so a member whose powers an owner has since
    -- reduced would get all of them back.
    --
    -- Everything else becomes a plain User and keeps its per-collection assignments.
    --
    -- `access_all` follows the same mapping the down migrations use: everyone who reached every
    -- collection keeps that reach, and a Custom member has to hold all three collection permissions
    -- -- Edit-only must not silently turn into the legacy "manage all collections" authority, which
    -- in that older schema also carried collection deletion. A member mapped to plain User never
    -- keeps it: `User + access_all` is the one legacy state the upgrade refuses.
    EXECUTE format(
        'UPDATE %I.users_organizations SET access_all = TRUE WHERE atype IN (0, 1)', ns_name
    );
    EXECUTE format(
        'UPDATE %I.users_organizations SET access_all = TRUE '
        'WHERE atype = 4 '
        '  AND uuid IN (SELECT users_organizations_uuid FROM %I.__vw_rollback_manager_allowlist) '
        '  AND create_new_collections = TRUE '
        '  AND edit_any_collection = TRUE '
        '  AND delete_any_collection = TRUE',
        ns_name, ns_name
    );

    -- The old server cannot load type 4.
    EXECUTE format(
        'UPDATE %I.users_organizations SET atype = 3 '
        'WHERE atype = 4 '
        '  AND uuid IN (SELECT users_organizations_uuid FROM %I.__vw_rollback_manager_allowlist)',
        ns_name, ns_name
    );
    EXECUTE format(
        'UPDATE %I.users_organizations SET atype = 2, access_all = FALSE WHERE atype = 4', ns_name
    );

    EXECUTE format(
        'ALTER TABLE %I.users_organizations '
        '  DROP COLUMN manage_users, '
        '  DROP COLUMN manage_groups, '
        '  DROP COLUMN manage_policies, '
        '  DROP COLUMN create_new_collections, '
        '  DROP COLUMN edit_any_collection, '
        '  DROP COLUMN delete_any_collection, '
        '  DROP COLUMN access_event_logs, '
        '  DROP COLUMN access_import_export, '
        '  DROP COLUMN access_reports',
        ns_name
    );

    -- Bookkeeping tables this feature may have left behind. A later re-upgrade rebuilds the
    -- provenance record and the history marker from the very `atype = 3` rows this script just
    -- restored, so the round trip converges.
    EXECUTE format('DROP TABLE IF EXISTS %I.__vw_custom_role_same_run_0716', ns_name);
    EXECUTE format('DROP TABLE IF EXISTS %I.__vw_allow_custom_role_downgrade', ns_name);
    EXECUTE format('DROP TABLE IF EXISTS %I.__vw_ack_permanent_collection_authority', ns_name);
    EXECUTE format('DROP TABLE IF EXISTS %I.__vw_rollback_manager_allowlist', ns_name);
    EXECUTE format('DROP TABLE IF EXISTS %I.__vw_custom_role_legacy_manager', ns_name);
    EXECUTE format('DROP TABLE IF EXISTS %I.__vw_custom_role_history_verified', ns_name);

    -- Finally forget the nine migrations, so the older binary does not see a ledger from the future
    -- and a later upgrade applies them again from a clean state.
    EXECUTE format(
        'DELETE FROM %I.__diesel_schema_migrations WHERE version IN ('
        '''20260630120000'', ''20260715120000'', ''20260716120000'', ''20260723120000'','
        '''20260724120000'', ''20260724130000'', ''20260724140000'', ''20260809120000'','
        '''20260810120000'')',
        ns_name
    );
END $$;

COMMIT;
