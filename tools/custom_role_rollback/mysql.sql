-- Roll a MySQL/MariaDB database back to the schema the Vaultwarden version *before* the Custom-role
-- change expects, so that older binary starts again. Read README.md in this directory first --
-- it lists exactly what is lost and how to run this safely.
--
-- NOTE: MySQL/MariaDB commit every DDL statement implicitly, so this script cannot be wrapped in a
-- transaction. That is exactly why everything below the precondition has to be reached in a known
-- state: an ALTER that fails halfway leaves every earlier statement committed. Take a backup before
-- running it; if it is interrupted, restore and start over.

-- ---------------------------------------------------------------------------------------------
-- Precondition. Read-only and session-local: it reads `information_schema` and the migration ledger,
-- prints the reason when the database does not fit, and aborts on a duplicate key in a TEMPORARY
-- table. No permanent object is created, altered or dropped, so a database this script does not fit
-- keeps its exact state -- which matters here precisely because DDL cannot be rolled back.
--
-- Without it, a partially upgraded database -- for example one where `access_all` was already dropped
-- but the access-permission columns were never added, which DDL autocommit makes reachable -- would
-- get through the first ADD COLUMN, the value rewrites, the type change and six DROP COLUMN statements before
-- failing on the seventh with error 1091, ending up *less* consistent than before.
--
-- Deliberately not a stored procedure with SIGNAL: MySQL caps `MESSAGE_TEXT` at 128 characters and
-- answers a longer one with "ERROR 1648 Data too long for condition item 'MESSAGE_TEXT'" instead of
-- the diagnosis (MariaDB accepts it, so the difference is easy to miss), and CREATE PROCEDURE is a
-- permanent object that would have to be written *before* the checks have run -- replacing any
-- same-named routine, surviving a refusal, and requiring routine privileges this script otherwise
-- does not need.
-- ---------------------------------------------------------------------------------------------
CREATE TEMPORARY TABLE __vw_rollback_precondition (
    ok INTEGER NOT NULL PRIMARY KEY
);
INSERT INTO __vw_rollback_precondition (ok) VALUES (1);

-- 1) Membership `access_all` has to be gone already, i.e. the upgrade ran and this script did not.
SELECT CONCAT(
    'REFUSED, nothing was changed: users_organizations.access_all still exists. This database was ',
    'either never upgraded past the Custom-role migrations, or this script already ran.'
) AS rollback_precondition_failure
FROM information_schema.columns
WHERE table_schema = DATABASE()
  AND table_name = 'users_organizations'
  AND column_name = 'access_all';
INSERT INTO __vw_rollback_precondition (ok)
SELECT 1
FROM information_schema.columns
WHERE table_schema = DATABASE()
  AND table_name = 'users_organizations'
  AND column_name = 'access_all';

-- 2) All nine permission columns have to be present.
SELECT CONCAT(
    'REFUSED, nothing was changed: expected all nine Custom-role permission columns on ',
    'users_organizations, found ', c.n, '. The upgrade is incomplete, so restore the backup taken ',
    'before it and start over.'
) AS rollback_precondition_failure
FROM (
    SELECT COUNT(*) AS n
    FROM information_schema.columns
    WHERE table_schema = DATABASE()
      AND table_name = 'users_organizations'
      AND column_name IN (
          'manage_users', 'manage_groups', 'manage_policies',
          'create_new_collections', 'edit_any_collection', 'delete_any_collection',
          'access_event_logs', 'access_import_export', 'access_reports'
      )
) AS c
WHERE c.n <> 9;
INSERT INTO __vw_rollback_precondition (ok)
SELECT 1
FROM (
    SELECT COUNT(*) AS n
    FROM information_schema.columns
    WHERE table_schema = DATABASE()
      AND table_name = 'users_organizations'
      AND column_name IN (
          'manage_users', 'manage_groups', 'manage_policies',
          'create_new_collections', 'edit_any_collection', 'delete_any_collection',
          'access_event_logs', 'access_import_export', 'access_reports'
      )
) AS c
WHERE c.n <> 9;

-- 3) All nine Custom-role migrations have to be recorded.
SELECT CONCAT(
    'REFUSED, nothing was changed: expected all nine Custom-role migrations in ',
    '__diesel_schema_migrations, found ', c.n, '. Schema and ledger disagree, so restore the backup ',
    'taken before the upgrade and start over.'
) AS rollback_precondition_failure
FROM (
    SELECT COUNT(*) AS n
    FROM __diesel_schema_migrations
    WHERE version IN (
        '20260630120000',
        '20260715120000',
        '20260716120000',
        '20260723120000',
        '20260724120000',
        '20260724130000',
        '20260724140000',
        '20260809120000',
        '20260810120000'
    )
) AS c
WHERE c.n <> 9;
INSERT INTO __vw_rollback_precondition (ok)
SELECT 1
FROM (
    SELECT COUNT(*) AS n
    FROM __diesel_schema_migrations
    WHERE version IN (
        '20260630120000',
        '20260715120000',
        '20260716120000',
        '20260723120000',
        '20260724120000',
        '20260724130000',
        '20260724140000',
        '20260809120000',
        '20260810120000'
    )
) AS c
WHERE c.n <> 9;

-- 4) No migration newer than the Custom-role change may be recorded: this script does not know what
--    such a migration changed, and removing only the nine versions below would leave the ledger
--    claiming a migration whose schema objects this script may have undone.
SELECT CONCAT(
    'REFUSED, nothing was changed: ', c.n, ' migration(s) newer than the Custom-role change are ',
    'recorded. Use the rollback script shipped with that newer version.'
) AS rollback_precondition_failure
FROM (
    SELECT COUNT(*) AS n
    FROM __diesel_schema_migrations
    WHERE version > '20260810120000'
) AS c
WHERE c.n <> 0;
INSERT INTO __vw_rollback_precondition (ok)
SELECT 1
FROM (
    SELECT COUNT(*) AS n
    FROM __diesel_schema_migrations
    WHERE version > '20260810120000'
) AS c
WHERE c.n <> 0;

-- 5) The upgrade records that this database's Custom-role history is accounted for. Without that
--    marker the database was migrated by an earlier revision of the change, whose migrations had
--    different effects.
SELECT CONCAT(
    'REFUSED, nothing was changed: __vw_custom_role_history_verified does not exist, so this ',
    'database was migrated by an earlier revision of the Custom-role change. Start Vaultwarden once ',
    'and follow the recovery it prints before rolling back.'
) AS rollback_precondition_failure
FROM (
    SELECT COUNT(*) AS n
    FROM information_schema.tables
    WHERE table_schema = DATABASE()
      AND table_name = '__vw_custom_role_history_verified'
) AS c
WHERE c.n <> 1;
INSERT INTO __vw_rollback_precondition (ok)
SELECT 1
FROM (
    SELECT COUNT(*) AS n
    FROM information_schema.tables
    WHERE table_schema = DATABASE()
      AND table_name = '__vw_custom_role_history_verified'
) AS c
WHERE c.n <> 1;

-- 6) Which memberships come back as legacy Manager has to be decided for *this* rollback. An empty
--    list is a valid answer and maps every Custom member to plain User.
SELECT CONCAT(
    'REFUSED, nothing was changed: __vw_rollback_manager_allowlist does not exist. See README.md, ',
    'section "Choosing which members come back as Manager".'
) AS rollback_precondition_failure
FROM (
    SELECT COUNT(*) AS n
    FROM information_schema.tables
    WHERE table_schema = DATABASE()
      AND table_name = '__vw_rollback_manager_allowlist'
) AS c
WHERE c.n <> 1;
INSERT INTO __vw_rollback_precondition (ok)
SELECT 1
FROM (
    SELECT COUNT(*) AS n
    FROM information_schema.tables
    WHERE table_schema = DATABASE()
      AND table_name = '__vw_rollback_manager_allowlist'
) AS c
WHERE c.n <> 1;

-- 7) ...and it has to have the shape the role mapping reads. Existence alone is not enough: a
--    hand-written or colliding table without a usable `users_organizations_uuid` column would pass
--    every check above and then fail on the first SELECT against it -- which happens *after* the
--    `ADD COLUMN` below has already committed implicitly, leaving a half-converted database.
--    Require exactly one non-nullable, uniquely indexed column of that name.
SELECT CONCAT(
    'REFUSED, nothing was changed: __vw_rollback_manager_allowlist must have exactly one column ',
    'named users_organizations_uuid, NOT NULL and uniquely indexed. Create it as documented in ',
    'README.md.'
) AS rollback_precondition_failure
FROM (
    SELECT
        (SELECT COUNT(*) FROM information_schema.columns
          WHERE table_schema = DATABASE() AND table_name = '__vw_rollback_manager_allowlist') AS cols,
        (SELECT COUNT(*) FROM information_schema.columns
          WHERE table_schema = DATABASE() AND table_name = '__vw_rollback_manager_allowlist'
            AND column_name = 'users_organizations_uuid' AND is_nullable = 'NO') AS usable,
        (SELECT COUNT(*) FROM information_schema.statistics
          WHERE table_schema = DATABASE() AND table_name = '__vw_rollback_manager_allowlist'
            AND column_name = 'users_organizations_uuid' AND non_unique = 0) AS uniq
) AS c
WHERE c.cols <> 1 OR c.usable <> 1 OR c.uniq < 1;
INSERT INTO __vw_rollback_precondition (ok)
SELECT 1
FROM (
    SELECT
        (SELECT COUNT(*) FROM information_schema.columns
          WHERE table_schema = DATABASE() AND table_name = '__vw_rollback_manager_allowlist') AS cols,
        (SELECT COUNT(*) FROM information_schema.columns
          WHERE table_schema = DATABASE() AND table_name = '__vw_rollback_manager_allowlist'
            AND column_name = 'users_organizations_uuid' AND is_nullable = 'NO') AS usable,
        (SELECT COUNT(*) FROM information_schema.statistics
          WHERE table_schema = DATABASE() AND table_name = '__vw_rollback_manager_allowlist'
            AND column_name = 'users_organizations_uuid' AND non_unique = 0) AS uniq
) AS c
WHERE c.cols <> 1 OR c.usable <> 1 OR c.uniq < 1;

-- `DROP TEMPORARY TABLE`, not `DROP TABLE`: the latter is one more statement that commits implicitly,
-- and it would happily drop a permanent table of the same name.
DROP TEMPORARY TABLE __vw_rollback_precondition;

-- ---------------------------------------------------------------------------------------------
-- From here on the database is known to be in the state this script converts *from*.
-- ---------------------------------------------------------------------------------------------

ALTER TABLE users_organizations ADD COLUMN access_all BOOLEAN NOT NULL DEFAULT FALSE;

-- Only a membership on the allowlist comes back as Manager. The legacy Manager role is not a subset
-- of what a Custom member holds -- it manages, and deletes, every collection reachable through
-- `users_collections.manage`, `collections_groups.manage` or `groups.access_all`, and reads member
-- and collection ACL details through `ManagerHeadersLoose`, none of which needs a permission flag in
-- the old schema -- so handing it out on anything less than a current, deliberate decision would
-- *grant* authority during a downgrade. `__vw_custom_role_legacy_manager` is not that decision: it
-- records who was a Manager before the first upgrade and is never updated afterwards, so a member
-- whose powers an owner has since reduced would get all of them back.
--
-- Everything else becomes a plain User and keeps its per-collection assignments.
--
-- `access_all` follows the same mapping the down migrations use: everyone who reached every
-- collection keeps that reach, and a Custom member has to hold all three collection permissions --
-- Edit-only must not silently turn into the legacy "manage all collections" authority, which in that
-- older schema also carried collection deletion. A member mapped to plain User never keeps it:
-- `User + access_all` is the one legacy state the upgrade refuses.
UPDATE users_organizations SET access_all = TRUE WHERE atype IN (0, 1);
UPDATE users_organizations
SET access_all = TRUE
WHERE atype = 4
  AND uuid IN (SELECT users_organizations_uuid FROM __vw_rollback_manager_allowlist)
  AND create_new_collections = TRUE
  AND edit_any_collection = TRUE
  AND delete_any_collection = TRUE;

-- The old server cannot load type 4.
UPDATE users_organizations SET atype = 3
WHERE atype = 4
  AND uuid IN (SELECT users_organizations_uuid FROM __vw_rollback_manager_allowlist);
UPDATE users_organizations SET atype = 2, access_all = FALSE WHERE atype = 4;

-- One ALTER, not nine. Every `ALTER TABLE` commits implicitly here, so nine statements mean eight
-- intermediate states an interruption could leave behind; one statement is the closest this backend
-- gets to all-or-nothing.
ALTER TABLE users_organizations
  DROP COLUMN manage_users,
  DROP COLUMN manage_groups,
  DROP COLUMN manage_policies,
  DROP COLUMN create_new_collections,
  DROP COLUMN edit_any_collection,
  DROP COLUMN delete_any_collection,
  DROP COLUMN access_event_logs,
  DROP COLUMN access_import_export,
  DROP COLUMN access_reports;

-- Bookkeeping tables this feature may have left behind. The legacy-Manager record goes too: a later
-- re-upgrade rebuilds it from the very `atype = 3` rows this script just restored, so the round trip
-- converges.
DROP TABLE IF EXISTS __vw_custom_role_same_run_0716;
DROP TABLE IF EXISTS __vw_allow_custom_role_downgrade;
DROP TABLE IF EXISTS __vw_allow_unresumable_mysql_downgrade;
DROP TABLE IF EXISTS __vw_ack_permanent_collection_authority;
DROP TABLE IF EXISTS __vw_rollback_manager_allowlist;
DROP TABLE IF EXISTS __vw_custom_role_legacy_manager;
DROP TABLE IF EXISTS __vw_custom_role_history_verified;

-- Finally forget the nine migrations, so the older binary does not see a ledger from the future
-- and a later upgrade applies them again from a clean state.
DELETE FROM __diesel_schema_migrations
WHERE version IN (
  '20260630120000',
  '20260715120000',
  '20260716120000',
  '20260723120000',
  '20260724120000',
  '20260724130000',
  '20260724140000',
  '20260809120000',
  '20260810120000'
);

-- Every statement above except this DELETE is DDL and was therefore committed implicitly the moment
-- it ran. The DELETE is plain DML: under `autocommit = 0` -- which `mysql --init-command`, a my.cnf
-- default, or a connection pool can all set -- it would be rolled back on disconnect, leaving the
-- schema rolled back but all nine migrations still marked as applied. A later upgrade would then
-- skip them and start new code against the old schema. Commit it explicitly; harmless when
-- autocommit is already on.
COMMIT;
