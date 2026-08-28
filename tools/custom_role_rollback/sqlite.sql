-- Roll a SQLite database back to the schema the Vaultwarden version *before* the Custom-role
-- change expects, so that older binary starts again. Read README.md in this directory first --
-- it lists exactly what is lost and how to run this safely.
--
-- `ALTER TABLE ... DROP COLUMN` is avoided on purpose -- it needs SQLite 3.35, and this script has to
-- work on the same older system SQLite the forward migrations support. The rebuild recreates
-- `access_all` and drops all nine permission columns in one step.

-- Stop at the first error. Without this the sqlite3 shell keeps going after a failed statement,
-- and a second run -- where the SELECT below can no longer see the permission columns -- would
-- still reach DROP TABLE and commit an empty users_organizations. `.bail on` is a shell command;
-- a runner that is not the sqlite3 CLI has to abort on the first error and roll back by itself.
.bail on

PRAGMA foreign_keys = OFF;

BEGIN;

-- Refuse to start at all unless the database is in the exact state this script converts *from*. A
-- repeat run, or a half-finished upgrade, would otherwise only fail somewhere in the middle. Each
-- check is read-only, and the name of the failing CHECK constraint *is* the error message.
CREATE TEMPORARY TABLE __vw_rollback_precondition (
    ok INTEGER NOT NULL CONSTRAINT
        refused_membership_access_all_still_exists_so_this_database_was_not_upgraded_or_was_already_rolled_back
        CHECK (ok = 1)
);
INSERT INTO __vw_rollback_precondition (ok)
SELECT CASE
    WHEN NOT EXISTS (SELECT 1 FROM pragma_table_xinfo('users_organizations') WHERE name = 'access_all')
    THEN 1
    ELSE 0
END;
DROP TABLE __vw_rollback_precondition;

CREATE TEMPORARY TABLE __vw_rollback_precondition_columns (
    ok INTEGER NOT NULL CONSTRAINT
        refused_all_nine_custom_role_permission_columns_must_exist_restore_the_pre_upgrade_backup
        CHECK (ok = 9)
);
INSERT INTO __vw_rollback_precondition_columns (ok)
SELECT COUNT(*)
FROM pragma_table_xinfo('users_organizations')
WHERE name IN (
    'manage_users', 'manage_groups', 'manage_policies',
    'create_new_collections', 'edit_any_collection', 'delete_any_collection',
    'access_event_logs', 'access_import_export', 'access_reports'
);
DROP TABLE __vw_rollback_precondition_columns;

-- The rebuild below copies a fixed column list, so anything this script does not know about would be
-- silently dropped together with its data. Require the table to hold *exactly* the eighteen columns
-- the Custom-role upgrade leaves behind -- not merely to contain them. A newer migration that added a
-- column, or a local modification, therefore refuses here instead of being destroyed at COMMIT.
--
-- `table_xinfo`, not `table_info`: the latter omits generated columns entirely, so a STORED or
-- VIRTUAL column would pass the count unseen and then be lost in the rebuild.
CREATE TEMPORARY TABLE __vw_rollback_precondition_exact_columns (
    ok INTEGER NOT NULL CONSTRAINT
        refused_users_organizations_has_unexpected_columns_this_script_is_older_than_the_database
        CHECK (ok = 1)
);
INSERT INTO __vw_rollback_precondition_exact_columns (ok)
SELECT CASE WHEN total = 18 AND known = 18 THEN 1 ELSE 0 END
FROM (
    SELECT
        COUNT(*) AS total,
        SUM(CASE WHEN name IN (
            'uuid', 'user_uuid', 'org_uuid', 'akey', 'status', 'atype',
            'reset_password_key', 'external_id', 'invited_by_email',
            'manage_users', 'manage_groups', 'manage_policies',
            'create_new_collections', 'edit_any_collection', 'delete_any_collection',
            'access_event_logs', 'access_import_export', 'access_reports'
        ) THEN 1 ELSE 0 END) AS known
    FROM pragma_table_xinfo('users_organizations')
);
DROP TABLE __vw_rollback_precondition_exact_columns;

-- Same reasoning for everything else attached to the table: `DROP TABLE` takes its indexes and
-- triggers with it, and the rebuild recreates only the PRIMARY KEY and the UNIQUE pair.
--
-- Counting `index_list` rather than `sqlite_master` on purpose. An index that SQLite created for a
-- UNIQUE constraint has no SQL text, so `sqlite_master.sql IS NOT NULL` cannot see it -- an extra
-- `UNIQUE(external_id)` would pass unnoticed and be gone afterwards. `index_list` reports every
-- index, so the upgraded table's own two are the exact expected count.
CREATE TEMPORARY TABLE __vw_rollback_precondition_objects (
    ok INTEGER NOT NULL CONSTRAINT
        refused_users_organizations_has_extra_indexes_constraints_or_triggers_the_rebuild_would_destroy
        CHECK (ok = 1)
);
INSERT INTO __vw_rollback_precondition_objects (ok)
SELECT CASE WHEN indexes = 2 AND triggers = 0 THEN 1 ELSE 0 END
FROM (
    SELECT
        (SELECT COUNT(*) FROM pragma_index_list('users_organizations')) AS indexes,
        (SELECT COUNT(*) FROM sqlite_master
          WHERE tbl_name = 'users_organizations' AND type = 'trigger') AS triggers
);
DROP TABLE __vw_rollback_precondition_objects;

CREATE TEMPORARY TABLE __vw_rollback_precondition_ledger (
    ok INTEGER NOT NULL CONSTRAINT
        refused_the_custom_role_migration_must_be_recorded_schema_and_ledger_disagree
        CHECK (ok = 1)
);
INSERT INTO __vw_rollback_precondition_ledger (ok)
SELECT COUNT(*)
FROM __diesel_schema_migrations
WHERE version IN (
  '20260630120000'
);
DROP TABLE __vw_rollback_precondition_ledger;

-- A migration newer than the Custom-role one has run, so this script cannot know what it changed
-- or whether the rebuild below would undo it. Removing only that one version would also leave the
-- ledger claiming a migration whose schema objects are gone.
CREATE TEMPORARY TABLE __vw_rollback_precondition_future_ledger (
    ok INTEGER NOT NULL CONSTRAINT
        refused_migrations_newer_than_the_custom_role_change_are_recorded_use_a_newer_rollback_script
        CHECK (ok = 0)
);
INSERT INTO __vw_rollback_precondition_future_ledger (ok)
SELECT COUNT(*) FROM __diesel_schema_migrations WHERE version > '20260630120000';
DROP TABLE __vw_rollback_precondition_future_ledger;

-- Which memberships come back as Manager has to be decided *for this rollback*. See README.md; an
-- empty list is a valid answer and maps every Custom member to plain User.
CREATE TEMPORARY TABLE __vw_rollback_precondition_allowlist (
    ok INTEGER NOT NULL CONSTRAINT
        refused_create_vw_rollback_manager_allowlist_first_see_readme_role_mapping
        CHECK (ok = 1)
);
INSERT INTO __vw_rollback_precondition_allowlist (ok)
SELECT COUNT(*)
FROM sqlite_master
WHERE type = 'table' AND name = '__vw_rollback_manager_allowlist';
DROP TABLE __vw_rollback_precondition_allowlist;

CREATE TABLE users_organizations_rollback (
  uuid       TEXT    NOT NULL PRIMARY KEY,
  user_uuid  TEXT    NOT NULL REFERENCES users (uuid),
  org_uuid   TEXT    NOT NULL REFERENCES organizations (uuid),
  access_all BOOLEAN NOT NULL DEFAULT 0,
  akey       TEXT    NOT NULL,
  status     INTEGER NOT NULL,
  atype      INTEGER NOT NULL,
  reset_password_key TEXT,
  external_id TEXT,
  invited_by_email TEXT DEFAULT NULL,

  UNIQUE (user_uuid, org_uuid)
);

-- Roles and the legacy flag are recomputed together, because in the old schema they are not
-- independent.
--
-- Only a membership on the allowlist comes back as Manager; everything else becomes a plain User and
-- keeps every grant `users_collections` and `collections_groups` carry. The legacy role is not a
-- subset of what a Custom member holds, so handing it out on less than a current, deliberate decision
-- would *grant* authority during a downgrade -- and historical provenance is not that decision. See
-- README.md.
--
-- `access_all` follows the mapping the down migrations use: a Custom member has to hold all three
-- collection permissions, because in the old schema the bit also carried collection deletion. A
-- member mapped to plain User never keeps it: `User + access_all` is the one state the upgrade
-- refuses, so leaving it set would strand this database.
INSERT INTO users_organizations_rollback (
  uuid, user_uuid, org_uuid, access_all, akey, status, atype,
  reset_password_key, external_id, invited_by_email
)
SELECT
  uo.uuid, uo.user_uuid, uo.org_uuid,
  CASE
    WHEN uo.atype IN (0, 1) THEN 1
    WHEN uo.atype = 4
         AND uo.uuid IN (SELECT users_organizations_uuid FROM __vw_rollback_manager_allowlist)
         AND uo.create_new_collections = 1
         AND uo.edit_any_collection = 1
         AND uo.delete_any_collection = 1 THEN 1
    ELSE 0
  END,
  uo.akey, uo.status,
  -- The old server cannot load type 4.
  CASE
    WHEN uo.atype = 4
         AND uo.uuid IN (SELECT users_organizations_uuid FROM __vw_rollback_manager_allowlist)
    THEN 3
    WHEN uo.atype = 4 THEN 2
    ELSE uo.atype
  END,
  uo.reset_password_key, uo.external_id, uo.invited_by_email
FROM users_organizations AS uo;

DROP TABLE users_organizations;

ALTER TABLE users_organizations_rollback RENAME TO users_organizations;

-- The two decisions this rollback required. A later re-upgrade needs neither: it reads the restored
-- `atype = 3` rows directly and converts them deterministically.
DROP TABLE IF EXISTS __vw_allow_custom_role_downgrade;
DROP TABLE IF EXISTS __vw_rollback_manager_allowlist;

-- Finally forget the migration, so the older binary does not see a ledger from the future and a
-- later upgrade applies it again from a clean state.
DELETE FROM __diesel_schema_migrations
WHERE version IN (
  '20260630120000'
);

COMMIT;
