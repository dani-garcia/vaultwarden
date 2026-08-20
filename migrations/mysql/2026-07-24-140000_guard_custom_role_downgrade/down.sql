-- Downgrade guard. Reverting this migration destroys Custom-role permission data that the legacy
-- role/access_all schema cannot represent, so it only runs with an explicit acknowledgement. Create
-- the marker table below while every Vaultwarden instance is stopped:
--
--     CREATE TABLE __vw_allow_custom_role_downgrade (acknowledged INTEGER NOT NULL PRIMARY KEY);
--
-- The acknowledgement stays valid for the rest of the revert chain and is consumed by the oldest
-- lossy migration (2026-06-30-120000), so one decision covers one downgrade -- and a re-upgrade
-- clears it again (2026-07-24-140000/up.sql), so consent is never inherited.
--
-- Operators who only need the old server version to start again do not need Diesel at all --
-- tools/custom_role_rollback/ has a self-contained script per backend.
CREATE TEMPORARY TABLE __vw_custom_role_downgrade_guard (
    blocked INTEGER NOT NULL PRIMARY KEY
);
INSERT INTO __vw_custom_role_downgrade_guard (blocked) VALUES (1);
-- The duplicate key aborts the revert. It is only inserted while the acknowledgement is absent.
INSERT INTO __vw_custom_role_downgrade_guard (blocked)
SELECT 1 FROM DUAL
WHERE NOT EXISTS (
    SELECT 1 FROM information_schema.tables
    WHERE table_schema = DATABASE() AND table_name = '__vw_allow_custom_role_downgrade');
-- `DROP TEMPORARY TABLE`, not `DROP TABLE`: the latter is one more statement that commits
-- implicitly on MySQL/MariaDB, and it would happily drop a permanent table of the same name.
DROP TEMPORARY TABLE __vw_custom_role_downgrade_guard;

-- Second, MySQL/MariaDB-only guard: this revert chain cannot be resumed here.
--
-- Every `ALTER TABLE` in it commits on its own, while Diesel deletes the ledger row in a separate
-- statement afterwards. A crash in between leaves the columns gone and the migration still recorded
-- as applied, and re-running it fails forever with `Unknown column` (1091) -- the startup preflight
-- then refuses the database, correctly, and the only way out is the backup. Making it resumable
-- needs conditional DDL, i.e. a stored procedure built before the checks have run; the standalone
-- script in tools/custom_role_rollback/mysql.sql does the whole downgrade in one audited pass
-- instead, and is what operators should use.
--
-- So this is supported for development checkouts only, and it says so. Acknowledge separately from
-- the data-loss marker above -- that one is about what a downgrade discards, this one is about what
-- an interrupted downgrade cannot repair:
--
--     CREATE TABLE __vw_allow_unresumable_mysql_downgrade (acknowledged INTEGER NOT NULL PRIMARY KEY);
--
-- The duplicate key aborts the revert. It is only inserted while the acknowledgement is absent.
CREATE TEMPORARY TABLE __vw_mysql_resume_guard (
    blocked INTEGER NOT NULL PRIMARY KEY
);
INSERT INTO __vw_mysql_resume_guard (blocked) VALUES (1);
INSERT INTO __vw_mysql_resume_guard (blocked)
SELECT 1 FROM DUAL
WHERE NOT EXISTS (
    SELECT 1 FROM information_schema.tables
    WHERE table_schema = DATABASE() AND table_name = '__vw_allow_unresumable_mysql_downgrade'
);
DROP TEMPORARY TABLE __vw_mysql_resume_guard;

-- Nothing else to undo: the acknowledgement deliberately survives this step. It has to still be here
-- when the next revert removes the first permission column, which is what this guard exists to
-- announce -- checking and dropping it in the same step would leave every following lossy revert
-- unguarded.
SELECT 1;
