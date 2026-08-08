-- Nine independent Custom-role permissions cannot be represented losslessly by the legacy
-- role/access_all schema, so a revert is blocked here -- before any older down migration removes
-- permission data.
--
-- It is an explicit, acknowledged decision though, not a dead end. Create the marker table below
-- while every Vaultwarden instance is stopped and this guard lets the revert through:
--
--     CREATE TABLE __vw_allow_custom_role_downgrade (acknowledged INTEGER NOT NULL PRIMARY KEY);
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
    WHERE table_schema = DATABASE() AND table_name = '__vw_allow_custom_role_downgrade'
);
DROP TABLE __vw_custom_role_downgrade_guard;

-- Consume the acknowledgement: it authorized *this* revert, not every future one. After a
-- re-upgrade the next revert has to be acknowledged again.
DROP TABLE IF EXISTS __vw_allow_custom_role_downgrade;
