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
SELECT 1
WHERE to_regclass('__vw_allow_custom_role_downgrade') IS NULL;
DROP TABLE __vw_custom_role_downgrade_guard;

-- Nothing else to undo: the acknowledgement deliberately survives this step. It has to still be here
-- when the next revert removes the first permission column, which is what this guard exists to
-- announce -- checking and dropping it in the same step would leave every following lossy revert
-- unguarded.
SELECT 1;
