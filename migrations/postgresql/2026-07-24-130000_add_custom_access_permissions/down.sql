-- Lossy revert: this removes the three Custom access permissions, which the legacy schema cannot
-- represent at all. The revert therefore
-- requires the same acknowledgement as 2026-07-24-140000/down.sql -- which only announces the loss,
-- it does not authorize it. Create the marker table while every Vaultwarden instance is stopped:
--
--     CREATE TABLE __vw_allow_custom_role_downgrade (acknowledged INTEGER NOT NULL PRIMARY KEY);
CREATE TEMPORARY TABLE __vw_custom_role_downgrade_guard (
    blocked INTEGER NOT NULL PRIMARY KEY
);
INSERT INTO __vw_custom_role_downgrade_guard (blocked) VALUES (1);
-- The duplicate key aborts the revert. It is only inserted while the acknowledgement is absent.
INSERT INTO __vw_custom_role_downgrade_guard (blocked)
SELECT 1
WHERE to_regclass('__vw_allow_custom_role_downgrade') IS NULL;
DROP TABLE __vw_custom_role_downgrade_guard;

ALTER TABLE users_organizations DROP COLUMN access_event_logs;
ALTER TABLE users_organizations DROP COLUMN access_import_export;
ALTER TABLE users_organizations DROP COLUMN access_reports;
