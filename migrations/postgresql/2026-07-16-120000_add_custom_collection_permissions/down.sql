-- Lossy revert: this removes the three independent Custom collection permissions, which the legacy
-- role/access_all schema cannot represent -- it only knows all three together. The revert therefore
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

-- The previous schema exposes access_all as the three collection permissions together. Avoid
-- turning Edit-only memberships into Create/Edit/Delete grants when rolling back.
UPDATE users_organizations
SET access_all = create_new_collections AND edit_any_collection AND delete_any_collection
WHERE atype = 4;

ALTER TABLE users_organizations DROP COLUMN create_new_collections;
ALTER TABLE users_organizations DROP COLUMN edit_any_collection;
ALTER TABLE users_organizations DROP COLUMN delete_any_collection;
