-- Nine independent Custom-role permissions cannot be represented losslessly by the legacy
-- role/access_all schema. Always stop before any older down migration removes permission data.
CREATE TEMPORARY TABLE __vw_custom_role_downgrade_guard (
    blocked INTEGER NOT NULL PRIMARY KEY
);
INSERT INTO __vw_custom_role_downgrade_guard (blocked) VALUES (1);
INSERT INTO __vw_custom_role_downgrade_guard (blocked) VALUES (1);
