-- Convert Custom members back to Manager, the representation older server versions
-- expect (they masquerade Manager as Custom in API responses and cannot load type 4).
UPDATE users_organizations SET atype = 3 WHERE atype = 4;
ALTER TABLE users_organizations DROP COLUMN manage_users;
ALTER TABLE users_organizations DROP COLUMN manage_groups;
ALTER TABLE users_organizations DROP COLUMN manage_policies;
