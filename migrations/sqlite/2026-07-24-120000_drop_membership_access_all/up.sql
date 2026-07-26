-- The membership `access_all` flag was Vaultwarden's pre-permissions patch for "this member can
-- reach every collection". It is now fully represented by the role model: Owners/Admins hold it
-- implicitly, and a Custom member holds it via `edit_any_collection`. Drop the redundant column.
-- This only concerns users_organizations; groups.access_all is a separate, still-supported feature.
ALTER TABLE users_organizations DROP COLUMN access_all;
