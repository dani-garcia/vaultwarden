-- Recreate the column and repopulate it from the role/permission model that replaced it, restoring
-- the invariant the immediately preceding schema relies on: access_all == access to every collection.
-- That is exactly Owners/Admins, plus Custom members holding `edit_any_collection`.
--
-- NOTE: this only holds for reverting *this* migration. Reverting further down the chain,
-- 2026-07-16 deliberately recomputes access_all as (create AND edit AND delete) for Custom members,
-- because in that older schema access_all also meant the legacy Manager "Manage all collections"
-- authority -- so a member who only held `edit_any_collection` comes out as a Manager *without*
-- access_all rather than silently gaining collection deletion. That is intentional and fail-closed;
-- the full rollback is blocked by 2026-07-24-140000/down.sql anyway.
ALTER TABLE users_organizations ADD COLUMN access_all BOOLEAN NOT NULL DEFAULT FALSE;
UPDATE users_organizations SET access_all = TRUE WHERE atype IN (0, 1);
UPDATE users_organizations SET access_all = TRUE WHERE atype = 4 AND edit_any_collection = TRUE;
