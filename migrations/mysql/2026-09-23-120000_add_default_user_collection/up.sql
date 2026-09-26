-- Older releases ignore both columns after a downgrade: a My Items collection becomes a regular one there, which
-- Owners, Admins and members with access to all collections see with its items.
ALTER TABLE collections ADD COLUMN default_user_uuid CHAR(36);
ALTER TABLE collections ADD COLUMN default_user_collection_email TEXT;
-- A member has at most one My Items collection per organization. NULL (a shared collection) never conflicts.
CREATE UNIQUE INDEX collections_default_user_uuid ON collections (org_uuid, default_user_uuid);
