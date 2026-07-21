ALTER TABLE organizations ADD COLUMN allow_admin_access_to_all_collection_items BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE organizations ADD COLUMN limit_collection_creation BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE organizations ADD COLUMN limit_collection_deletion BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE organizations ADD COLUMN limit_item_deletion BOOLEAN NOT NULL DEFAULT FALSE;