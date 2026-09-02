-- archives.cipher_uuid is left out: it is declared as an explicit FOREIGN KEY,
-- so InnoDB already maintains an index for it. Every other table below uses
-- inline REFERENCES, which MySQL parses and ignores, so no index exists.
CREATE INDEX idx_ciphers_user_uuid ON ciphers (user_uuid);
CREATE INDEX idx_ciphers_organization_uuid ON ciphers (organization_uuid);
CREATE INDEX idx_attachments_cipher_uuid ON attachments (cipher_uuid);
CREATE INDEX idx_folders_user_uuid ON folders (user_uuid);
CREATE INDEX idx_folders_ciphers_folder_uuid ON folders_ciphers (folder_uuid);
CREATE INDEX idx_ciphers_collections_collection_uuid ON ciphers_collections (collection_uuid);
CREATE INDEX idx_favorites_cipher_uuid ON favorites (cipher_uuid);
CREATE INDEX idx_devices_user_uuid ON devices (user_uuid);
CREATE INDEX idx_collections_org_uuid ON collections (org_uuid);
CREATE INDEX idx_users_collections_collection_uuid ON users_collections (collection_uuid);
CREATE INDEX idx_users_organizations_org_uuid ON users_organizations (org_uuid);
CREATE INDEX idx_groups_organizations_uuid ON `groups` (organizations_uuid);
CREATE INDEX idx_groups_users_users_organizations_uuid ON groups_users (users_organizations_uuid);
CREATE INDEX idx_collections_groups_groups_uuid ON collections_groups (groups_uuid);
CREATE INDEX idx_event_org_uuid_event_date ON event (org_uuid, event_date);
CREATE INDEX idx_event_cipher_uuid_event_date ON event (cipher_uuid, event_date);
CREATE INDEX idx_event_event_date ON event (event_date);
