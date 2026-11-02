-- Creating the index above lets InnoDB drop the index it had made for the `organization_uuid`
-- foreign key, and it then refuses to drop the last index that constraint is left with. Put a
-- single column index back first, unless an earlier revert already left one behind.
SET @restore_fk_index := IF(
    (SELECT COUNT(*) FROM information_schema.STATISTICS
     WHERE table_schema = DATABASE() AND table_name = 'auth_requests' AND index_name = 'organization_uuid') = 0,
    'CREATE INDEX organization_uuid ON auth_requests (organization_uuid)',
    'DO 0'
);
PREPARE restore_fk_index FROM @restore_fk_index;
EXECUTE restore_fk_index;
DEALLOCATE PREPARE restore_fk_index;
DROP INDEX auth_requests_creation_date ON auth_requests;
DROP INDEX auth_requests_organization_type ON auth_requests;

ALTER TABLE auth_requests DROP COLUMN atype;

ALTER TABLE devices DROP COLUMN encrypted_private_key;
ALTER TABLE devices DROP COLUMN encrypted_public_key;
ALTER TABLE devices DROP COLUMN encrypted_user_key;
