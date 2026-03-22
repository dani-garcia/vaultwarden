-- groups_users and collections_groups were created with UNIQUE instead of
-- PRIMARY KEY. Diesel requires primary keys on all tables for schema
-- introspection. Drop the auto-named unique index and add the primary key.
ALTER TABLE groups_users
  DROP INDEX groups_uuid,
  ADD PRIMARY KEY (groups_uuid, users_organizations_uuid);

ALTER TABLE collections_groups
  DROP INDEX collections_uuid,
  ADD PRIMARY KEY (collections_uuid, groups_uuid);
