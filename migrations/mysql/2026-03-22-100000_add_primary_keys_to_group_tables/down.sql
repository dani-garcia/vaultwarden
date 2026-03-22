ALTER TABLE groups_users
  DROP PRIMARY KEY,
  ADD UNIQUE (groups_uuid, users_organizations_uuid);

ALTER TABLE collections_groups
  DROP PRIMARY KEY,
  ADD UNIQUE (collections_uuid, groups_uuid);
