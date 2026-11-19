-- Removes the legacy "access all collections" flags and the legacy Manager role, like Bitwarden's
-- Organization_EnableCollectionEnhancements: whoever had access to all collections gets an explicit assignment to every
-- collection that exists now, and a Manager becomes a User who manages every collection they are assigned to.
-- Ref: https://github.com/bitwarden/server/blob/341acc9d3d8988cec8fe05debfa6d557cf5ab749/util/Migrator/DbScripts/2024-01-25_00_Organization_EnableCollectionEnhancements.sql

-- Everyone whose access changes syncs again
UPDATE users SET updated_at = UTC_TIMESTAMP()
WHERE uuid IN (SELECT user_uuid FROM users_organizations WHERE access_all OR atype = 3)
   OR uuid IN (
       SELECT uo.user_uuid FROM users_organizations uo
       JOIN groups_users gu ON gu.users_organizations_uuid = uo.uuid
       JOIN `groups` g ON g.uuid = gu.groups_uuid
       WHERE g.access_all
   );

-- Groups with access to all collections: read and write access to every collection. Bitwarden also cleared the manage
-- option here, which none of its organizations could have set yet. Vaultwarden has had it for a while, so it is kept.
UPDATE collections_groups SET read_only = FALSE, hide_passwords = FALSE
WHERE EXISTS (
    SELECT 1 FROM `groups` g JOIN collections c ON c.org_uuid = g.organizations_uuid
    WHERE g.access_all AND g.uuid = collections_groups.groups_uuid AND c.uuid = collections_groups.collections_uuid
);
INSERT INTO collections_groups (collections_uuid, groups_uuid, read_only, hide_passwords, manage)
SELECT c.uuid, g.uuid, FALSE, FALSE, FALSE
FROM `groups` g JOIN collections c ON c.org_uuid = g.organizations_uuid
WHERE g.access_all
  AND NOT EXISTS (SELECT 1 FROM collections_groups cg WHERE cg.collections_uuid = c.uuid AND cg.groups_uuid = g.uuid);
UPDATE `groups` SET revision_date = UTC_TIMESTAMP() WHERE access_all;

-- Members with access to all collections: the same for them
UPDATE users_collections SET read_only = FALSE, hide_passwords = FALSE
WHERE EXISTS (
    SELECT 1 FROM users_organizations uo JOIN collections c ON c.org_uuid = uo.org_uuid
    WHERE uo.access_all AND uo.user_uuid = users_collections.user_uuid AND c.uuid = users_collections.collection_uuid
);
INSERT INTO users_collections (user_uuid, collection_uuid, read_only, hide_passwords, manage)
SELECT uo.user_uuid, c.uuid, FALSE, FALSE, FALSE
FROM users_organizations uo JOIN collections c ON c.org_uuid = uo.org_uuid
WHERE uo.access_all
  AND NOT EXISTS (SELECT 1 FROM users_collections uc WHERE uc.user_uuid = uo.user_uuid AND uc.collection_uuid = c.uuid);

-- Managers, as in Bitwarden: every assignment of a Manager becomes read and write access with the manage option, and the
-- collections of their groups get such an assignment of their own, since the groups themselves don't get the option.
UPDATE users_collections SET read_only = FALSE, hide_passwords = FALSE, manage = TRUE
WHERE EXISTS (
    SELECT 1 FROM users_organizations uo JOIN collections c ON c.org_uuid = uo.org_uuid
    WHERE uo.atype = 3 AND uo.user_uuid = users_collections.user_uuid AND c.uuid = users_collections.collection_uuid
);
INSERT INTO users_collections (user_uuid, collection_uuid, read_only, hide_passwords, manage)
SELECT DISTINCT uo.user_uuid, cg.collections_uuid, FALSE, FALSE, TRUE
FROM users_organizations uo
JOIN groups_users gu ON gu.users_organizations_uuid = uo.uuid
JOIN `groups` g ON g.uuid = gu.groups_uuid AND g.organizations_uuid = uo.org_uuid
JOIN collections_groups cg ON cg.groups_uuid = g.uuid
WHERE uo.atype = 3
  AND NOT EXISTS (
      SELECT 1 FROM users_collections uc WHERE uc.user_uuid = uo.user_uuid AND uc.collection_uuid = cg.collections_uuid
  );
UPDATE users_organizations SET atype = 2 WHERE atype = 3;

ALTER TABLE `groups` DROP COLUMN access_all;
ALTER TABLE users_organizations DROP COLUMN access_all;
