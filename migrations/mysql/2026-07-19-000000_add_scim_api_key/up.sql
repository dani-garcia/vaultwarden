-- org_uuid is VARCHAR(40) to match organizations.uuid exactly; the FOREIGN KEY
-- must be a table-level clause because MySQL silently ignores inline
-- column-level REFERENCES.
CREATE TABLE scim_api_key (
	uuid            CHAR(36) NOT NULL PRIMARY KEY,
	org_uuid        VARCHAR(40) NOT NULL UNIQUE,
	key_hash        VARCHAR(255) NOT NULL,
	enabled         BOOLEAN NOT NULL DEFAULT TRUE,
	created_at      DATETIME NOT NULL,
	revision_date   DATETIME NOT NULL,
	FOREIGN KEY(org_uuid) REFERENCES organizations(uuid)
);
