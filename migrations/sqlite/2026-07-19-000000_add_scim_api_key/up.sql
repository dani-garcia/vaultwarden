CREATE TABLE scim_api_key (
	uuid            TEXT NOT NULL PRIMARY KEY,
	org_uuid        TEXT NOT NULL UNIQUE,
	key_hash        TEXT NOT NULL,
	enabled         BOOLEAN NOT NULL DEFAULT 1,
	created_at      DATETIME NOT NULL,
	revision_date   DATETIME NOT NULL,
	FOREIGN KEY(org_uuid) REFERENCES organizations(uuid)
);
