CREATE TABLE scim_api_key (
	uuid            CHAR(36) NOT NULL PRIMARY KEY,
	org_uuid        CHAR(36) NOT NULL UNIQUE REFERENCES organizations(uuid),
	key_hash        VARCHAR(255) NOT NULL,
	enabled         BOOLEAN NOT NULL DEFAULT TRUE,
	created_at      DATETIME NOT NULL,
	revision_date   DATETIME NOT NULL
);
