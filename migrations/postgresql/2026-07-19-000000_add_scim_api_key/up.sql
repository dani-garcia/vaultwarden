CREATE TABLE scim_api_key (
	uuid            CHAR(36) NOT NULL PRIMARY KEY,
	org_uuid        CHAR(36) NOT NULL UNIQUE REFERENCES organizations(uuid),
	key_hash        TEXT NOT NULL,
	enabled         BOOLEAN NOT NULL DEFAULT true,
	created_at      TIMESTAMP NOT NULL,
	revision_date   TIMESTAMP NOT NULL
);
