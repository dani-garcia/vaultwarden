CREATE TABLE organization_api_key (
	uuid			CHAR(36) NOT NULL,
	org_uuid		CHAR(36) NOT NULL REFERENCES organizations(uuid),
	atype			INTEGER NOT NULL,
	api_key			VARCHAR(255),
	revision_date	TIMESTAMP NOT NULL,
	PRIMARY KEY(uuid, org_uuid)
);

ALTER TABLE users ADD COLUMN external_id TEXT;
