CREATE TABLE auth_requests (
	uuid            CHAR(36) NOT NULL PRIMARY KEY,
	user_uuid	    CHAR(36) NOT NULL,
	organization_uuid           CHAR(36),
	request_device_identifier         CHAR(36) NOT NULL,
	device_type         INTEGER NOT NULL,
	request_ip         TEXT NOT NULL,
	response_device_id         CHAR(36),
	access_code         TEXT NOT NULL,
	public_key         TEXT NOT NULL,
	enc_key         TEXT NOT NULL,
	master_password_hash         TEXT NOT NULL,
	approved         BOOLEAN,
	creation_date         TIMESTAMP NOT NULL,
	response_date         TIMESTAMP,
	authentication_date         TIMESTAMP,
	FOREIGN KEY(user_uuid) REFERENCES users(uuid),
	FOREIGN KEY(organization_uuid) REFERENCES organizations(uuid)
);