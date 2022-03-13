-- Create new devices table with primary keys on both uuid and user_uuid
CREATE TABLE devices_new (
	uuid	TEXT NOT NULL,
	created_at	DATETIME NOT NULL,
	updated_at	DATETIME NOT NULL,
	user_uuid	TEXT NOT NULL,
	name	TEXT NOT NULL,
	atype	INTEGER NOT NULL,
	push_token	TEXT,
	refresh_token	TEXT NOT NULL,
	twofactor_remember	TEXT,
	PRIMARY KEY(uuid, user_uuid),
	FOREIGN KEY(user_uuid) REFERENCES users(uuid)
);

-- Transfer current data to new table
INSERT INTO devices_new SELECT * FROM devices;

-- Drop the old table
DROP TABLE devices;

-- Rename the new table to the original name
ALTER TABLE devices_new RENAME TO devices;
