-- Store permission bits as a signed integer to match Rust/Diesel i32.
ALTER TABLE users_organizations ADD COLUMN permissions INTEGER DEFAULT NULL;
