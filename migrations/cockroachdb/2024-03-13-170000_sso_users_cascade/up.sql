ALTER TABLE sso_users
  DROP CONSTRAINT "sso_users_user_uuid_fkey",
  ADD CONSTRAINT "sso_users_user_uuid_fkey" FOREIGN KEY(user_uuid) REFERENCES users(uuid) ON UPDATE CASCADE ON DELETE CASCADE;
