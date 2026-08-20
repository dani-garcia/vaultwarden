-- This is an idempotent data repair, and it creates no rows: reverting it must not remove permissions
-- or recreate the invalid persisted Manager type. The older-schema migration performs its own safe
-- conversion.
SELECT 1;
