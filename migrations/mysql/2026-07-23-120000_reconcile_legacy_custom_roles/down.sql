-- This is an idempotent data repair. Reverting it must not remove permissions or recreate the
-- invalid persisted Manager type; the older-schema migration performs its own safe conversion.
SELECT 1;
