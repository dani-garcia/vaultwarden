-- Nothing to undo: this migration only re-applies permissions that 2026-07-23-120000 also sets, and
-- the original values are not recoverable. The permission columns themselves are removed further down
-- the chain by 2026-07-16-120000/down.sql, which is guarded.
SELECT 1;