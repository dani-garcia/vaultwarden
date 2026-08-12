-- Forward migration marker: its down migration intentionally blocks an automatic lossy downgrade
-- before any granular permission column is removed.
--
-- It also cleans up after 2026-07-15: the same-run bookkeeping table has served its purpose by now
-- (2026-07-23 consumed the marker), so it is not left behind in every database. A single DDL
-- statement is safe even on MySQL, where DDL commits implicitly -- re-running it is a no-op.
DROP TABLE IF EXISTS __vw_custom_role_same_run_0716;

-- Also clear a downgrade acknowledgement left over from an earlier revert, so consent is
-- never inherited across an upgrade. Both of them: this backend's revert chain needs a second one,
-- acknowledging that it cannot be resumed after a crash between a committed ALTER and the ledger.
DROP TABLE IF EXISTS __vw_allow_custom_role_downgrade;
DROP TABLE IF EXISTS __vw_allow_unresumable_mysql_downgrade;
