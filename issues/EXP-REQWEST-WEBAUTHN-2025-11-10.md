# Experiment: reqwest(native-tls) & webauthn-rs bump (2025-11-10)

Summary
-------
Two non-destructive experiments were executed in a copied workspace to evaluate remediation paths for the top license clusters.

1) reqwest/native-tls experiment
- Script: `docker/audit/exp/reqwest_native_exp.sh`
- Action: attempted to prefer `native-tls` for `reqwest` by editing `Cargo.toml`, running `cargo update -p reqwest`, and running `cargo-deny` (licenses) in a workspace copy.
- Result: `cargo-deny` reduced license errors to a single error: `ar_archive_writer v0.2.0` (license: Apache-2.0 WITH LLVM-exception) via `lettre` -> `psm` -> `stacker` -> `chumsky` -> `vaultwarden` path. The `webpki-roots` (CDLA-Permissive-2.0) failure was removed in this experiment.
- Artifacts: `docker/audit/output/deny_reqwest_native.err` (diagnostic), `docker/audit/output/deny_reqwest_native.json` (may be empty), `docker/audit/output/req_exp.done` (marker).

2) webauthn-rs bump experiment
- Script: `docker/audit/exp/patch_and_run.sh`
- Action: in a workspace copy, attempted to bump `webauthn-rs` to `0.6` and ran `cargo update -p webauthn-rs` and `cargo-deny` (licenses).
- Result: MPL-2.0 failures related to the `webauthn-rs` family were removed by the non-destructive bump attempt (in the copied workspace experiment). The remaining single license rejection (same as above) persisted.
- Artifacts: `docker/audit/output/deny_licenses.err`, `docker/audit/output/deny_licenses.json` (may be empty), `docker/audit/output/exp.done`.

Conclusion & recommended next step
--------------------------------
- Both experiments significantly reduced the license noise: from the previously reported set down to one remaining rejection: `ar_archive_writer v0.2.0` (Apache-2.0 WITH LLVM-exception).
- Recommended immediate actions:
  1. Decide whether to temporarily allow `Apache-2.0 WITH LLVM-exception` in `deny.toml` (timeboxed) to unblock CI, OR
  2. Investigate the `lettre`/`psm` chain to find alternative crates or versions that avoid `ar_archive_writer`.
- If you approve, I can open a follow-up branch that applies the minimal change (either temporary allowlist addition or a patch bump) and run CI to verify `cargo-deny` cleanly passes.

Notes
-----
- All changes in these experiments were done in copied workspaces inside the audit container and did not modify the main branch's `Cargo.toml` or lockfile.
- Full experiment artifacts are saved under `docker/audit/output/` in the repository workspace.
