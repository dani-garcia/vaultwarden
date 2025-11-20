# License triage summary — 2025-11-12

This short summary aggregates the highest-impact license failures reported by the audit tooling and gives a quick feasibility recommendation for policy and remediation.

Source
------
- Generated from `docker/audit/output/license_triage_2025-11-09.csv` and follow-up experiment artifacts in `docker/audit/output/`.

Top offenders
-------------
1. webauthn-rs family — MPL-2.0 (direct)
   - Crates: `webauthn-rs v0.5.3`, `webauthn-rs-core v0.5.3`, `webauthn-rs-proto v0.5.3`, `webauthn-attestation-ca v0.5.3`, `base64urlsafedata v0.5.3`
   - Path: direct dependency from `vaultwarden` to `webauthn-rs`.
   - Impact: high (direct dependency). Remediation: upgrade to permissive version, replace crate, or vendor functionality.

2. webpki-roots — CDLA-Permissive-2.0 (transitive)
   - Crate: `webpki-roots v1.0.3` via `hyper-rustls -> reqwest -> openidconnect`.
   - Impact: medium. Remediation: prefer `native-tls` or upgrade TLS/reqwest stack to versions that avoid `webpki-roots`.

3. ar_archive_writer — Apache-2.0 WITH LLVM-exception (transitive)
   - Crate: `ar_archive_writer v0.2.0` via `lettre -> psm -> stacker -> chumsky`.
   - Impact: small (single remaining blocking error after experiments). Remediation: bump `lettre`/`psm` versions (experiment shows this removes the error) or timebox an allowlist entry while a bump PR is prepared.

Feasibility and immediate policy guidance
---------------------------------------
- The webauthn-rs cluster requires direct attention (upgrade/replace); temporarily allowing MPL-2.0 is defensible but should be strictly timeboxed and tracked.
- The webpki-roots issue looks solvable by TLS/reqwest feature/upgrade changes; continue the experiment work and prefer coordinated upgrades rather than allowing CDLA-Permissive-2.0 permanently.
- The ar_archive_writer issue is directly addressable via a `lettre`/`psm` bump. Experiments in a workspace copy removed the error, so preparing a minimal bump PR is recommended.

Actionable next steps
---------------------
1. Prepare a minimal PR to bump `lettre` and/or `psm` to the versions validated by the experiment and run CI with cargo-deny.
2. Continue webauthn-rs remediation plan (upgrade/replace/vendor) as the top priority.
3. Keep MPL-2.0 and CDLA-Permissive-2.0 as temporary allowlist entries while the above are addressed; remove them as soon as remediation is merged.

Artifacts
---------
- `docker/audit/output/license_triage_2025-11-09.csv`
- Experiment outputs: `docker/audit/output/deny_let_update.*`, `deny_reqwest_native.*`, `deny_licenses.*`
