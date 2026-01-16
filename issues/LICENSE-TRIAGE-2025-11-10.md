# License triage summary (2025-11-10)

Summary
-------
This short report summarizes the top remaining license failures reported by `cargo-deny` after temporary allowlist adjustments and initial experiments.

Top offenders (extracted from `docker/audit/output/license_triage_2025-11-09.csv`):

- webauthn-rs family (MPL-2.0):
  - `webauthn-rs v0.5.3` (direct dependency)
  - `webauthn-rs-core v0.5.3`
  - `webauthn-rs-proto v0.5.3`
  - `webauthn-attestation-ca v0.5.3`
  - `base64urlsafedata v0.5.3`

- webpki-roots (CDLA-Permissive-2.0):
  - `webpki-roots v1.0.3` pulled via `hyper-rustls v0.27.7` -> `reqwest v0.12.24` -> `openidconnect v4.0.1` (and also via `opendal`/`yubico_ng`).

Counts and impact
-----------------
- cargo-deny reported 7 license errors in the most recent run. The list above represents the full set of failing crates.

Short remediation guidance
------------------------
- `webauthn-rs`: direct dependency. Options: (a) upgrade (if a permissively licensed version exists), (b) replace with an alternative WebAuthn crate, or (c) vendor minimal functionality. Immediate step: contact upstream and search for forks/relicensing.
- `webpki-roots`: transitive via the TLS/HTTP stack. Options: (a) coordinated upgrade of `reqwest`/`hyper-rustls`/`openidconnect` or (b) switch TLS backend/features to avoid `webpki-roots`.

Artifacts
---------
- Full diagnostics and experiment artifacts: `docker/audit/output/` (files: `*_deny.err`, `*_deny.json`, `*_build.err`).

Next steps
----------
1. Owner assignment and tasking in PR checklist (see draft PR #2).
2. Continue coordinated upgrades for `reqwest` chain and attempt to upgrade/replace `webauthn-rs`.
3. Remove temporary allowlist once all offenders are resolved.
