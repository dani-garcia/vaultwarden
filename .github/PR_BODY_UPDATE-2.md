Temporary license allowlist: MPL-2.0 and CDLA-Permissive-2.0 were added to deny.toml on branch experiment/webauthn-upgrade to unblock CI while coordinated upgrades/replacements are attempted. This is timeboxed and tracked in issues/FEASIBILITY-WEBAUTHN-WEBPKI.md and issues/TRACK-2025-11-09-RSA-PASTE.md. See the experiment artifacts in docker/audit/output/.

## Pre-merge task checklist
These tasks must be completed, reviewed, and verified before this PR is merged. Owners are suggested; assign specific maintainers or security approvers as appropriate.

- [ ] Security lead — confirm and sign off the timebox for the temporary allowlist (target approval date: 2025-11-17). This PR should not be merged without that sign-off.
- [ ] Maintainer — run `cargo tree -i rsa` and `cargo tree -i paste`, paste the reverse-dependency outputs in a follow-up comment, and confirm proposed remediation path for each.
- [ ] Maintainer — attempt `webauthn-rs` remediation (preferred order):
	- [ ] Upgrade `webauthn-rs` to a permissively licensed release if available and verify builds/tests.
	- [ ] If no upgrade available, evaluate replacing `webauthn-rs` with another WebAuthn implementation or vendor a minimal shim; document chosen approach.
	- [ ] Add tests covering affected auth flows and run CI.
- [ ] Maintainer — coordinate TLS/HTTP stack remediation to remove `webpki-roots` (CDLA-Permissive-2.0):
	- [ ] Test toggling `reqwest` features to prefer `native-tls` in an isolated workspace copy and publish the artifact logs.
	- [ ] Upgrade `hyper-rustls`/`reqwest`/`openidconnect` as needed to versions that don't bring `webpki-roots`, or change TLS backend.
	- [ ] Verify `cargo-deny` runs clean locally and on CI after each incremental change.
- [ ] Maintainer — provide a short summary comment with before/after `cargo-deny` outputs and link to `docker/audit/output/` artifacts.
- [ ] Maintainer — remove the temporary allowlist entries from `deny.toml` and verify CI shows zero license failures.
- [ ] Maintainer — remove the temporary `advisories.ignore` entries (RUSTSEC ignores) from `deny.toml` and verify CI shows zero advisories and license failures before any final merge.

## Short triage summary (top offenders)
See `issues/LICENSE-TRIAGE-2025-11-10.md` and `docker/audit/output/license_triage_2025-11-09.csv` for full details. Top offenders:

- webauthn-rs family (MPL-2.0): `webauthn-rs v0.5.3` (direct dep), `webauthn-rs-core v0.5.3`, `webauthn-rs-proto v0.5.3`, `webauthn-attestation-ca v0.5.3`, `base64urlsafedata v0.5.3` — remediation: upgrade/replace/vendor.
- webpki-roots (CDLA-Permissive-2.0): `webpki-roots v1.0.3` pulled transitively via `hyper-rustls -> reqwest -> openidconnect` — remediation: coordinated `reqwest`/TLS backend upgrade or feature change.

Artifacts and logs: `docker/audit/output/` contains the `cargo-deny` diagnostics, reverse-dependency trees and experiment logs used to evaluate remediation paths.

See also: `issues/LICENSE-TRIAGE-SUMMARY-2025-11-12.md` for the condensed top-offender analysis and recommended next steps.

Once all tasks above are complete and CI is green with `cargo-deny` passing, this PR may be merged and the temporary allowlist removed.
