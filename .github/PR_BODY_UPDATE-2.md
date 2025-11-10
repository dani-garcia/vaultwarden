Temporary license allowlist: MPL-2.0 and CDLA-Permissive-2.0 were added to deny.toml on branch experiment/webauthn-upgrade to unblock CI while coordinated upgrades/replacements are attempted. This is timeboxed and tracked in issues/FEASIBILITY-WEBAUTHN-WEBPKI.md and issues/TRACK-2025-11-09-RSA-PASTE.md. See the experiment artifacts in docker/audit/output/.

## Tasks
- [ ] Owner: Security lead — confirm timebox and approve temporary allowlist (by 2025-11-17)
- [ ] Owner: Maintainer — attempt `webauthn-rs` upgrade or replacement; report feasibility (see issues/FEASIBILITY-WEBAUTHN-WEBPKI.md)
- [ ] Owner: Maintainer — coordinate `reqwest`/`hyper-rustls`/`openidconnect` upgrades to remove `webpki-roots` (see docker/audit/output/* and reqwest/webpki trees)
- [ ] Owner: Maintainer — verify cargo-deny clean runs on CI after each change
- [ ] Owner: Maintainer — remove temporary allowlist and update deny.toml when all issues resolved

## Triage summary
See issues/LICENSE-TRIAGE-2025-11-10.md for a short summary of the top offenders and remediation options.
