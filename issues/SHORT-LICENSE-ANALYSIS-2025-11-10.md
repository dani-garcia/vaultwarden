# Short license-failure analysis (2025-11-10)

Purpose
-------
This short analysis summarizes the top offenders that caused the recent license failures (537 total failures reported across the full audit) and provides a quick feasibility assessment of whether the temporary allowlist can be narrowed or must remain in place while remediation proceeds.

Key findings
------------
- The top failing crates (from `docker/audit/output/license_triage_2025-11-09.csv`) are:
  - webauthn-rs family (MPL-2.0): `webauthn-rs v0.5.3` (direct dep), `webauthn-rs-core v0.5.3`, `webauthn-rs-proto v0.5.3`, `webauthn-attestation-ca v0.5.3`, `base64urlsafedata v0.5.3`.
  - `webpki-roots v1.0.3` (CDLA-Permissive-2.0) pulled transitively via `hyper-rustls -> reqwest -> openidconnect`.
  - `ar_archive_writer v0.2.0` (Apache-2.0 WITH LLVM-exception) reported via `lettre` (present in CSV but not blocking if Apache+LLVM-exception is in your allowlist policy).

Feasibility of policy adjustment
--------------------------------
- MPL-2.0 cluster (webauthn-rs):
  - Because `webauthn-rs` is a direct dependency for `vaultwarden`, allowing MPL-2.0 in the policy would immediately remove this class of failures.
  - Trade-off: MPL-2.0 is a copyleft-style license with obligations different from Apache/MIT; adding it to an allowlist should be treated as temporary and timeboxed while an upgrade/replacement is pursued.
  - Recommendation: Keep restrictive stance (do not permanently allow MPL-2.0). Use timeboxed temporary allowlist and expedite `webauthn-rs` remediation.

- CDLA-Permissive-2.0 cluster (webpki-roots):
  - This is transitive via TLS stacks; often solvable by switching TLS backend (native-tls) or upgrading `reqwest`/`hyper-rustls`/`openidconnect` chain.
  - Feasibility: Medium — requires coordination across multiple crates; experimenting with toggling features or bumping versions may remove webpki-roots without wider policy changes.
  - Recommendation: Prioritize a targeted experiment (already started) to prefer `native-tls` or bump specific dependencies; avoid permanently allowing CDLA-Permissive-2.0 unless remediation proves infeasible.

Quick action items
------------------
1. Apply targeted experiments (in separate ephemeral branches):
   - Toggle `reqwest` to prefer `native-tls` in a workspace copy and run `cargo-deny`.
   - Attempt upgrading/removing `openidconnect`'s `reqwest` feature as done in previous experiments and record before/after diffs.
2. Attempt `webauthn-rs` remediation (upgrade, replace, or vendor) as top priority; the direct dependency makes this the highest-impact remediation.
3. Keep temporary allowlist timeboxed and document progress in `issues/TRACK-2025-11-09-RSA-PASTE.md`.

Conclusion
----------
Short-term policy change (temporary allowlist for MPL-2.0 and CDLA-Permissive-2.0) is defensible as a timeboxed mitigation while focused remediation proceeds. The high-impact targets are `webauthn-rs` (direct dep) and the transitive `webpki-roots` via the TLS stack. Prioritize `webauthn-rs` remediation and coordinated TLS-stack experiments; if they succeed, remove the temporary allowlist.
