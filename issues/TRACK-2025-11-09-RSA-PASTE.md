# TRACK-2025-11-09: Remediate transitive `rsa` and `paste` advisories

Status: Open
Owner: @maintainers (please assign)
Created: 2025-11-09

Summary
-------

This tracking issue records the planned remediation work for two transitive advisories found during the local audit on 2025-11-09:

- RUSTSEC-2023-0071 — `rsa = 0.9.8` (Marvin Attack). No safe published upgrade was available at audit time. Transitive path: `openidconnect` -> `...` -> `rsa`.
- RUSTSEC-2024-0436 — `paste = 1.0.15` (unmaintained). Transitive path: `rmp`/`rmpv` -> `paste`.

Goals
-----

1. Remove or replace the transitive dependency on `rsa` so the project does not depend on the vulnerable crate.
2. Replace or remove `paste` usage by migrating to a maintained alternative (e.g., `pastey`) or removing the transitive dependency chain.
3. Remove the temporary exceptions from `deny.toml` once remediation is complete.

Plan
----

1. Repro steps
   - Run `cargo tree -i rsa` and `cargo tree -i paste` to show the reverse dependency chain and confirm the top-level crate(s) importing them.

2. Investigate fixes
   - For `rsa`: identify whether `openidconnect` or another dependency directly pulls `rsa`. Check if newer published versions of the top-level crate avoid `rsa`.
   - If no published version removes `rsa`, assess vendor or patch options:
     - Replace `openidconnect` with an alternative OIDC client that avoids `rsa` (e.g., a crate using ring/openssl for crypto), or
     - Submit a PR to upstream crates to adopt a constant-time implementation, or
     - Vendor a small shim that provides the needed functionality using a vetted crypto library.

   - For `paste`: check if `rmp`/`rmpv` can be upgraded to eliminate `paste` or if a maintained fork (e.g., `pastey`) can be used.

3. Tests and validation
   - Add unit/integration tests for the replaced functionality (auth flows, message formats) to ensure behavior parity.
   - Re-run audit tooling in CI and verify `cargo-deny` no longer reports the advisories.

4. Timeline and owner
   - Target ETA: 2026-02-01 (three months). Adjust based on investigation findings.
   - Owner: @maintainers or assign a specific engineer.

5. Rollback/compensating controls
   - If remediation requires longer work, consider adding hardened monitoring, limiting feature usage, or using runtime mitigations where possible.

Links
-----

- Audit note: SECURITY-AUDIT-2025-11-09.md
- PR branch: remediations/audit-2025-11-09

Next steps
----------
- Assign an owner, run `cargo tree -i rsa` and `cargo tree -i paste`, and update this issue with findings and the chosen remediation path.

---

Temporary license allowlist (2025-11-09)
-------------------------------------

On 2025-11-09 a temporary license allowlist was added to `deny.toml` to reduce noise from widely-used OSI-approved licenses so CI can proceed with the security remediation work. The licenses added were: `Unicode-3.0`, `ISC`, `0BSD`, and `Zlib`. This change explicitly did NOT add `MPL-2.0` or `CDLA-Permissive-2.0`.

Review: The license allowlist will be revisited on or before 2026-02-07 (90 days) and removed or narrowed depending on remediation progress.
