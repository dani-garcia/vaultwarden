# Local Dependency Audit — 2025-11-09

Summary
-------

This repository was audited locally using the Docker-based audit tooling in `docker/audit`. The audit ran `cargo-audit` and `cargo-deny` and produced the following notable findings:

- RUSTSEC-2023-0071 (rsa 0.9.8) — a timing side-channel vulnerability ("Marvin Attack") affecting the `rsa` crate. No safe upgrade was available at the time of the audit; the crate is transitive (via `openidconnect`).
- RUSTSEC-2024-0436 (paste 1.0.15) — crate marked as unmaintained (transitive via `rmp`/`rmpv`).
- License checks reported numerous rejections (many transitive crates), see `docker/audit/output/cargo-deny-licenses.err` for full diagnostics.

Artifacts
---------

The raw audit captures are available in `docker/audit/output/` in this working copy (they were copied from the audit container):

- `cargo-version.txt` — cargo version captured from the audit container
- `cargo-audit.err` — cargo-audit stderr (contains CLI errors/diagnostics or JSON when supported)
- `cargo-deny-advisories.err` — cargo-deny advisories diagnostics (JSON preferred)
- `cargo-deny-licenses.err` — cargo-deny license diagnostics (large)

Recommended next steps
----------------------

1. Triage RUSTSEC-2023-0071 (rsa)
   - Use `cargo tree -i rsa` to confirm the top-level crate(s) that bring in `rsa` (expected: `openidconnect`).
   - Try upgrading `openidconnect` to a newer version that does not bring `rsa`, or replace the OIDC/JWT dependency with an alternative that uses a constant-time crypto implementation (e.g., ring/openssl-backed option).
   - If the dependency cannot be removed immediately, document the exception and create a tracking issue to replace the transitive dependency.

2. Triage `paste` unmaintained advisory
   - Identify the top-level dependency chain and attempt to upgrade or replace the dependency (rmp/rmpv) or migrate to a maintained fork.

3. License policy
   - Review `deny.toml` added to the repository as a starting policy. Adjust `licenses.allowed` to match project licensing policy.
   - For crates that are necessary but have unapproved licenses, add specific exceptions with justification and target remediation dates.

4. CI integration
   - The PR adds a GitHub Actions workflow `.github/workflows/audit.yml` which runs `cargo-audit` and `cargo-deny`. Tweak versions and failure behavior to match your release policy (block PRs or open warnings).

5. Follow-up work
   - If replacements require code changes (e.g., replacing OIDC crate), create small follow-up PRs with unit tests and integration tests for auth flows.

Contact / Tracking
------------------

Open a follow-up issue for each remediation item (e.g., "Replace transitive rsa usage" and "Replace unmaintained paste dependency"). Link those issues from this note and the PR.
