Feasibility report: webauthn-rs (MPL-2.0) and webpki-roots (CDLA-Permissive-2.0)

Date: 2025-11-09
Branch: remediations/audit-2025-11-09

Summary
-------
This short report captures the dependency graph findings and remediation options for the two license clusters discovered by cargo-deny:

- webauthn-rs family (webauthn-rs, webauthn-rs-core, webauthn-rs-proto, webauthn-attestation-ca) — license: MPL-2.0
- webpki-roots — license: CDLA-Permissive-2.0 (pulled transitively via `reqwest` / `hyper-rustls` in our graph)

Reverse-dependency findings (what pulled them into the workspace)
---------------------------------------------------------------
- `webauthn-rs v0.5.3` is a direct dependency in `Cargo.toml` (we use features: `danger-allow-state-serialisation`, `danger-credential-internals`).
  - Reverse deps: `webauthn-rs v0.5.3` -> `vaultwarden v1.0.0` (direct)

- `webpki-roots v1.0.3` is transitive via the HTTP/TLS stack:
  - webpki-roots v1.0.3 -> hyper-rustls v0.27.7 -> reqwest v0.12.24 -> openidconnect v4.0.1 -> vaultwarden v1.0.0
  - reqwest is also used in other paths (opendal, yubico-ng, etc.) so webpki-roots appears multiple times transitively.

Feasibility and remediation options (short)
-------------------------------------------
For each cluster below I list pragmatic options, effort estimate, and recommended next action.

1) webauthn-rs (MPL-2.0)

Options:
- Upgrade: check whether `webauthn-rs` publishes a newer version with a different license. If a newer release exists that uses a more permissive license (or is relicensed), upgrade and test. Effort: low-to-moderate (run `cargo update -p webauthn-rs` and run tests; review any breaking API/behaviour changes).
- Replace: adopt an alternative WebAuthn crate or implement minimal functionality in-house. Effort: medium-to-high depending on coverage and features used (we currently enable two non-trivial features).
- Vendor / shim: vendor the needed logic into the repo (or a small wrapper using a different crypto backend) and maintain it as in-tree or as a local crate. Effort: medium; maintenance burden shifts to the project.
- Per-crate exception: timeboxed exception for `webauthn-rs*` in `deny.toml`. Effort: trivial config change but increases audit scope (temporary).

Likelihood / comments:
- Because `webauthn-rs` is a direct dependency and we enable special features for state/credential internals, replacing it may be disruptive.
- First attempt should be: verify upstream for newer versions (minor patch/feature releases), test upgrade locally, and evaluate behavior differences.

Recommended immediate action for webauthn-rs:
- Run `cargo search` / check crates.io for `webauthn-rs` releases (manual step / maintainers action).
- Locally try `cargo update -p webauthn-rs` then run the test suite and exercise WebAuthn flows.
- If upgrade is not available or disruptive, open a narrow, documented, timeboxed per-crate exception for the `webauthn-rs` family while planning a replacement path.

2) webpki-roots (CDLA-Permissive-2.0)

Options:
- Swap TLS backend or reqwest features: `reqwest` supports multiple TLS backends (rustls vs native-tls) and root-store options (webpki-roots vs system roots). Switching to `native-tls` or `rustls` variant with system roots might eliminate the `webpki-roots` dependency.
- Upgrade reqwest / hyper-rustls: newer versions may use different transitive root crates; attempt `cargo update -p reqwest` and `cargo update -p hyper-rustls` and test.
- Replace or vendor: if a dependency requires `webpki-roots` specifically and cannot be changed, consider an explicit per-crate exception or select alternative upstream crates that avoid CDLA.

Likelihood / comments:
- Because `webpki-roots` is pulled in by `reqwest`/`hyper-rustls`, a small change in reqwest features (switching to native-tls) or upgrading reqwest often avoids webpki-roots. This is generally low-to-moderate effort.

Recommended immediate action for webpki-roots:
- Try switching `reqwest` features (in `Cargo.toml`) to use `native-tls` (or system roots) and run `cargo update` and the test suite.
- Alternatively, try `cargo update -p reqwest` and `cargo update -p hyper-rustls` to bring in newer upstream transitive changes, then re-run `cargo-deny`.

Commands to try (local dev / CI experimentation)
------------------------------------------------
# In a branch / local dev container
# 1) Try upgrading webauthn-rs
cargo update -p webauthn-rs
cargo test

# 2) Try upgrading reqwest/hyper-rustls
cargo update -p reqwest
cargo update -p hyper-rustls
cargo test

# 3) Try switching reqwest TLS features to native-tls (edit Cargo.toml):
# reqwest = { version = "0.12.24", features = ["native-tls", "stream", "json", ...], default-features = false }
cargo update
cargo test

# 4) Re-run the audit after any change
# (inside audit container or CI) - this verifies cargo-deny results
/usr/local/cargo/bin/cargo-deny --manifest-path Cargo.toml check licenses --format json

Risk assessment & policy suggestion
----------------------------------
- Short-term: a documented, timeboxed, per-crate exception for the webauthn-rs family and/or webpki-roots is acceptable to unblock CI while we attempt upgrades. However, because `webauthn-rs` is a direct dependency and non-trivial, invest effort to try an upgrade/replacement within a short timeline (30-90 days).
- Medium-term: prefer dependency upgrades or swapping reqwest TLS options over perpetual exceptions. Upgrades reduce maintenance debt and long-term audit risk.

Deliverables included with this report
-------------------------------------
- Reverse dependency outputs captured in `docker/audit/output/webauthn-tree.txt` and `docker/audit/output/webpki-tree.txt`.
- License triage CSV: `docker/audit/output/license_triage_2025-11-09.csv`.
- Recommended commands and next steps (above).

If you want, I can attempt the low-risk experiments now:
- Try `cargo update -p reqwest` and re-run `cargo-deny` (low effort, downloads crates), or
- Try `cargo update -p webauthn-rs` and run test suite (may require exercising WebAuthn flows).

Next suggested step
-------------------
Run the quick experiment: upgrade `reqwest` (and hyper-rustls) in a temporary branch, re-run `cargo-deny` and tests, and report the results. This often removes `webpki-roots` without deeper changes.

Experiment results (2025-11-10)
--------------------------------
Summary of actions run in a temporary experiment branch and container:

- Performed `cargo search webauthn-rs` inside the audit container; crates.io shows `webauthn-rs = "0.5.3"` as the current published version in that namespace (search results saved to `docker/audit/output/webauthn_search.txt`).
- Ran a safe workspace copy upgrade attempt (in `/tmp/wrk_upgrade`) where I attempted incremental updates: `cargo update -p reqwest`, `cargo update -p hyper-rustls`, and `cargo update -p webauthn-rs`. Build and `cargo-deny` were run in the copy. Outputs were captured to `docker/audit/output/upgrade_*.{out,err,json}`.

Findings:

- The quick experiments did not eliminate the MPL-2.0 or CDLA-Permissive-2.0 diagnostics. `cargo-deny` still reports 7 license errors — the same clusters identified earlier (webauthn-rs family and webpki-roots). See `docker/audit/output/upgrade_deny.err` for the diagnostic JSON lines.
- The crates.io search indicates no newer `webauthn-rs` version in the same crate name space beyond `0.5.3` (at time of experiment). That suggests upgrading `webauthn-rs` may not be an option unless an alternate crate name or published fork exists.

Next steps recommended:

- Given that `webauthn-rs` appears to be at 0.5.3 on crates.io, investigate upstream (project repository) for planned releases or contact upstream about licensing/maintenance.
- For the TLS/root-store problem (webpki-roots), continue with a coordinated upgrade of `reqwest` + `hyper-rustls` and dependent crates (openidconnect/opendal) on a feature-aware branch; if upgrades are blocked, trial a `native-tls` switch in a dedicated branch where dependent features are adjusted accordingly.

All experiment artifacts are available under `docker/audit/output/`.

