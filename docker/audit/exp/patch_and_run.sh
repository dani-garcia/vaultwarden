#!/usr/bin/env bash
set -euo pipefail

# Safe copy of workspace
cp -a /workspace /tmp/wrk_copy
cd /tmp/wrk_copy

# Try bumping webauthn-rs to 0.6 in the copy (non-destructive)
perl -0777 -pe 's/webauthn-rs\s*=\s*"[^"]+"/webauthn-rs = "0.6"/g' -i Cargo.toml || true

# Attempt to update that package only
/usr/local/cargo/bin/cargo update -p webauthn-rs || true

# Run cargo-deny licenses check and capture outputs
/usr/local/cargo/bin/cargo deny --manifest-path Cargo.toml --format json check licenses > /tmp/deny_licenses.json 2>/tmp/deny_licenses.err || true

# Record done marker
echo done > /tmp/exp.done
