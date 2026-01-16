#!/usr/bin/env bash
set -euo pipefail

cp -a /workspace /tmp/wrk_req
cd /tmp/wrk_req

# Replace rustls features to prefer native-tls in reqwest (simple approach editing Cargo.toml)
perl -0777 -pe 's/reqwest\s*=\s*"[^"]+"/reqwest = "0.12.24"/g' -i Cargo.toml || true
# Remove rustls-tls feature and add tls = "native-tls" where features are specified
perl -0777 -pe 's/rustls-tls/native-tls/g' -i Cargo.toml || true

# Attempt to update reqwest and run cargo-deny licenses in the copied workspace
/usr/local/cargo/bin/cargo update -p reqwest || true
/usr/local/cargo/bin/cargo deny --manifest-path Cargo.toml --format json check licenses > /tmp/deny_reqwest_native.json 2>/tmp/deny_reqwest_native.err || true

echo done > /tmp/req_exp.done
