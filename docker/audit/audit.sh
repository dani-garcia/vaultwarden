set -euo pipefail
export PATH="/usr/local/cargo/bin:/usr/local/bin:$PATH"
echo "=== cargo-audit --version ==="
/usr/local/cargo/bin/cargo-audit --version || true
echo "=== cargo-audit report ==="
# Run cargo-audit on the workspace Cargo.lock if present; local crate otherwise
/usr/local/cargo/bin/cargo-audit || true
echo "=== cargo-deny --version ==="
/usr/local/cargo/bin/cargo-deny --version || true
echo "=== cargo-deny advisories ==="
# Use --manifest-path as a global option and run check advisories and licenses
/usr/local/cargo/bin/cargo-deny --manifest-path Cargo.toml check advisories || true
echo "=== cargo-deny licenses ==="
/usr/local/cargo/bin/cargo-deny --manifest-path Cargo.toml check licenses || true