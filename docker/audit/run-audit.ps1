param(
    [string]$Workspace = "$PSScriptRoot\..\..",
    [string]$ImageName = "vaultwarden-audit:latest"
)

Push-Location $PSScriptRoot
try {
    Write-Host "Building Docker image '$ImageName' (this may take several minutes)..."
    docker build -t $ImageName .

    Write-Host "Running audit container... outputs will be written to: $Workspace"
    docker run --rm -v "${Workspace}:/workspace" -w /workspace $ImageName bash -lc '
        set -euo pipefail
        echo "=== cargo-audit --version ==="
        /usr/local/cargo/bin/cargo-audit --version || true
        echo "=== cargo-audit report ==="
        /usr/local/cargo/bin/cargo-audit -q || true
        echo "=== cargo-deny --version ==="
        /usr/local/cargo/bin/cargo-deny --version || true
        echo "=== cargo-deny advisories ==="
        /usr/local/cargo/bin/cargo-deny check advisories --manifest-path Cargo.toml || true
        echo "=== cargo-deny licenses ==="
        /usr/local/cargo/bin/cargo-deny check licenses --manifest-path Cargo.toml || true
    '
}
finally {
    Pop-Location
}
