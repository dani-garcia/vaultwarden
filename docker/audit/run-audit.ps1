param(
    [string]$Workspace = "$PSScriptRoot\..\..",
    [string]$ImageName = "vaultwarden-audit:latest"
)

Push-Location $PSScriptRoot
try {
    Write-Host "Building Docker image '$ImageName' (this may take several minutes)..."
    docker build -t $ImageName .

    Write-Host "Running audit container... outputs will be written to: $Workspace"

    # Create a small LF-only shell script to avoid CRLF issues when passing
    # multi-line commands into bash on Linux containers from Windows hosts.
    $auditScriptPath = Join-Path $PSScriptRoot 'audit.sh'
    $scriptContent = @'
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
'@

    # Ensure the script uses LF-only line endings by replacing CRLF with LF
    $scriptContent = $scriptContent -replace "`r`n", "`n"
    # Write bytes directly to ensure exact newlines (UTF8 without BOM)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($scriptContent)
    [System.IO.File]::WriteAllBytes($auditScriptPath, $bytes)

    # Run the audit script inside the container by mounting it read-only
    docker run --rm -v "${Workspace}:/workspace" -v "${auditScriptPath}:/audit.sh:ro" -w /workspace $ImageName bash -lc 'bash /audit.sh'
}
finally {
    Pop-Location
}
