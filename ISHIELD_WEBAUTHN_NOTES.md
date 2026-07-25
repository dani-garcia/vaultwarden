# Swissbit iShield Key 2 Pro / WebAuthn notes

Status as of 2026-07-19.

## Current status

- Affected authenticator: Swissbit iShield Key 2 Pro MIFARE
- Device version: `1.1.0`
- FIDO applet: `v1.4.0-0-gd69b47b`
- AAGUID: `7787a482-13e8-4784-8a06-c7ed49a7aaf4`
- Supported protocols: U2F, CTAP 2.0, CTAP 2.1
- Relevant reported options:
  - `clientPin: yes`
  - `alwaysUv: no`
  - `makeCredUvNotRqd: yes`
- Tested Vaultwarden release: `1.36.0`
- Tested Web Vault release: `2026.4.1`
- Tested browser: Google Chrome `150.0.7871.124`
- Server: Debian 13, Linux x86_64, SQLite, native installation created by the Proxmox VE Community Script
- Vaultwarden serves HTTPS directly; no reverse proxy is used.

With an FIDO2 PIN already configured on the iShield, unmodified Vaultwarden does
not show a PIN prompt during registration. The WebAuthn ceremony eventually
times out. Registering the key without a configured PIN works. YubiKeys with an
existing PIN work correctly in the same environment, and the iShield works on
webauthn.io.

Vaultwarden deliberately changes the registration and authentication policy to
`userVerification: discouraged`, since WebAuthn is being used as a second factor.
The iShield advertises `makeCredUvNotRqd: yes`, so the client is allowed to try
credential creation without PIN-based user verification. That path does not
complete in the tested combination.

Changing both the client challenge and server-side ceremony state from
`discouraged` to `preferred` fixes the problem. Registration then requests the
PIN, completes after touching the key, and authentication also succeeds in a new
Incognito session.

Upstream issue:

- <https://github.com/dani-garcia/vaultwarden/issues/7437>

Swissbit support has also been informed. Following maintainer feedback, an
upstream implementation is in progress on the local branch
`webauthn-2fa-user-verification-config`. It adds the editable server option
`WEBAUTHN_2FA_USER_VERIFICATION`, with `discouraged` remaining the default and
`preferred` enabling the working PIN/UV flow. The option is also exposed by the
existing Vaultwarden admin configuration UI.

## Diagnostic source patch

For Vaultwarden 1.36.0, four values in
`src/api/core/two_factor/webauthn.rs` were changed:

```diff
- state["rs"]["policy"] = Value::String("discouraged".to_string());
+ state["rs"]["policy"] = Value::String("preferred".to_string());

- asc.user_verification = UserVerificationPolicy::Discouraged_DO_NOT_USE;
+ asc.user_verification = UserVerificationPolicy::Preferred;

- state["ast"]["policy"] = Value::String("discouraged".to_string());
+ state["ast"]["policy"] = Value::String("preferred".to_string());

- response.public_key.user_verification = UserVerificationPolicy::Discouraged_DO_NOT_USE;
+ response.public_key.user_verification = UserVerificationPolicy::Preferred;
```

Both the response sent to the browser and the server-side state must remain
consistent. Changing only the response is not the recommended test.

## Current LXC binary and rollback

The original 1.36.0 binary was saved as:

```text
/opt/vaultwarden/bin/vaultwarden.original
```

The original SHA-256 recorded during the test was:

```text
c7d507bb05a30af1ea3974fac53713be747730ce653e9ee26a1b3cd0a65b2c7e
```

Rollback to that binary:

```bash
systemctl stop vaultwarden

install -o root -g root -m 0755 \
  /opt/vaultwarden/bin/vaultwarden.original \
  /opt/vaultwarden/bin/vaultwarden

rm -f /opt/vaultwarden/bin/.uv-preferred-version

systemctl start vaultwarden
systemctl status vaultwarden --no-pager
```

An official PVE Community Script update will overwrite the active custom binary.
The iShield is expected to fail again after such an update unless upstream has
changed the policy or the custom build is reapplied.

## Post-update rebuild script

Install the following as `/usr/local/sbin/vaultwarden-uv-patch` inside the LXC.
It intentionally aborts if the upstream source no longer contains exactly the
four expected policy expressions.

```bash
#!/usr/bin/env bash
set -Eeuo pipefail

VW_ROOT="/opt/vaultwarden"
VW_BIN="${VW_ROOT}/bin/vaultwarden"
BUILD_DIR="/tmp/vaultwarden-uv-build"
SOURCE_FILE="src/api/core/two_factor/webauthn.rs"

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: This script must be run as root." >&2
    exit 1
fi

if [[ ! -x "$VW_BIN" ]]; then
    echo "ERROR: Vaultwarden binary not found: $VW_BIN" >&2
    exit 1
fi

VERSION="$("$VW_BIN" --version 2>/dev/null |
    grep -oE '[0-9]+\.[0-9]+\.[0-9]+' |
    head -n1)"

if [[ -z "$VERSION" ]]; then
    echo "ERROR: Could not determine the installed Vaultwarden version." >&2
    exit 1
fi

PATCHED_MARKER="${VW_ROOT}/bin/.uv-preferred-version"

if [[ -f "$PATCHED_MARKER" ]] &&
   [[ "$(<"$PATCHED_MARKER")" == "$VERSION" ]] &&
   "$VW_BIN" --version 2>/dev/null | grep -q 'uv-preferred'; then
    echo "Vaultwarden $VERSION is already patched."
    exit 0
fi

echo "Preparing UV-preferred build for Vaultwarden $VERSION"

command -v git >/dev/null ||
    { echo "ERROR: git is not installed." >&2; exit 1; }

command -v cargo >/dev/null ||
    { echo "ERROR: cargo is not available." >&2; exit 1; }

if [[ "$BUILD_DIR" != "/tmp/vaultwarden-uv-build" ]]; then
    echo "ERROR: Unexpected build directory: $BUILD_DIR" >&2
    exit 1
fi

rm -rf -- "$BUILD_DIR"

git clone \
    --branch "$VERSION" \
    --depth 1 \
    https://github.com/dani-garcia/vaultwarden.git \
    "$BUILD_DIR"

cd "$BUILD_DIR"

if [[ ! -f "$SOURCE_FILE" ]]; then
    echo "ERROR: Expected source file is missing: $SOURCE_FILE" >&2
    exit 1
fi

STATE_PATTERN='Value::String("discouraged".to_string())'
POLICY_PATTERN='UserVerificationPolicy::Discouraged_DO_NOT_USE'

STATE_COUNT="$(grep -Fc "$STATE_PATTERN" "$SOURCE_FILE" || true)"
POLICY_COUNT="$(grep -Fc "$POLICY_PATTERN" "$SOURCE_FILE" || true)"

if [[ "$STATE_COUNT" -ne 2 || "$POLICY_COUNT" -ne 2 ]]; then
    echo "ERROR: Vaultwarden's WebAuthn implementation has changed." >&2
    echo "Expected two state policies and two challenge policies." >&2
    echo "Found state=$STATE_COUNT, challenge=$POLICY_COUNT." >&2
    echo "No binary was changed." >&2
    exit 1
fi

sed -i \
    's/Value::String("discouraged".to_string())/Value::String("preferred".to_string())/g' \
    "$SOURCE_FILE"

sed -i \
    's/UserVerificationPolicy::Discouraged_DO_NOT_USE/UserVerificationPolicy::Preferred/g' \
    "$SOURCE_FILE"

REMAINING_STATE="$(grep -Fc "$STATE_PATTERN" "$SOURCE_FILE" || true)"
REMAINING_POLICY="$(grep -Fc "$POLICY_PATTERN" "$SOURCE_FILE" || true)"
PREFERRED_STATE="$(grep -Fc 'Value::String("preferred".to_string())' "$SOURCE_FILE" || true)"
PREFERRED_POLICY="$(grep -Fc 'UserVerificationPolicy::Preferred' "$SOURCE_FILE" || true)"

if [[ "$REMAINING_STATE" -ne 0 ||
      "$REMAINING_POLICY" -ne 0 ||
      "$PREFERRED_STATE" -lt 2 ||
      "$PREFERRED_POLICY" -lt 2 ]]; then
    echo "ERROR: Patch verification failed. No binary was changed." >&2
    exit 1
fi

git diff --check

echo "Applied source patch:"
git diff -- "$SOURCE_FILE"

export VW_VERSION="${VERSION}-uv-preferred"

cargo build \
    --locked \
    --features "sqlite,mysql,postgresql" \
    --release

TEST_BIN="${VW_ROOT}/bin/vaultwarden.uv-preferred-${VERSION}"
OFFICIAL_BACKUP="${VW_ROOT}/bin/vaultwarden.official-${VERSION}"

install -o root -g root -m 0755 \
    target/release/vaultwarden \
    "$TEST_BIN"

if ldd "$TEST_BIN" | grep -q 'not found'; then
    echo "ERROR: The new binary has unresolved libraries." >&2
    rm -f -- "$TEST_BIN"
    exit 1
fi

"$TEST_BIN" --version

if [[ ! -e "$OFFICIAL_BACKUP" ]]; then
    install -o root -g root -m 0755 \
        "$VW_BIN" \
        "$OFFICIAL_BACKUP"
fi

echo "Installing patched binary..."

systemctl stop vaultwarden

install -o root -g root -m 0755 \
    "$TEST_BIN" \
    "$VW_BIN"

printf '%s\n' "$VERSION" >"$PATCHED_MARKER"

if ! systemctl start vaultwarden; then
    echo "ERROR: Patched Vaultwarden failed to start; restoring official binary." >&2

    install -o root -g root -m 0755 \
        "$OFFICIAL_BACKUP" \
        "$VW_BIN"

    rm -f -- "$PATCHED_MARKER"
    systemctl start vaultwarden
    exit 1
fi

if ! systemctl is-active --quiet vaultwarden; then
    echo "ERROR: Service is not active; restoring official binary." >&2

    systemctl stop vaultwarden || true
    install -o root -g root -m 0755 \
        "$OFFICIAL_BACKUP" \
        "$VW_BIN"

    rm -f -- "$PATCHED_MARKER"
    systemctl start vaultwarden
    exit 1
fi

echo
echo "Successfully installed:"
"$VW_BIN" --version

systemctl status vaultwarden --no-pager
echo
echo "Official binary backup: $OFFICIAL_BACKUP"
```

Make it executable:

```bash
chmod 0755 /usr/local/sbin/vaultwarden-uv-patch
```

Run it after the normal PVE Community Script update:

```bash
vaultwarden-uv-patch
```

Then verify:

```bash
/opt/vaultwarden/bin/vaultwarden --version
systemctl status vaultwarden --no-pager
journalctl -u vaultwarden -n 50 --no-pager
```

The version should contain a suffix similar to:

```text
Vaultwarden 1.37.0-uv-preferred
```

## Version-specific rollback after using the script

For example, to restore the official 1.36.0 binary saved by the script:

```bash
systemctl stop vaultwarden

install -o root -g root -m 0755 \
  /opt/vaultwarden/bin/vaultwarden.official-1.36.0 \
  /opt/vaultwarden/bin/vaultwarden

rm -f /opt/vaultwarden/bin/.uv-preferred-version

systemctl start vaultwarden
systemctl status vaultwarden --no-pager
```

Before running the script against a future release, first check issue #7437 and
the release notes. Do not apply the custom build if Vaultwarden has introduced an
official setting or otherwise changed the relevant WebAuthn behavior.
