# Passkey regression tests

`passkey_unlock.rs` launches the real Vaultwarden binary on loopback with a
temporary database, synthetic accounts, signed WebAuthn assertions and encrypted
key fixtures. No identity provider or authenticator hardware is contacted. The
tests do not establish hardware PRF support or stock-client decryption.

Run the portable HTTP cases with SQLite:

```sh
cargo test --locked --features sqlite --test passkey_unlock
```

The PostgreSQL tests require a disposable local PostgreSQL instance. They create
and drop their own `vw_passkey_*` databases. The fixture deliberately accepts
only loopback, the `postgres` maintenance database, and the synthetic credentials
shown below. The test role needs permission to create databases; never use a
production instance or credentials.

```sh
VW_PASSKEY_TEST_DATABASE_URL='postgresql://passkey_test:synthetic-passkey-test@127.0.0.1:15432/postgres' \
  cargo test --locked --features sqlite,postgresql --test passkey_unlock \
  -- --include-ignored --test-threads=1
```

The PostgreSQL-only concurrency and interruption cases are marked `ignore`
because they need that instance. A default test run does not cover them.

Before enabling passkeys for real vaults, separately test compatible clients and
authenticators: enrollment, fresh sign-in, PRF decryption of existing personal
and shared items, master-password fallback, multiple passkeys, removal, and
password/KDF/account-key changes. For SSO-only installations, verify SSO is still
required. Keep backups and a working fallback throughout these checks.
