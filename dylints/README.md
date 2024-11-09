# How to run Lints

```sh
cargo install cargo-dylint dylint-link

RUSTFLAGS="-Aunreachable_patterns" cargo dylint --all -- --features sqlite
```