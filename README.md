# Viper Chat v2 — Native Rust

Private, incremental rewrite of Viper Chat around a fail-closed decision engine,
versioned Tool Guard policy, and durable SQLite trajectory ledger.

This repository starts with Phase 1 only. The Rust workspace is deliberately
incapable of executing tools. See [`docs/v2/`](docs/v2/) for the frozen product
specification, architecture, migration plan, ADRs, and protocol contracts.

## Build and verify

```sh
cargo test --workspace --all-targets
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
```

`Cargo.lock` is committed because this is an application/workspace, not a
published library-only crate set.

## License

Noncommercial use is available under the [PolyForm Noncommercial License
1.0.0](https://polyformproject.org/licenses/noncommercial/1.0.0). Commercial
use requires a separate paid commercial license; see [`LICENSE`](LICENSE).
This is source-available software, not an OSI-approved open-source release.
