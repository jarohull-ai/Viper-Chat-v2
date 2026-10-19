# Viper Chat v2 — Native Rust

Private, incremental rewrite of Viper Chat around a fail-closed decision engine,
versioned Tool Guard policy, and durable SQLite trajectory ledger.

Phase 1 is complete; Phase 2 starts with the `viper-server` HTTP API. The Rust
workspace is still deliberately incapable of executing tools. See
[`docs/v2/`](docs/v2/) for the frozen product specification, architecture,
migration plan, ADRs, and protocol contracts.

The `viper-server` executable binds to IPv4 loopback and requires the SEED IPC
socket plus an inherited credential descriptor. Startup options and current
deployment limitations are in [`docs/v2/DEPLOYMENT.md`](docs/v2/DEPLOYMENT.md).

## Build and verify

```sh
cargo test --workspace --all-targets
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
```

`Cargo.lock` is committed because this is an application/workspace, not a
published library-only crate set.

## License

Personal and other noncommercial use is available under the [PolyForm
Noncommercial License 1.0.0](https://polyformproject.org/licenses/noncommercial/1.0.0).
Use for commercial advantage or monetary compensation requires a separate paid
commercial license; see [`LICENSE`](LICENSE). PolyForm Noncommercial also
allows certain noncommercial institutional uses (including qualifying
educational, charitable, and public-research uses) regardless of funding, so
the rule is based on the purpose of use—not solely on whether the user is a
company. This is source-available software, not an OSI-approved open-source
release. The license terms should be reviewed by qualified counsel before
commercial distribution.
