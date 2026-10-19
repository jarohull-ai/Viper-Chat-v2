# viper-server deployment (Phase 2 bootstrap)

`viper-server` is a Linux executable and HTTP API bootstrap, not yet a complete
production deployment. It only binds to `127.0.0.1`; there is no remote bind
option, TLS termination, authentication layer, or tool-execution endpoint.

Build and inspect its CLI:

```sh
cargo build -p viper-server --bin viper-server
cargo run -p viper-server -- --help
```

Required startup inputs:

- `--db PATH`: SQLite trajectory ledger.
- `--seed-runtime-dir PATH` and `--seed-socket PATH`: the private runtime
  directory and socket expected by [SEED IPC v2](protocols/SEED_IPC_V2.md).
- `--seed-provider-uid UID`: the distinct Linux UID expected for the provider.
- `--seed-provider-keyring PATH`: administrator-provisioned Ed25519 public
  trust bundle. It is public, but integrity-sensitive and must not be writable
  by group or other users.
- Optional `--policy PATH` and `--guard-level strict|balanced|off` select a
  validated Tool Guard policy and sensitivity level. The embedded versioned
  policy is used when `--policy` is omitted.
- Optional `--port PORT` selects the loopback HTTP port (default 3000; `0`
  requests an ephemeral port).

Example argument shape:

```sh
viper-server \
  --db /var/lib/viper/trajectory.sqlite3 \
  --seed-runtime-dir /run/viper-seed \
  --seed-socket /run/viper-seed/seed.sock \
  --seed-provider-uid 991 \
  --seed-provider-keyring /etc/viper/seed-provider-keys.json \
  --port 3000
```

Only the provider receives its Ed25519 signing key through an inherited
`VIPER_SEED_SIGNING_KEY_V2` credential descriptor. `viper-server` receives the
public key bundle only. Run the two services as separate UIDs and configure the
provider-owned runtime directory and narrow shared IPC group as specified in
the protocol. `--allow-same-uid-development` exists only for local tests and
must not be used in production.

The production provider executable and first-run credential provisioner are
not implemented yet. Until then, this executable cannot form a complete
decision service: the configured socket must be served by an IPC v2 provider,
and both peer-UID checks must pass. Provider lifecycle management, service
units, restart policy, and key rotation belong to that follow-up slice. Do not
expose this loopback API through a reverse proxy before the separate
authenticated remote-API design exists.
