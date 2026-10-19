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
  directory and socket expected by [SEED IPC v1](protocols/SEED_IPC_V1.md).
- `--seed-credential-fd N`: an inherited descriptor (N >= 3) containing the
  strict `VIPER_SEED_KEY_V1` record. This is the shared symmetric IPC HMAC key,
  not a model/API credential. Because IPC v1 uses HMAC in both directions, the
  server and SEED provider both need the same key record; each process must
  receive it through a trusted service-manager credential handoff. The server
  does not read `.env` or accept a key on the command line.
- Optional `--policy PATH` and `--guard-level strict|balanced|off` select a
  validated Tool Guard policy and sensitivity level. The embedded versioned
  policy is used when `--policy` is omitted.
- Optional `--port PORT` selects the loopback HTTP port (default 3000; `0`
  requests an ephemeral port).

Example argument shape (the credential descriptor must be securely inherited
from the service manager; this snippet intentionally does not provision it):

```sh
viper-server \
  --db /var/lib/viper/trajectory.sqlite3 \
  --seed-runtime-dir /run/viper-seed \
  --seed-socket /run/viper-seed/seed.sock \
  --seed-credential-fd 3 \
  --port 3000
```

The current HMAC-v1 trust model means a compromised server process can use its
keyring to forge provider authentication. If the desired boundary is that only
the SEED provider receives private key material, IPC must move to a versioned
asymmetric-authentication design before production use; do not imply that the
current shared-HMAC descriptor achieves provider-only custody.

The production `viper-seed` provider process and first-run credential
provisioner are not implemented yet. Until then, this executable cannot form a
complete decision service: the configured socket must be served by a matching
authenticated provider, and both peers must satisfy the IPC ownership checks.
Provider lifecycle management, service units, restart policy, and credential
rotation belong to that follow-up slice. Do not expose this loopback API through
a reverse proxy before the separate authenticated remote-API design exists.
