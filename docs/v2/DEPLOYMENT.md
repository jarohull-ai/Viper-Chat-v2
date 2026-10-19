# viper-server deployment (Phase 2 bootstrap)

`viper-server` is a Linux executable and HTTP API bootstrap, not yet a complete
production deployment. It only binds to `127.0.0.1`; there is no remote bind
option, TLS termination, authentication layer, or tool-execution endpoint.

Build and inspect its CLI:

```sh
cargo build -p viper-server --bin viper-server
cargo build -p viper-seed --bin viper-seed-provider
cargo build -p viper-seed --bin viper-seed-keygen
cargo run -p viper-server -- --help
cargo run -p viper-seed --bin viper-seed-provider -- --help
cargo run -p viper-seed --bin viper-seed-keygen -- --help
```

## First-run credential provisioning

Create the output directories first; they must already exist, be root-owned,
and not be writable by group or other users. Run the provisioner as root with
the dedicated non-root provider UID. It refuses existing destinations, never
prints private material, and publishes files without replacing existing paths:

```sh
install -d -o root -g root -m 0755 /etc/viper-seed
install -d -o root -g root -m 0755 /etc/viper
install -d -o root -g 991 -m 0750 /var/lib/viper-seed/credentials
viper-seed-keygen \
  --key-id provider-2026-10 \
  --provider-uid 991 \
  --provider-gid 991 \
  --private-output /var/lib/viper-seed/credentials/signing-key \
  --public-output /etc/viper/seed-provider-keys.json
```

The private file is mode `0400`, owned by the provider UID/GID; its parent is
root-owned and group-traversable by the provider. The public keyring is mode
`0644`, root-owned. Both are generated from one OS-random Ed25519 seed
and synced before publication. This command is first-run-only: it never
overwrites, rotates, or deletes existing credentials. For now, an operator
supplies the private file to the provider on inherited FD 3
(`3</var/lib/viper-seed/credentials/signing-key`); do not copy it into argv,
an environment variable, or a server-owned location. Automated rotation and a
automated rotation workflow remain separate follow-up work.

## systemd provider service

`deploy/systemd/viper-seed-provider.service` is a hardened starting template.
It assumes static `viper-seed` and `viper-ipc` accounts/groups, the provider
binary at `/usr/local/bin/viper-seed-provider`, the credential and runtime
paths above, and a `viper-server` UID of `990` (edit `--client-uid` to match).
Add the server account to `viper-ipc`; do not make the socket world-accessible.
The template uses systemd's credential-directory specifier (`%d`) and opens
that credential on FD 3 for the provider. The key bytes never appear in unit
arguments or environment. `RuntimeDirectory=` gives the provider its managed
socket directory; `ProtectSystem=strict` leaves that directory writable while
keeping the rest of the filesystem read-only.

Install and verify the template for the target host's systemd version before
enabling it:

```sh
install -o root -g root -m 0644 deploy/systemd/viper-seed-provider.service \
  /etc/systemd/system/viper-seed-provider.service
systemd-analyze verify /etc/systemd/system/viper-seed-provider.service
systemctl daemon-reload
systemctl enable --now viper-seed-provider.service
```

This is a deployment example, not a claim of host-level validation. Review the
UID/GID and paths, run `systemd-analyze verify` on the deployment distribution,
then verify socket ownership and an authenticated client connection. The full
root-only server + real-provider + SQLite end-to-end test remains separate;
run it in an isolated local setup or on a dedicated privileged runner, not as
part of the current standard CI job.

## Privileged test scope

The unit tests for key format/keypair agreement run in ordinary CI and need no
privileges. They do not execute the provisioner against the host filesystem or
verify installed UID/GID/modes. Running `viper-seed-keygen` itself requires
root. A future filesystem-provisioning integration test and the full
`viper-server` + provider + SQLite process test require root plus distinct
service UIDs; run them locally in an isolated environment or on a dedicated
privileged runner. Standard CI currently covers the separate cross-UID IPC
tests, but does not claim to run those provisioning or full process tests.

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

The provider process can be started with the inherited credential on file
descriptor 3 (the descriptor must contain exactly the v2 key record defined in
the protocol; never put the private key in argv or environment):

```sh
viper-seed-provider \
  --runtime-dir /run/viper-seed \
  --socket /run/viper-seed/seed.sock \
  --client-uid 990 \
  --credential-fd 3 \
  3</run/credentials/viper-seed-signing-key
```

For manual starts, the runtime directory must already exist, be provider-owned,
non-writable by group/other, and traversable by the dedicated IPC group. The
provider will not remove stale socket paths at startup. It checks the received Tool Guard evidence
against its own loaded policy before signing a decision. This initial provider
is deliberately policy-backed: it is not an LLM, does not execute tools, and
does not claim an independent semantic SEED decider. Rotation orchestration
and a broader provider decision engine remain follow-up work. Do not expose this
loopback API through a reverse proxy before the separate authenticated
remote-API design exists.
