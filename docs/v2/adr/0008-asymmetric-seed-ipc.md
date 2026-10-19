# ADR-0008: Provider-only signing custody for SEED IPC v2

- Status: accepted
- Date: 2026-10-19
- Supersedes: ADR-0007 shared HMAC provisioning for production IPC
- Protocol: `SEED_IPC_V2`

## Context

SEED IPC v1 uses the same HMAC secret at both peers. A compromised `viper-server` can therefore
forge provider authentication. Delivering the provider's signing secret to `viper-server` defeats
the intended process separation. Unix peer credentials also currently require both processes to
share one UID, so filesystem and key custody need to be separated together.

## Decision

- Replace production IPC v1 with `viper.seed.ipc.v2`; no implicit v1 fallback or downgrade.
- The SEED provider owns one Ed25519 signing private key. It receives that key only through a
  dedicated inherited OS credential descriptor. `viper-server` never receives private signing
  material.
- `viper-server` receives a pinned, versioned public-key trust bundle. It verifies provider
  signatures with strict Ed25519 verification. The provider's key ID, request digest, proposal ID,
  session ID, both nonces, verdict and sanitized explanation are signed together.
- Requests are authorized by a dedicated Unix IPC trust boundary, not by sharing the provider
  signing key: `viper-seed` and `viper-server` run as distinct service UIDs. The runtime directory is
  provider-owned and non-writable by its group; the socket grants access only to the dedicated IPC
  group. Each peer checks the other peer's configured UID with kernel credentials. Deployment under
  one UID is unsupported for production because same-UID processes can undermine process isolation.
- The response signature binds a canonical digest of the full typed decision request and fresh
  client/provider nonces, preventing response substitution and replay across requests. Canonical
  encoding and exact message order are specified in `protocols/SEED_IPC_V2.md`.
- Public-key rotation uses an explicit trust bundle with one ACTIVE key and zero or more RETIRING
  keys with an absolute expiry no more than 300 seconds ahead. New signatures use only ACTIVE.
  Expired or revoked keys fail closed. Emergency revocation removes the key and restarts/reloads the
  server trust bundle immediately. No key is fetched from the provider over the socket.
- The server's public trust bundle is an integrity-sensitive configuration file, not a secret. It
  must be provisioned through a trusted administrator/service-manager path and must not be
  group/world writable. The private signing descriptor remains provider-only.
- IPC failures, missing/unknown keys, invalid signatures, expired retiring keys, UID mismatch,
  malformed frames, and timeout all become recorded `VETO_DENIED`. Never fall back to v1 or a
  local permissive gate.

## Consequences

- Compromise of `viper-server` can submit requests but cannot forge an APPROVED provider response.
- Compromise of the provider can still issue forged decisions; the provider remains inside the
  trusted computing base and must be sandboxed and independently audited.
- Service deployment now requires separate UIDs, a narrow shared socket group, asymmetric key
  provisioning, and coordinated public-key rotation.
- The v1 implementation remains only as historical compatibility/test code until the v2 provider,
  client, cross-UID suite, and migration evidence pass. Production startup must fail if configured
  for v1.
