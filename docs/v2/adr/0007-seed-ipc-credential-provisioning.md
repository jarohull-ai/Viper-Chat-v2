# ADR-0007: Provision SEED IPC credentials outside the application

- Status: accepted
- Date: 2026-10-19
- Specification: `VIPER-SPEC-2.0`

## Context

`AuthKeyring` protects key bytes in process memory, but does not define how the first key reaches
the client and provider. A `.env` file or command-line argument can leak through backups, diagnostics,
process listings, or support bundles. An OS keychain is useful interactively, but is not uniformly
available to unattended services and CI.

## Decision

- Never load production IPC keys from `.env`, command-line arguments, protocol messages, or logs.
- Both IPC peers accept the shared HMAC key only from a dedicated inherited descriptor (or an
  equivalent OS service credential facility that exposes a private file/descriptor). Under the
  current symmetric protocol this means both `viper-server` and the SEED provider hold the same
  secret. `viper-seed` accepts one strict record:
  `VIPER_SEED_KEY_V1\\n<key-id>\\n<64 lowercase hex chars>\\n`, capped at 256 bytes.
  The descriptor is read once through EOF, validated as exactly one key record, then closed by the
  caller; parsed key bytes enter `AuthKeyring` and are zeroized on replacement/drop. The credential
  manager must provide a finite file-like descriptor and close-on-exec behavior for unrelated
  children.
- First-run provisioning belongs to an explicit install/setup operation, not server startup. It
  generates a CSPRNG 256-bit key and stores/delivers it through the OS credential facility with
  owner-only access. The setup operation must fail if that facility cannot establish the required
  ownership and permissions; it must not silently fall back to plaintext environment configuration.
- CI and tests inject ephemeral keys through private inherited descriptors. They do not reuse
  developer or production credentials.
- Rotation creates a new key through the same provisioning boundary, then supplies it to both peers
  before invoking the existing bounded `ACTIVE`/`RETIRING` transition. Emergency compromise revokes
  immediately and requires fresh provisioning. Application-level remote key export is prohibited.
- OS keychain integration may be an adapter to this boundary, not a separate protocol or mandatory
  dependency for headless deployments.

## Consequences

- This makes secret delivery explicit while keeping CI and headless services possible without
  pretending `.env` is a secure secret store.
- A production credential loader and first-run setup operation are required before a real provider
  can be considered ready. The strict loader is implemented; first-run setup/provisioning remains
  outstanding and is deferred with the production provider to Phase 2. Until then, only
  administratively provisioned descriptor credentials and ephemeral test keys are supported.
- Secret persistence, ownership, rotation coordination, and recovery must be tested against each
  supported service manager/OS. `zeroize` alone does not protect keys at rest or from a compromised
  process account.
- Provider-only key custody is not achieved by HMAC v1: either peer holding the key can forge the
  other's role. A future asymmetric protocol is required if the server must not hold provider
  signing material.
