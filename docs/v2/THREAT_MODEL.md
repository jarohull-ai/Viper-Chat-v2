# Viper Chat v2 threat model

Status: reviewed for Phase 2 IPC v2; updated 2026-10-19.

## Protected assets

- Integrity of SEED verdicts and their binding to the exact proposal and Tool Guard evidence.
- Provider Ed25519 signing private key and policy/configuration integrity.
- Durable trajectory confidentiality, integrity, and hash-chain continuity.
- Host files, credentials, and processes that a future sandbox executor may access.

## Trust boundaries

1. **HTTP caller → `viper-server`:** requests are untrusted. Strict schemas, size bounds, loopback
   binding, durable proposal-before-decision recording, and fail-closed errors apply. Remote access
   and user authentication are not part of this slice.
2. **`viper-server` → SEED provider:** processes use distinct service UIDs and a narrowly shared Unix
   socket group. Kernel peer credentials authenticate the local peer identity. The provider alone
   holds the Ed25519 private key; the server holds only an administrator-pinned public key bundle.
   The provider signs a transcript binding the full canonical request digest, proposal ID, session,
   both nonces, verdict, and sanitized reason.
3. **SEED provider → decision implementation:** the provider's evaluator is trusted to compute the
   decision. Missing, malformed, timed-out, or failed evaluation is VETO. The provider is the
   trusted computing base for decision correctness.
4. **Application → SQLite ledger:** writes are serialized and committed before receipts are
   returned. Reads verify the hash chain. A local attacker with write access to the database can
   deny service; the hash chain detects alteration but is not an external immutable anchor.
5. **Future executor → host:** no executor exists in the current slice. A future executor must
   revalidate a durable non-cloneable permit immediately before spawn and run inside the sandbox.

## Compromise analysis

- A compromised `viper-server` can submit arbitrary proposals, cause denial of service, and suppress
  HTTP responses. It cannot manufacture a valid provider signature or alter an authenticated
  provider result without detection. The provider independently validates peer UID and request
  bounds. A server compromise is therefore not equivalent to provider compromise.
- A compromised provider can issue false signed decisions. The provider UID and private signing
  descriptor must be isolated; provider compromise requires immediate key revocation and audit.
- A compromised root account, kernel, service manager, provider signing process, or signing key
  provisioning channel is outside the protection offered by IPC signatures.
- Running both processes under the same UID is development-only; same-UID compromise can undermine
  process-memory and descriptor isolation and does not satisfy provider-only custody.
- Public-key bundle replacement can redirect trust. It is public data but integrity-critical, so
  its file and parent directories must be root-owned and not writable by group/other users.

## Fail-closed requirements

Protocol downgrade, unknown/expired/revoked key, invalid Ed25519 signature, request-digest or ID
mismatch, UID mismatch, unsafe socket metadata, malformed/oversized frame, timeout, provider
unavailability, and ledger failure must never yield `APPROVED`. IPC v1 has no production fallback.
The executor must not be built until the cross-UID end-to-end and failure matrix is green.
