# SEED IPC v2 wire contract

- Protocol: `viper.seed.ipc.v2`
- Transport: Linux Unix stream socket
- Framing: unsigned 32-bit big-endian byte length followed by exactly one UTF-8 JSON value
- Maximum frame: 65,536 bytes
- Authentication: provider-signed Ed25519 decision response; kernel peer credentials authorize
  socket peers
- Downgrade: forbidden; v1 and v2 use distinct protocol identifiers and key material

All messages use strict schemas (`deny_unknown_fields`). Invalid UTF-8, empty/partial/oversized
frames, unknown fields, invalid enum values, trailing bytes, or signature failures terminate the
exchange and fail closed. Raw frames and signatures are never written to logs or trajectory.

## Process and socket boundary

Production runs `viper-server` and the SEED provider under distinct UIDs. The absolute runtime
directory is owned by the provider UID, has no group/world write permission, and is traversable by
the dedicated IPC group (typically mode `0750`). The socket is owned by the provider UID and grants
read/write only to that group (typically mode `0660`). The provider checks the connecting client's
configured UID; the client checks the provider's configured UID via kernel peer credentials. The
public-key bundle is provisioned to `viper-server`; the private signing descriptor is provisioned
only to the provider. Same-UID deployment is development-only and does not meet the custody claim.

## One-shot exchange

1. Client sends `client_hello`: `protocol`, random `session_id`, and fresh 32-byte `client_nonce`
   (lowercase hex).
2. Provider sends `server_challenge`: matching `session_id` and fresh 32-byte `provider_nonce`.
3. Client sends `decision_request`: matching `session_id`, `request_id`, `proposal_id`, `trace_id`,
   actor, RFC3339 timestamp, closed tool name, sorted string arguments, and Tool Guard
   action/rule/policy version/digest.
4. Provider evaluates the request and sends `decision_response`: matching request/proposal IDs,
   closed verdict, stable reason code, bounded sanitized explanation, `request_digest`, provider
   `key_id`, and 64-byte Ed25519 signature encoded as 128 lowercase hex characters.
5. Provider closes the stream. Any extra byte or second response invalidates the exchange.

There is no client HMAC and no provider private key at the client. The client's Unix UID is the
request authorization identity. This is intentionally a local IPC protocol, not a remotely
reachable API.

## Canonical digest and signature

The client and provider calculate `request_digest = SHA-256(canonical_request)`. Canonical request
bytes are a fixed domain separator `VIPER-SEED-IPC-V2-REQUEST\0`, followed by unsigned 64-bit
big-endian length-prefixed UTF-8 fields in this order: protocol, request ID, proposal ID, trace ID,
actor, timestamp, tool wire name, guard action, matched rule ID (empty when absent), policy version,
and policy digest. Then append a 32-bit big-endian argument count followed by each key/value pair in
lexicographic key order, each as a 64-bit length-prefixed UTF-8 field.

The provider signs a second canonical transcript beginning with
`VIPER-SEED-IPC-V2-RESPONSE\0`, then the 64-bit-length-prefixed protocol, key ID, and session ID;
the raw 32-byte client nonce, provider nonce, and request digest; then the 64-bit-length-prefixed
request ID, proposal ID, verdict wire name, reason code, and sanitized explanation. All values must
also match the original request before signature verification succeeds. The client uses strict
Ed25519 verification and compares the request digest it computed before sending.

## Public-key bundle and rotation

The provider gets one strict `VIPER_SEED_SIGNING_KEY_V2` record from an inherited private descriptor:
header, key ID, and 32-byte Ed25519 seed as 64 lowercase hex characters, each newline-terminated.
The descriptor is bounded, consumed once, closed, and temporary secret bytes are zeroized.

The server's public trust bundle is versioned JSON with schema `VIPER_SEED_PUBLIC_KEYS_V2`, exactly
one active key record, and zero or more retiring records (`key_id`, 32-byte public key in lowercase
hex, `accept_until_epoch`). Unknown fields, duplicate IDs, malformed points, more than 16 keys, or
retirement expiry beyond the 300-second grace ceiling are rejected. Active and unexpired retiring
keys verify; unknown, revoked, or expired keys do not. The trust bundle and its parent directory
must be root-owned regular file/directory objects not writable by group/other. Key rotation
provisions the new private key to the provider and the matching new public key as ACTIVE to the
server; the old public key is RETIRING
until the explicit deadline. Emergency rotation removes the old key immediately and restarts both
services. A failed/missing bundle is startup-fatal.

## Required tests

- Valid Ed25519 signature and strict rejection of modified message, non-canonical/invalid
  signatures, wrong key ID and malformed public keys.
- A recorded APPROVED response cannot be replayed for a fresh client nonce, another session,
  request ID, proposal ID, arguments, Tool Guard digest, or verdict.
- ACTIVE/RETIRING/expired/revoked key behavior at exact grace boundaries and duplicate key IDs.
- Real distinct-UID client/provider processes: allowed configured UIDs connect; mismatched UIDs,
  unsafe directory/socket modes, symlink substitutions and world/group-writable directory fail.
- Full HTTP → v2 IPC provider → SQLite integration verifies that the response follows durable
  ledger COMMIT; provider outage, invalid signature and timeout result in durable VETO.
