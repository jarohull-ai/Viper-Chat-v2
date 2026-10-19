# ADR-0005: Rotate SEED IPC HMAC keys with bounded overlap

- Status: accepted
- Date: 2026-10-18
- Specification: `VIPER-SPEC-2.0`

## Context

HMAC is symmetric authentication. Replacing a key atomically without overlap disconnects healthy
sessions, while accepting an old key for arbitrary new sessions extends the value of compromised
material. Wall-clock-dependent tests also make boundary behavior ambiguous.

## Decision

Maintain one `ACTIVE` key and optional `RETIRING` keys identified by stable `key_id`. Rotation:

- signs every new session with `ACTIVE`;
- allows a `RETIRING` key only for a session registered before rotation;
- uses an exclusive, injected epoch boundary capped at 300 seconds;
- binds protocol, key ID, session ID, peer role and both 32-byte nonces into HMAC-SHA-256;
- rejects replayed live session IDs;
- zeroizes in-memory secrets on replacement/drop;
- immediately rejects a `REVOKED` key and advances a revocation epoch so live channels can close.

New secret material is provisioned outside the protocol through an inherited descriptor or OS
credential facility. Emergency compromise uses revocation with no grace period. Failure leaves the
adapter unready and all decisions fail closed.

## Consequences

- Healthy established sessions can finish during planned rotation.
- Possession of a retiring key cannot establish a new session.
- Rotation/revocation time is explicit input, preserving deterministic tests.
- This does not claim asymmetric authentication. Adding public-key identity later requires a new
  protocol version and ADR.
