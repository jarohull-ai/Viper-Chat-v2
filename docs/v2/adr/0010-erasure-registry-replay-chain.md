# ADR-0010: Erasure Registry replay and digest chain

- Status: accepted for local implementation and adapter design; production
  validation remains pending
- Date: 2026-10-19
- Scope: append-only tombstone history and recovery from an older Registry
  snapshot; does not enable LID collection
- Depends on: ADR-0009

## Context

ADR-0009 defines an etcd quorum state store and an independent S3 Object Lock
archive. Its first contract compared sequence numbers and digests, but did not
define an archive enumeration/replay API or bind each event to its predecessor.
After restoring an older etcd snapshot, the Registry therefore could detect a
newer archive head but could not prove and apply the missing events. Sequence
equality alone also does not detect a fork or modified intermediate event.

No production Registry data has been collected. The local mock implementation
may evolve to the v2 event format without a data migration. Any deployment
that has persisted v1 Registry events must not silently reinterpret them as v2;
it requires an explicit migration and verification procedure.

## Decision

### Event format and digest chain

1. New events use protocol identifier `VIPER_ERASURE_TOMBSTONE_V2`. V1 events
   remain immutable and are never rewritten in place.
2. Every canonical JCS payload includes `registry_id`, contiguous `sequence`,
   random `operation_id`, random opaque `key_handle`, transition `state`, UTC
   `issued_at`, and lowercase-hex `prev_digest`. Sequence zero is reserved for
   the genesis checkpoint, whose digest is 32 zero bytes. The first event has
   sequence 1 and that genesis digest as `prev_digest`.
3. The Ed25519 signature covers the RFC 8785 canonical UTF-8 payload with the
   v2 domain prefix `VIPER-ERASURE-TOMBSTONE-V2\0`. Reject unknown/revoked key
   IDs, malformed or non-canonical payloads, duplicate JSON keys, invalid
   digests, and invalid signatures.
4. Define an event digest as:

   ```text
   SHA-256(
     "VIPER-ERASURE-CHAIN-V2\0" ||
     uint64_be(payload_length) || canonical_payload ||
     uint64_be(signature_length) || signature
   )
   ```

   The `prev_digest` in event N must equal the digest of event N-1. The digest
   includes the signature, so changing either signed content or signature
   changes the chain. Never accept a gap, duplicate sequence with different
   bytes, alternate predecessor, or fork.
5. Checkpoints are `(registry_id, sequence, digest)` values derived only from a
   verified contiguous event chain. A checkpoint is an upper watermark for a
   replay read, not independent proof that its event body is valid. The archive
   adapter must retrieve and verify the exact retained object versions behind
   that watermark.

### Archive replay API

The archive contract exposes a bounded, paginated read equivalent to:

```text
read_events(after: Checkpoint, through: Checkpoint, cursor: Option<Cursor>)
  -> ReplayPage { through, events, next_cursor }
```

- `after` is the caller's verified local etcd head; `through` is captured once
  from the archive's latest verified checkpoint and remains fixed across every
  page in that replay attempt.
- Events are ordered by sequence and include the complete signed event bytes,
  exact object version, and verified event digest. A page cannot silently skip
  a sequence or return an event outside `(after.sequence, through.sequence]`.
- An empty page before reaching `through`, a cursor loop, duplicate/conflicting
  sequence, inaccessible object version, missing retention metadata, or
  signature/digest/chain mismatch is an integrity failure and keeps readiness
  false. Do not treat object listing order as event order; parse and verify the
  sequence, predecessor, and digest.
- The S3 implementation lists versions under a fixed registry prefix, reads
  exact version IDs, and verifies each object is locked in COMPLIANCE mode for
  at least the configured retention. The runtime role cannot delete versions,
  shorten retention, or change bucket lock/versioning configuration.

### Restore and replay state machine

1. Startup, snapshot restore, or site promotion begins with readiness false and
   observation decryption denied.
2. Reconcile etcd's durable `deletion_pending` operations first. Complete their
   idempotent archive write/finalization; never reopen a key whose delete gate
   was durably closed.
3. Read the local etcd head and latest verified archive checkpoint. If etcd is
   ahead of the archive, or both report the same sequence with different
   digests, stop fail-closed and alert; do not rewrite either history.
4. If the archive is ahead, page from the etcd head through the captured
   archive checkpoint. Verify every event's signature, canonical form,
   digest, sequence, registry ID, and predecessor before applying it.
5. Apply each replayed event with a quorum-backed compare-and-swap requiring
   the current etcd head to equal the event's `prev_digest` and preceding
   sequence. Applying identical bytes twice is idempotent; conflicting bytes
   for a sequence are fatal. Replayed `pending` events deny decrypts;
   `confirmed` events mark the handle permanently deleted. A missing key record
   is not recreated as active.
6. Re-read both heads after replay. Readiness is allowed only when they agree
   exactly, all transitions are resolved, and every eligible site is caught up.
   If the archive advanced during replay, repeat from the new local head to the
   new watermark before opening readiness.

No decrypt path may use cached `active` state during replay, partition, stale
checkpoint, or uncertain site promotion. Reconciliation errors leave readiness
false and preserve already applied tombstones.

## Required local tests

The mock-level suite must cover:

1. Restore etcd to sequence N, archive is at N+K: replay all K events in order,
   reach the same final digest, and keep erased handles denied.
2. Missing tombstone within the reported archive watermark: refuse readiness;
   do not skip the gap. When the exact event becomes available, replay is
   idempotent and reaches the checkpoint.
3. Modified event bytes, signature, digest, or `prev_digest`: reject before
   applying the event and keep readiness false.
4. Duplicate identical replay: no second logical state transition. Duplicate
   sequence with different bytes: permanent integrity failure.
5. Archive watermark changes while paging: finish only to the captured
   watermark, then fetch and reconcile the newer watermark before readiness.

These tests establish orchestration logic only. They do not establish etcd
quorum, S3 Object Lock behavior, IAM isolation, snapshot durability, or
replication behavior.

## Consequences

- Restore no longer depends on etcd retaining the latest tombstone: S3 is the
  replay source for missing immutable events, while quorum-backed etcd remains
  the online authorization store.
- Replay can be bounded and resumed with cursors, but the implementation must
  retain a trusted anchor checkpoint and verify continuity from it. A digest
  chain cannot by itself prove completeness if both the anchor and archive are
  rolled back together; independent account, IAM, retention, and recovery
  controls remain necessary.
- The v2 payload adds a predecessor digest and changes its domain/version.
  Signing keys need verification-key rotation rules that preserve historical
  verification for all retained events.
- Production collection remains disabled until real three-node etcd,
  Object-Lock, snapshot-restore, and failover tests pass for the exact deployed
  versions and topology.

## References

- [RFC 8785: JSON Canonicalization Scheme](https://www.rfc-editor.org/rfc/rfc8785)
- [etcd disaster recovery and snapshot restore](https://etcd.io/docs/v3.7/op-guide/recovery/)
- [Amazon S3 Object Lock](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html)
- [MinIO Object Locking](https://min.io/docs/minio/linux/administration/object-management/object-retention.html)
