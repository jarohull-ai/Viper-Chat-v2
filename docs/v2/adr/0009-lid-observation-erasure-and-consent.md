# ADR-0009: Erasable LID observations and collection gate

- Status: proposed; requires product-owner and deployment-specific privacy review
- Date: 2026-10-19
- Scope: future LID observations only; no provider integration or collection enabled

## Context

Migration `0003_lid_observations.sql` stores LID metadata in SQLite and also
appends the values and a source-event reference to the append-only trajectory
chain. Those fields are durable and linkable. Deleting only the SQLite row
cannot erase the ledger copy, while changing an old event would break the hash
chain. The current write API is suitable only for controlled local engineering
experiments, not real-user collection.

## Decision (proposed)

1. Keep collection disabled by default. Do not connect the provider or accept
   real-user observations until schema, notice/consent UX, retention, deletion,
   backup handling, access controls, and labeling have passed review and tests.
2. Replace plaintext observation writes with a separately erasable payload.
   Generate a random data-encryption key (DEK) per observation and encrypt the
   complete potentially linkable record using authenticated encryption. This
   includes LID, neighbor count, timestamps, model/corpus identities, source
   references, and later annotations. Keep DEKs in a dedicated key service or
   OS key store with explicit backup semantics; never store plaintext DEKs in
   SQLite, trajectory events, logs, ordinary backups, or repository files.
3. The immutable trajectory may contain only a schema/version identifier and
   ciphertext (or a commitment to its exact bytes). It must not contain
   plaintext LID, user/workspace/source-event identifiers, labels, or a stable
   key/subject identifier. Encrypting the payload while leaving linkable
   metadata in the chain is insufficient.
4. On revocation or retention expiry, first disable future writes for the
   workspace. Then destroy the DEK in every authorized key-service replica,
   delete ciphertext/index rows, and append a minimal erasure audit event
   without identity or observation link. Because the chain hashes immutable
   ciphertext, it remains verifiable without rewriting history. Deletion must
   also cover replicas, exports, WAL/journal files, crash dumps, and backup
   expiry or crypto-erasure behavior.
5. Treat key destruction as a technical mechanism, not a blanket guarantee of
   legal erasure or GDPR compliance. Verify keys cannot be recovered from
   key-store backups, snapshots, replicas, swap, logs, or recovery procedures.
   Minimize metadata even when encrypted.
6. Product collection is off unless an authorized user has received clear
   notice and explicitly enabled it for the workspace and purpose. Version the
   notice/purpose, record the authorization separately from observation
   payloads, and make revocation stop writes immediately. Opt-in is an
   engineering safeguard; the appropriate lawful basis and controller duties
   need deployment-specific review.
7. Do not infer labels from LID. If introduced, labels must be human-reviewed,
   correctable, and carry label-schema/review provenance and confidence. Keep
   development and holdout sets segregated. Do not copy prompts/completions to
   the LID store; source-content review needs a separate authorization, access,
   and deletion policy.

## Key lifecycle and backup policy (proposed)

- **Store decision:** reject application-managed SQLite as the production key
  store. `viper-db` may hold ciphertext and non-sensitive indexes only; key
  material and any wrapped DEKs must remain in a separately administered key
  service. `zeroize` is defense-in-depth for transient in-process key buffers,
  not a persistence/deletion mechanism. Define a narrow Rust `KeyStore`
  interface and keep the concrete provider replaceable. Select HashiCorp Vault
  Transit as the first production-backend candidate: use one non-exportable
  Transit key per observation, encrypt/decrypt inside Vault, and address keys
  only by random opaque IDs. Vault documents deletion of a named Transit key,
  but this is not yet accepted as sufficient erasure: a restore of an older
  Vault snapshot must not resurrect a deleted key. Production enablement is
  blocked until anti-rollback deletion tombstones, backup/replica behavior,
  scale, and restore tests are implemented and pass. Until then, use only an
  ephemeral in-memory test implementation and keep collection disabled.
- **Hardware option assessment:** do not select YubiHSM 2 as the per-observation
  key store. Yubico documents a maximum of 256 stored objects per device, which
  is too small for one durable key object per observation at useful scale; its
  documented wrapped-object backup/restore also means deletion must account
  for exported copies. SoftHSM is a software emulator, not evidence of physical
  HSM protection. A later deployment may use Vault with an HSM-backed seal or
  another KMS, but must pass the same per-observation erasure and restore suite.
- **Custody:** run Vault under a separate service identity and network policy.
  `viper-server` receives only an operation-scoped capability for encrypting
  or decrypting the observation; the Transit key is never exported to the
  application. The key service holds the per-observation DEK as an individually
  deletable object. If a later backend uses envelope encryption, wrapped DEKs
  must remain only inside that backend's deletion domain—not in SQLite,
  trajectory, or ordinary backups—unless every backup copy can be reliably
  purged or cryptographically invalidated. A generic OS keyring is not
  interchangeable with this contract without proving equivalent semantics.
- **Availability during retention:** keys must survive ordinary process and
  host restarts for the approved retention period. Replication/backup may be
  used for availability only if every copy is under the same deletion control
  and has a documented inventory. A recoverable backup copy means the
  observation is not cryptographically erased. No key material may be backed
  up into the SQLite backup or general system backup independently of that
  control.
- **Rotation:** separate key-encryption-key (KEK) rotation from per-observation
  DEK lifetime. If envelope encryption is used, rotation re-wraps DEKs under a
  new KEK and retains the old KEK only for a bounded, documented migration
  window. Erasure must remove/destroy the individual DEK or all of its wrapped
  copies, not merely rotate the KEK. Keep a versioned key ID in the private
  key-service index, not the trajectory. Do not rewrite historical ledger
  events during rotation.
- **Early deletion and error handling:** key deletion is a terminal state; do
  not provide an operator “restore deleted key” path. Before the irreversible
  deletion step, validate the observation's retention/authorization state,
  target key handle, and complete copy inventory. Use an idempotent deletion
  workflow with a durable state machine (`active` → `deletion_pending` →
  `destroyed` → `ciphertext_purged`). An interrupted workflow resumes safely;
  failure to prove all key copies destroyed leaves collection disabled and
  raises an alert. This is an operational safeguard, not a reason to retain a
  withdrawn key against the applicable policy.
- **Backup restore:** database backups may contain ciphertext, never a DEK or
  a wrapped DEK recoverable with a surviving KEK. A restore must reconcile
  each encrypted row with the key service; missing/destroyed keys yield an
  explicit permanently-unavailable record, never regenerated keys or fallback
  plaintext. Key-service backups, if any, must preserve deletion tombstones so
  restoring an older snapshot cannot resurrect a destroyed key. Define backup
  expiry and test restore from snapshots predating deletion.
- **Audit:** record aggregate counts and operation outcomes without stable
  observation/workspace identifiers or plaintext key IDs. Restrict key
  administration, require separate authorization for manual destructive
  operations, and audit access to the key service. Retention-triggered deletion
  remains automated and must not wait indefinitely for an operator.

## Migration and acceptance criteria

- Mark the current `viper-db` observation API and migration `0003` as
  prototype-only; provider code must not call them for real traffic.
- Add a new schema/API that writes encrypted payloads plus non-linking
  commitments. Do not rewrite prior trajectory events to simulate deletion.
- Test that DEK deletion makes payload recovery fail, observation deletion
  leaves the chain verifiable, and no plaintext or stable linkage appears in
  ledger rows, logs, exports, or error messages.
- Test revocation, expiry, interrupted deletion, key-store failure, backup
  restore from a pre-deletion snapshot, key rotation during retention, and
  idempotent retry. Verify that a deleted key is absent from every configured
  replica and restore path and that authenticated decryption fails after
  deletion. Failure to destroy keys or complete purge
  keeps collection disabled and raises an operational error.
- Define and test retention durations and backup expiry before enabling
  collection. The profile below is an engineering proposal, not approved policy.

## Retention decisions and local profile

- **Provisional engineering profile (selected for design/testing only):**
  Vault/etcd backups and snapshots are retained for at most 90 days; a replica
  may lag by at most 7 days; restore/failover must finish within 7 days; and a
  provisional 16-day safety margin is added to round the proposed retention to
  a **120-day minimum** WORM period (`90 + 7 + 7 + 16`). The 16-day margin is a
  planning assumption, not a measured recovery bound. This is not an approved
  business or privacy policy and does not enable collection. The 7-day
  replication limit must be enforced and tested; if any backup copy lags
  longer, or if recovery
  takes longer, calculate the tombstone period from the actual maximum instead
  and extend it. Any backup with unbounded retention means tombstones cannot
  safely expire.
- **Observation payload:** propose a maximum retention of 90 days from
  collection, with earlier key destruction on an accepted erasure request.
  This is likewise a proposal, not approved policy. The product
  owner/controller must approve the purpose, duration, and lawful basis after
  privacy review; until then collection stays off.
- **Tombstone/archive:** retain the minimal tombstone and its checkpoint for
  at least the computed interval above, then expire it only after confirming
  no corresponding pre-deletion backup is restorable. Do not set Object Lock
  Compliance retention until backup, replication, and restore maxima are
  approved: Compliance retention cannot be shortened once applied. Tombstones
  contain only a random opaque key handle, monotonic sequence, protocol/state
  version, and signed event digest; omit user/workspace IDs, content, LID,
  source-event links, and unnecessary timestamps. Reassess whether the opaque
  handle remains linkable data and whether the duration is appropriate before
  collection.
- **Change control:** if a future deployment lengthens backup retention,
  replication lag, or restore windows, the tombstone expiry must be recalculated
  before that configuration is activated. Never shorten an existing locked
  tombstone's retention or claim it is safe to expire based only on the nominal
  backup policy; verify every replica, archive copy, and recovery path.
- **Local-only candidate:** MinIO with object locking/versioning is the
  proposed self-hosted WORM alternative to S3, not yet approved. The bucket
  must be created with locking enabled; if replicated, both source and target
  buckets must have object locking enabled and TLS must protect replication.
  MinIO documents that replication decrypts on the source and transmits over
  the network before the target re-encrypts; the replication path is therefore
  inside the trusted boundary and must use authenticated TLS.
  The MinIO archive must be outside the etcd/Vault backup rollback and
  administrator domains (a second path on the same host is insufficient).
  Run the full S3-compatible conformance suite against the exact MinIO version
  and deployment topology; compatibility claims do not substitute for these
  tests. Until it passes, local deployments keep collection disabled.

## Required Vault validation plan (not yet executed)

The Vault dev server is only a disposable adapter-test target. It cannot prove
snapshot recovery, replica deletion, production access control, or throughput
under the deployed topology. Run destructive recovery cases in an isolated
non-production network with disposable credentials and clusters; never restore
a test snapshot into production.

1. **Adapter and idempotency (dev/test Vault):** create an opaque per-record
   key, encrypt/decrypt a fixture, delete it, confirm decrypt fails, delete it
   a second time, and confirm the tombstone-backed result is idempotent
   `already_destroyed` (do not treat an arbitrary not-found response as proof
   that a previously valid key was destroyed). Confirm unknown IDs and
   Vault/network errors fail closed. This is
   the only tier a Vault dev server can establish.
2. **Snapshot anti-rollback (durable isolated Raft cluster):** create key and
   ciphertext, capture snapshot A, delete the key and persist a deletion
   tombstone in the Erasure Registry and its independent monotonic anchor, then capture
   snapshot B. Restore A into an isolated cluster. Before serving any request,
   replay all post-A tombstones and verify the key is absent and decryption
   fails. Also restore A without replay as a negative control: if the key
   returns, startup/readiness must remain blocked until tombstone reconciliation
   completes. Also restore the Registry from a snapshot predating the
   tombstone: the independent anchor must detect rollback and either replay the
   missing tombstone or keep the entire service unavailable. The tombstone
   source must be independently administered and
   outside the Vault snapshot/restore domain, with freshness verified so an old
   tombstone backup cannot silently roll back erasures. Restore B and confirm
   the deleted state remains. Test a crash at every deletion/reconciliation
   transition and idempotent replay.
3. **Replication and failover (only if the selected deployment uses it):**
   test the actual licensed topology. Vault Enterprise DR and performance
   replication are separately licensed features; Transit encryption keys are
   among replicated state. Create a key, wait for the documented replication
   barrier, delete on the primary, and verify deletion on every secondary and
   after DR promotion. During partition/lag, the system must not claim erasure
   complete or serve decrypts from a potentially stale secondary. If equivalent
   deletion guarantees cannot be demonstrated, disable replication for this
   key domain or reject this backend/topology for collection.
4. **Scale and recovery load:** first run a 1,000-observation smoke test for
   create/encrypt/decrypt/delete, measuring key count, latency, errors, and
   cleanup. This is plumbing evidence only—not production scale approval.
   Then load-test against an owner-approved target derived from peak observation
   creation rate, retained observations, deletion/expiry rate, and recovery
   objectives. Record Vault version/edition, topology, policies, hardware,
   sample size, p50/p95/p99 latency, throughput, errors, replication lag, and
   restore time. Reject the backend if target limits or deletion objectives
   are missed; do not infer scale from 1,000 records alone.

**Release gate:** attach sanitized logs/results and exact Vault version and
edition to the deployment evidence. All tiers applicable to the deployment
must pass, including restore and replica checks. A pass validates only that
tested configuration; it does not establish legal compliance or general
production readiness. Until then, provider collection remains disabled.

Registry-specific cases are also mandatory: (a) retry the same deletion through
every state transition and verify exactly one logical tombstone with an
idempotent terminal result; (b) partition the Registry quorum and verify no
delete is acknowledged as complete and all decrypts fail closed; (c) restore an
old Registry snapshot and verify the external checkpoint detects rollback; and
(d) attempt promotion of a Vault replica missing the latest tombstone and
verify it is quarantined before it can serve any request. Also test that
recovery after quorum returns replays every S3 tombstone without losing
unrelated active records, and that an S3 outage blocks decrypts and cannot
produce a false `confirmed` result. In a disposable AWS account, verify the
runtime role cannot delete/shorten a COMPLIANCE-locked object version, duplicate
sequence/object IDs are rejected, and restore of an older etcd snapshot replays
the S3 archive before readiness. The etcd/S3 profile is a concrete reference
choice, but the backend must meet these invariants before implementation is
accepted.

## Tombstone authority and replication contract (proposed)

**Reference product choice:** use etcd as the quorum-backed Erasure Registry
and Amazon S3 Object Lock as its independent WORM archive/checkpoint anchor.
This is a proposed deployment profile, not an implementation or a claim that
the products alone provide the required guarantees. It introduces an AWS
dependency; deployments requiring fully local/host-sovereign operation must
keep collection disabled until an alternative WORM backend passes the same
conformance suite.

The logical registry is a dedicated service over a three- or five-member etcd
cluster, separate from Vault storage and the observation database. Registry
events use monotonically increasing IDs and append-only create semantics;
application clients cannot access etcd directly. Since etcd RBAC is not itself
a create-only event-log guarantee, the Registry API enforces compare-and-create
transactions, while signed WORM copies detect attempted mutation or rollback.
The etcd snapshot is not the anti-rollback anchor: restore can roll the
keyspace/revision back, so restored instances must reconstruct and reconcile
from the WORM archive before serving.

The WORM archive is a separate general-purpose S3 bucket created with
Versioning and Object Lock enabled, in a separate security-administered AWS
account. Store a signed, sequenced tombstone event (or bounded ordered batch)
as a unique object version with **COMPLIANCE** retention. The runtime role may
create/read objects but cannot delete object versions, change retention, or
disable the archive. Retention must cover the longest-lived Vault/etcd snapshot
and backup plus the restore/recovery window; if backups have no bounded
expiry, the tombstone archive must remain available for that lifetime. The
archive stores only random opaque Vault-key handles, sequence and minimal
reconciliation metadata—never user/workspace IDs, prompts, LID values, or
source-event references. The opaque handle may still be linkable to encrypted
rows in old backups and must be treated as sensitive pseudonymous metadata.

S3 Object Lock protects object versions; a delete marker or a newer version
does not remove the old locked version. Compliance retention is intentionally
irreversible until expiry, so retention and data-minimization policy for these
minimal tombstones must be explicitly approved. S3 provides WORM behavior, not
an application-level append API; unique object names, signatures, sequence
checks, IAM restrictions, and duplicate detection are enforced by the Registry.

The Registry is authoritative for whether a key may be used. It must:

- commit tombstone appends to a quorum spanning every failover-eligible failure
  domain before acknowledging a deletion request;
- publish signed, monotonically numbered tombstone events/checkpoints to the
  Object-Lock archive outside both Vault and etcd snapshot rollback domains;
  after restore, verify archive freshness and replay every later tombstone
  before readiness;
- replicate the tombstone stream synchronously (or with an equivalent quorum
  guarantee) to every failover-eligible site. A site that is offline or behind
  is removed from the failover/read path until it has caught up;
- fail closed if the quorum, freshest checkpoint, or any eligible site's
  deletion state cannot be established. Operators cannot force readiness by
  acknowledging a stale snapshot.

Deletion has two externally visible stages: `pending` (access denied, purge in
progress) and `confirmed` (all eligible copies verified absent). The Registry
first closes the per-record decrypt gate and drains in-flight operations, then
durably appends the signed tombstone to S3 Object Lock and commits the matching
event to etcd quorum. Only after both durable writes may it acknowledge the
request as `pending`; a crash after the S3 write is recovered by replaying the
archive before readiness. If the WORM write fails, do not acknowledge the
request, keep observation decrypts fail-closed, and return a retryable error.
Then delete the named Transit key in the Vault primary; wait for
Vault's consistency mechanism and verify the key is absent on every
failover-eligible cluster; then mark the tombstone `confirmed`. If any step is
uncertain, keep the record inaccessible and deletion pending, alert, and retry.
Application access is denied immediately after the durable pending tombstone;
physical key removal is asynchronous. Do not report erasure complete until all
eligible Vault copies are confirmed absent. Direct Vault access is restricted
to the adapter identity and audited; every decrypt is serialized through the
Registry authorization path and may not use a cached `active` result. Vault
replication is eventually consistent and may serve stale reads, so a successful
primary delete alone is not sufficient evidence. If quorum or the WORM archive
is unavailable, fail closed for observation decrypts and leave deletion
unacknowledged/pending; never silently roll back to an `active` state.

On startup, restore, or promotion, the adapter must obtain the freshest signed
Registry checkpoint and reconcile tombstones before accepting decrypt requests.
If etcd quorum or the S3 archive is unavailable, stale, or inconsistent,
readiness stays false. If this deployment cannot provide the stated quorum,
anchor, and fail-closed routing, it must not enable collection or use Vault
replicas for this key domain.

**Quorum outage recovery:** during a partition without etcd quorum, no
tombstone write is acknowledged and all observation decrypts fail closed. When
quorum returns, the Registry compares the latest etcd sequence with the
highest signed S3 sequence, replays missing archive events idempotently, checks
that active non-erased records still have their corresponding Vault keys, and
only then restores readiness. A test must demonstrate that unrelated active
records remain decryptable after recovery while erased records remain
permanently unavailable. etcd's snapshot revision bump can prevent revision
numbers from appearing to go backward to watchers, but it does not restore
missing tombstone data; replay from S3 remains mandatory.

## Consequences and limitations

- The ledger proves an opaque encrypted record existed; the separately held
  key makes its contents erasable. Ciphertext size/timing can still leak
  metadata, so collection and event detail must be minimized.
- The current schema is not retroactively erasable. No real-user collection is
  authorized by this ADR.
- Cryptographic erasure, consent capture, retention, labeling, and lawful basis
  are distinct controls. Passing engineering tests is not a legal determination.

## References

- [GDPR Article 5: data minimisation and storage limitation](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32016R0679)
- [GDPR Article 6: lawful bases](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32016R0679)
- [GDPR Article 17: right to erasure and exceptions](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32016R0679)
- [SQLite `secure_delete` pragma](https://www.sqlite.org/pragma.html#pragma_secure_delete)
- [`zeroize` crate documentation](https://docs.rs/zeroize/latest/zeroize/)
- [Vault Transit key deletion API](https://developer.hashicorp.com/vault/api-docs/secret/transit)
- [Vault snapshot restore procedure](https://developer.hashicorp.com/vault/docs/sysadmin/snapshots/restore)
- [Vault replication requirements and Transit key replication](https://developer.hashicorp.com/vault/docs/enterprise/replication)
- [Vault replication consistency and stale-read behavior](https://developer.hashicorp.com/vault/docs/enterprise/consistency)
- [etcd disaster recovery and snapshot restore](https://etcd.io/docs/v3.7/op-guide/recovery/)
- [etcd role-based access control](https://etcd.io/docs/v3.5/op-guide/authentication/rbac/)
- [Amazon S3 Object Lock](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html)
- [Configuring S3 Object Lock](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock-configure.html)
- [MinIO Object Locking](https://min.io/docs/minio/linux/administration/object-management/object-retention.html)
- [MinIO bucket replication requirements](https://min.io/docs/minio/linux/administration/bucket-replication/bucket-replication-requirements.html)
- [YubiHSM 2 object capacity](https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-intro-core-concepts.html)
- [YubiHSM 2 backup and restore](https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-backup-restore.html)
