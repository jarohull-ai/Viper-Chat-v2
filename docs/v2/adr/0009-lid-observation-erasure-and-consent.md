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
  a wrapped DEK recoverable with a surviving KEK. A restore must reconcile each encrypted row with the key
  service; missing/destroyed keys yield an explicit permanently-unavailable
  record, never regenerated keys or fallback plaintext. Key-service backups,
  if any, must preserve deletion tombstones so restoring an older snapshot
  cannot resurrect a destroyed key. Define backup expiry and test restore from
  snapshots predating deletion.
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
  collection. The previously discussed 90 days remains a proposal, not policy.

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
- [YubiHSM 2 object capacity](https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-intro-core-concepts.html)
- [YubiHSM 2 backup and restore](https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-backup-restore.html)
