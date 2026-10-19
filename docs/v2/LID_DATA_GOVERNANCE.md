# LID observation data gate

Status: engineering gate; not a legal compliance determination.

## Current state

- Provider collection is disabled and no interaction data is currently collected.
- The model revision and artifact digests in `MODEL_BUNDLE_LOCK.json` are
  pinned for reproducible local experiments only. The 470 MB weights have not
  been downloaded or verified by this checkout; the runtime loader must verify
  every asset before use. This candidate is not production-approved.
- The database schema stores numeric LID and model/corpus metadata, but its
  `quality_gate` record is appended to the non-deleting trajectory hash chain.
  There is no retention purge, withdrawal, or deletion workflow. Therefore no
  real-user collection may be enabled yet.
- ADR-0009 proposes a separately erasable encrypted payload. It is not
  implemented or approved; the current migration/API remains prototype-only
  and must not be used for real traffic.

## Required gates before provider integration

1. **Notice and opt-in:** default off; require an explicit affirmative choice
   per workspace/project before recording any observation. The UI and
   revocation control do not exist yet. A product opt-in is an engineering
   safeguard, not a conclusion about the legally appropriate basis for every
   deployment.
2. **Purpose and minimization:** limit use to evaluating semantic geometry and
   later calibration. Store only LID, neighbor count, fixed model/corpus
   identities, timestamp, and the minimum linkage needed for audit. Never store
   prompts, completions, emails, embeddings, credentials, or inferred labels.
3. **Retention and withdrawal:** do not promise a duration until deletion is
   technically enforceable across the table, append-only ledger, backups, and
   exports. Ninety days is only a candidate for review, not the current policy.
   The current hash-chain design makes linked observation metadata durable. A
   proposal is per-observation authenticated encryption with separately held
   keys, no plaintext identifiers/metrics in the chain, and deletion by key
   destruction plus ciphertext/index removal. This needs implementation,
   recovery-path testing, and legal review; crypto-erasure is not itself proof
   of GDPR compliance. The key service must have documented custody, rotation,
   replica inventory, backup/tombstone behavior, and an idempotent deletion
   state machine; restoring a pre-deletion backup must never resurrect a key.
   Application-managed SQLite is rejected as a production key store; `zeroize`
   only protects transient memory and does not make SQLite files/backups erasable.
   Vault Transit is the selected reference backend candidate, not yet production-
   approved: per-observation keys must be deleted across replicas and must not
   reappear after restoring an older snapshot. YubiHSM 2 is not selected for
   per-observation keys because its documented capacity is 256 objects/device.
4. **Labeling:** no labels are collected or inferred today. A later workflow
   must use human review, record label-schema/review provenance, support
   correction, and keep development and holdout labels segregated. Do not use
   holdout labels to tune thresholds. Source-content review needs separate
   authorization, access controls, and a deletion policy; do not copy source
   text into the LID store for convenience.
5. **Access and export:** define who can read observations, how they are
   exported, and how access is audited before any operational collection.

These safeguards reflect GDPR principles of data minimisation and storage
limitation. Consent is one possible lawful basis, not a universal prerequisite
or a substitute for determining the controller's obligations and providing
required information. The right to erasure has conditions and exceptions.
Deployment-specific legal review remains necessary. See [GDPR Article 5
(principles)](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32016R0679),
[Article 6 (lawful bases)](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32016R0679),
and [Article 17 (erasure)](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32016R0679).

The detailed proposal and acceptance tests are in
[`adr/0009-lid-observation-erasure-and-consent.md`](adr/0009-lid-observation-erasure-and-consent.md).
