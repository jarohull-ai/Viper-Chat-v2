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
   The current hash-chain design makes linked observation metadata durable, so
   the ledger representation must be redesigned (for example, unlinkable
   salted commitments plus expiring rows) before collection is enabled.
4. **Labeling:** no labels are collected or inferred today. A later workflow
   must use human review, record reviewer/label provenance separately, support
   correction, and keep development and holdout labels segregated. Do not use
   holdout labels to tune thresholds.
5. **Access and export:** define who can read observations, how they are
   exported, and how access is audited before any operational collection.

These safeguards reflect the GDPR principles of data minimisation and storage
limitation. Consent is one possible lawful basis, not a universal substitute
for determining the controller's obligations and providing the required
information. Deployment-specific legal review remains necessary. See
[GDPR Article 5](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32016R0679)
and [Article 6](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32016R0679).
