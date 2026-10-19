# ADR-0006: Separate committed receipts from single-use execution permits

- Status: accepted
- Date: 2026-10-18
- Specification: `VIPER-SPEC-2.0`

## Context

The executor must never start a side effect before the authorizing trajectory state is durable.
Returning `Result<()>` or a plain `HashedEvent` from the database would leave that ordering rule in
documentation: neither type proves that SQLite completed `COMMIT`. A Rust-only non-cloneable token
would improve local ordering, but would not stop replay by another process or after a crash.

## Decision

`viper-db::LedgerAppender::append` returns an opaque `CommittedEvent`. Its constructor is private to
`viper-db`, and the writer creates it only after the transaction's `COMMIT` succeeds. Failed or
rolled-back batches return no receipt. The receipt exposes committed event evidence but is not an
execution authority.

Phase 2 will introduce an opaque `ExecutionPermit` with all of these properties:

- it is created only from the required committed verdict and, when applicable, committed human
  approval;
- it binds the proposal ID, normalized tool and argument digest, policy digest, decision and
  approval event sequence/hash, expiry, and a unique permit ID;
- it implements neither `Clone` nor `Copy`, nor `Serialize`/`Deserialize`, and the executor consumes
  it by value;
- immediately before process creation, the executor atomically claims the permit in SQLite. The
  durable claim has a uniqueness constraint on the permit ID and is committed with the
  `tool_execution` transition. An existing claim denies execution.

The permit constructor remains private to the authorization composition boundary. Phase 1 does not
define the permit yet because it has no executor and must not expose a misleading authority type.

## Consequences

- Rust rejects passing an uncommitted `HashedEvent` where committed evidence is required.
- Rust ownership rejects ordinary in-process double use of an `ExecutionPermit`.
- The durable unique claim closes replay across processes, restarts, and crash recovery; ownership
  alone cannot provide that guarantee.
- `CommittedEvent` deliberately remains insufficient to call the executor, preventing every
  trajectory append from becoming implicit authority.
- Phase 2 must test compile-fail misuse, duplicate claims, concurrent claims, expiry, argument
  substitution, crash-before-claim, crash-after-claim, and restart recovery before enabling spawn.
