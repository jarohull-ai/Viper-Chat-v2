# ADR-0003: `viper-seed` owns the Viper decision boundary

- Status: accepted
- Date: 2026-10-18
- Specification: `VIPER-SPEC-2.0`

## Context

The local `seed-core` 0.1.6 contains useful concepts but also a fail-open unknown-profile path, a
non-functional repetition guard, non-durable ad-hoc audit hashing, incomplete enforcement coverage,
and a license requiring a recorded commercial decision. Treating `viper-seed` as a temporary
wrapper would put those defects on the Phase 1 critical path and make ownership of the final verdict
ambiguous.

## Decision

`viper-seed` is the permanent Viper-owned Tool Guard, provider boundary and verdict composer. It
does not link or spawn `seed-core` 0.1.6. Unavailable or invalid providers fail closed.

`seed-core` may be repaired and released independently. A future version can be admitted only as an
optional external provider behind `viper.seed.ipc.v1`, after protocol, security, concurrency,
license and provenance gates. It cannot replace or bypass Viper's policy composition, trajectory or
human-approval boundary.

## Consequences

- Phase 1 can finish without waiting for `seed-core` repairs.
- Provider replacement does not alter Viper's final-decision semantics.
- Some policy concepts may temporarily exist in both projects, but their ownership is explicit.
- Future `seed-core` admission requires a new acceptance ADR; matching names or APIs are
  insufficient.
