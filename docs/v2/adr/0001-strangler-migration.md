# ADR-0001: Use vertical-slice strangler migration

- Status: accepted
- Date: 2026-10-18

## Decision

Keep Viper Chat v1.12.0 runnable and replace behavior in independently testable vertical slices.
The legacy application is a regression oracle, not a source tree to transliterate module by module.

## Consequences

- Each cutover has explicit parity and rollback criteria.
- TypeScript and Rust coexist temporarily.
- Adapters may add short-term work, but prevent a high-risk big-bang rewrite.
- A feature is not migrated until the whole path, including failure handling and observability, is
  owned by Rust.
