# ADR-0002: Build the decision gate before execution

- Status: accepted
- Date: 2026-10-18

## Context

An alternative first slice was message validation and sanitization. It is simpler, but does not
establish the product's primary trust boundary. A supervised Gemma review through VIPER WISPER also
recommended the decision/audit slice for risk reduction and testability.

## Decision

The first Rust slice covers:

`tool proposal -> Tool Guard -> SEED boundary -> composed verdict -> SHA-256 trajectory`

It exposes no execution function. VETO outranks escalation, escalation outranks approval, and SEED
failure produces VETO.

## Consequences

- Security semantics become executable before process spawning exists.
- Existing v1.12 Tool Guard cases can become differential fixtures.
- The external SEED implementation remains replaceable behind a narrow trait.
- Durable SQLite storage and actual sandbox execution are deliberately deferred to later slices.
