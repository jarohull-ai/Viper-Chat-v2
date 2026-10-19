# ADR-0004: Batch trajectory writes without acknowledging volatile events

- Status: accepted
- Date: 2026-10-18
- Specification: `VIPER-SPEC-2.0`

## Context

The global trajectory chain serializes event order by design. Benchmarking on the Phase 1 reference
host showed that SHA-256 is not the limiting operation: a 512-byte SHA-256 took about 294 ns and a
complete canonical event about 1,369 ns, while durable SQLite commits were orders of magnitude
slower. Enabling a nonexistent `sha2 0.11.1` `asm` feature would not help; this version already uses
runtime CPU feature detection and selected hardware acceleration where available.

## Decision

Use one bounded writer that groups at most 10 events or waits at most 10 ms after the first queued
event. It writes the batch with `BEGIN IMMEDIATE`, advances the durable head in the same transaction,
and acknowledges each caller only after COMMIT. The acknowledgement is an opaque
`CommittedEvent`, not a plain in-memory event. Queue saturation applies backpressure. A future
executor must receive a distinct `ExecutionPermit` derived from the required committed evidence
before crossing the side-effect boundary, as specified in ADR-0006.

The values are defaults, not permanent performance claims. Changes require the same durability and
concurrency tests plus a benchmark record on supported hardware.

## Consequences

- The chain remains globally ordered and crash-consistent.
- Concurrent producers share fsync cost; the reference benchmark improved from about 1,937 to
  11,363 events/second for 1,000 events.
- A slow COMMIT delays its batch, so queue depth and commit latency must be observable.
- No caller may interpret successful queue admission as durable acceptance.
