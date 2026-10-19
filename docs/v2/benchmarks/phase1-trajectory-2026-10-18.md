# Phase 1 trajectory benchmark — 2026-10-18

These are local engineering measurements, not product-wide performance guarantees.

## Environment

- CPU: AMD Ryzen 5 5500, 6 cores / 12 threads, SHA-NI available
- OS: Linux 7.0.0-38-generic x86_64
- Rust: 1.97.1
- `sha2`: 0.11.1
- `sqlx`: 0.9.0 with bundled SQLite, WAL and `synchronous=FULL`
- Profile: optimized `cargo bench`

## Commands and results

```text
cargo bench -p viper-trajectory --bench trajectory_hash
sha256_512b: 1,000,000 iterations; 294 ms; 294 ns/hash
canonical_event: 100,000 iterations; 136 ms; 1,369 ns/event

cargo bench -p viper-db --bench ledger_write
single_commit: 1,000 events; 516 ms; 1,937 events/s
batch_10: 1,000 events; 88 ms; 11,363 events/s
```

## Decision

SQLite durability dominates canonical hashing on this host. Keep `sha2` default runtime hardware
detection and optimize transaction count. Adopt a bounded default batch of 10 events / 10 ms with
post-COMMIT acknowledgement. Re-run on every supported architecture before changing defaults.
