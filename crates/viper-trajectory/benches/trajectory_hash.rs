//! Standalone throughput comparison for raw SHA-256 and canonical trajectory construction.

use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::hint::black_box;
use std::time::Instant;
use viper_trajectory::{EventInput, EventKind, build_hashed_event};

const HASH_ITERATIONS: u64 = 1_000_000;
const EVENT_ITERATIONS: u64 = 100_000;
const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

fn main() {
    if cfg!(debug_assertions) {
        println!("trajectory benchmark skipped outside optimized cargo bench profile");
        return;
    }
    let payload = [0x5a_u8; 512];
    let hash_started = Instant::now();
    for _ in 0..HASH_ITERATIONS {
        black_box(Sha256::digest(black_box(payload)));
    }
    let hash_elapsed = hash_started.elapsed();

    let mut previous = GENESIS_HASH.to_owned();
    let event_started = Instant::now();
    for sequence in 0..EVENT_ITERATIONS {
        let event = build_hashed_event(
            sequence,
            &previous,
            EventInput {
                id: format!("benchmark-event-{sequence}"),
                trace_id: "benchmark-trace".into(),
                occurred_at: "2026-10-18T18:00:00Z".into(),
                kind: EventKind::ToolProposed,
                detail: BTreeMap::from([
                    ("actor".into(), "benchmark-agent".into()),
                    ("command".into(), "cargo test --workspace".into()),
                ]),
            },
        )
        .expect("benchmark fixture must be valid");
        previous = event.hash;
    }
    let event_elapsed = event_started.elapsed();

    println!(
        "sha256_512b: iterations={HASH_ITERATIONS} elapsed_ms={} ns_per_hash={}",
        hash_elapsed.as_millis(),
        hash_elapsed.as_nanos() / u128::from(HASH_ITERATIONS)
    );
    println!(
        "canonical_event: iterations={EVENT_ITERATIONS} elapsed_ms={} ns_per_event={} head={previous}",
        event_elapsed.as_millis(),
        event_elapsed.as_nanos() / u128::from(EVENT_ITERATIONS)
    );
}
