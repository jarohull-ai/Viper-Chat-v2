//! Standalone comparison of durable single-event and batched `SQLite` commits.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};
use tempfile::tempdir;
use tokio::runtime::Builder;
use viper_db::{LedgerConfig, TrajectoryDb};
use viper_trajectory::{EventInput, EventKind};

const PRODUCERS: usize = 20;
const EVENTS_PER_PRODUCER: usize = 50;

fn main() {
    if cfg!(debug_assertions) {
        println!("ledger benchmark skipped outside optimized cargo bench profile");
        return;
    }
    let runtime = Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("benchmark runtime must start");
    runtime.block_on(async {
        run_scenario("single_commit", 1).await;
        run_scenario("batch_10", 10).await;
    });
}

async fn run_scenario(name: &str, max_batch_events: usize) {
    let directory = tempdir().expect("benchmark temporary directory must exist");
    let path = directory.path().join(format!("{name}.db"));
    let database = TrajectoryDb::open(
        &path,
        LedgerConfig {
            max_batch_events,
            max_batch_delay: Duration::from_millis(10),
            ..LedgerConfig::default()
        },
    )
    .await
    .expect("benchmark database must open");
    let started = Instant::now();
    let mut workers = Vec::new();
    for producer in 0..PRODUCERS {
        let appender = database.appender();
        workers.push(tokio::spawn(async move {
            for index in 0..EVENTS_PER_PRODUCER {
                let _ = appender
                    .append(EventInput {
                        id: format!("event-{producer}-{index}"),
                        trace_id: "benchmark-trace".into(),
                        occurred_at: "2026-10-18T18:00:00Z".into(),
                        kind: EventKind::ToolProposed,
                        detail: BTreeMap::from([
                            ("actor".into(), "benchmark-agent".into()),
                            ("command".into(), "cargo test --workspace".into()),
                        ]),
                    })
                    .await
                    .expect("benchmark append must commit");
            }
        }));
    }
    for worker in workers {
        worker.await.expect("benchmark producer must finish");
    }
    let elapsed = started.elapsed();
    let events = PRODUCERS * EVENTS_PER_PRODUCER;
    let elapsed_ms = elapsed.as_millis().max(1);
    let events_per_second = (events as u128 * 1_000) / elapsed_ms;
    database
        .shutdown()
        .await
        .expect("benchmark database must close cleanly");
    println!(
        "{name}: events={events} elapsed_ms={} events_per_second={events_per_second}",
        elapsed.as_millis()
    );
}
