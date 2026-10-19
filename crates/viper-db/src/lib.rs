//! Durable `SQLite` persistence for Viper's global trajectory ledger.

use serde_json::from_str;
use sqlx::migrate::Migrator;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use sqlx::{Connection, Row, SqliteConnection, SqlitePool};
use std::collections::BTreeMap;
use std::path::Path;
use std::str::FromStr;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::{Instant, timeout_at};
use viper_trajectory::{EventInput, EventKind, HashedEvent, TrajectoryChain, build_hashed_event};

static MIGRATOR: Migrator = sqlx::migrate!("./migrations");
const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Stable persistence failure categories for service/API mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DbErrorCode {
    /// Configuration is internally inconsistent.
    InvalidConfiguration,
    /// `SQLite` or migration operation failed.
    Database,
    /// Canonical event construction or chain verification failed.
    Integrity,
    /// The bounded writer is not available.
    WriterUnavailable,
}

/// Sanitized database failure that can cross task boundaries.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{code:?}: {message}")]
pub struct DbError {
    /// Stable category.
    pub code: DbErrorCode,
    /// Sanitized operator detail.
    pub message: String,
}

impl DbError {
    fn database(error: impl std::fmt::Display) -> Self {
        Self {
            code: DbErrorCode::Database,
            message: error.to_string(),
        }
    }

    fn integrity(error: impl std::fmt::Display) -> Self {
        Self {
            code: DbErrorCode::Integrity,
            message: error.to_string(),
        }
    }

    fn writer_unavailable(message: &str) -> Self {
        Self {
            code: DbErrorCode::WriterUnavailable,
            message: message.to_owned(),
        }
    }
}

/// Opaque receipt proving that a trajectory event was acknowledged after `COMMIT`.
///
/// This is durability evidence, not authorization to perform a side effect. The future executor
/// will accept a separate, non-cloneable `ExecutionPermit` bound to committed decision evidence.
/// `CommittedEvent` has no public constructor, so callers cannot promote an in-memory
/// [`HashedEvent`] into a durable receipt.
#[derive(Debug, PartialEq, Eq)]
#[must_use = "a committed event receipt must be explicitly inspected or consumed"]
pub struct CommittedEvent {
    event: HashedEvent,
}

impl CommittedEvent {
    fn after_commit(event: HashedEvent) -> Self {
        Self { event }
    }

    /// Returns the committed trajectory event.
    #[must_use]
    pub fn event(&self) -> &HashedEvent {
        &self.event
    }

    /// Returns the event's durable global sequence.
    #[must_use]
    pub fn sequence(&self) -> u64 {
        self.event.sequence
    }

    /// Returns the committed event hash.
    #[must_use]
    pub fn hash(&self) -> &str {
        &self.event.hash
    }
}

/// Bounded writer and `SQLite` durability settings.
#[derive(Debug, Clone)]
pub struct LedgerConfig {
    /// Maximum pending append commands.
    pub queue_capacity: usize,
    /// Maximum events committed in one transaction.
    pub max_batch_events: usize,
    /// Maximum time the first event waits for batch peers.
    pub max_batch_delay: Duration,
    /// `SQLite` lock wait ceiling.
    pub busy_timeout: Duration,
    /// Maximum reader connections. The writer opens its own connection.
    pub max_read_connections: u32,
}

impl Default for LedgerConfig {
    fn default() -> Self {
        Self {
            queue_capacity: 1_024,
            max_batch_events: 10,
            max_batch_delay: Duration::from_millis(10),
            busy_timeout: Duration::from_secs(2),
            max_read_connections: 4,
        }
    }
}

impl LedgerConfig {
    fn validate(&self) -> Result<(), DbError> {
        if self.queue_capacity == 0
            || self.max_batch_events == 0
            || self.max_batch_delay.is_zero()
            || self.busy_timeout.is_zero()
            || self.max_read_connections == 0
        {
            return Err(DbError {
                code: DbErrorCode::InvalidConfiguration,
                message: "ledger limits must all be greater than zero".into(),
            });
        }
        Ok(())
    }
}

enum WriterCommand {
    Append {
        input: EventInput,
        reply: oneshot::Sender<Result<CommittedEvent, DbError>>,
    },
    Shutdown {
        reply: oneshot::Sender<()>,
    },
}

/// Cloneable producer for the single bounded ledger writer.
#[derive(Clone)]
pub struct LedgerAppender {
    sender: mpsc::Sender<WriterCommand>,
}

impl LedgerAppender {
    /// Waits for durable COMMIT acknowledgement for one event.
    ///
    /// # Errors
    ///
    /// Returns a fail-closed error when queueing, canonicalization or `SQLite` commit fails.
    pub async fn append(&self, input: EventInput) -> Result<CommittedEvent, DbError> {
        let (reply, response) = oneshot::channel();
        self.sender
            .send(WriterCommand::Append { input, reply })
            .await
            .map_err(|_| DbError::writer_unavailable("trajectory writer stopped"))?;
        response
            .await
            .map_err(|_| DbError::writer_unavailable("trajectory writer dropped acknowledgement"))?
    }
}

/// Durable ledger service with one serialized writer and a separate read pool.
pub struct TrajectoryDb {
    pool: SqlitePool,
    sender: mpsc::Sender<WriterCommand>,
    worker: Option<JoinHandle<()>>,
}

impl TrajectoryDb {
    /// Opens, migrates and verifies a `SQLite` ledger before accepting writes.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid limits, migration/open failure, or an invalid existing chain.
    pub async fn open(path: &Path, config: LedgerConfig) -> Result<Self, DbError> {
        config.validate()?;
        let options = connect_options(path, config.busy_timeout)?;
        let pool = SqlitePoolOptions::new()
            .max_connections(config.max_read_connections)
            .connect_with(options.clone())
            .await
            .map_err(DbError::database)?;
        MIGRATOR.run(&pool).await.map_err(DbError::database)?;
        verify_pool(&pool).await?;

        let writer = SqliteConnection::connect_with(&options)
            .await
            .map_err(DbError::database)?;
        let (sender, receiver) = mpsc::channel(config.queue_capacity);
        let worker = tokio::spawn(run_writer(writer, receiver, config));
        Ok(Self {
            pool,
            sender,
            worker: Some(worker),
        })
    }

    /// Returns a cloneable bounded append handle.
    #[must_use]
    pub fn appender(&self) -> LedgerAppender {
        LedgerAppender {
            sender: self.sender.clone(),
        }
    }

    /// Verifies persisted rows and the durable chain head.
    ///
    /// # Errors
    ///
    /// Returns an integrity or `SQLite` failure and never repairs data automatically.
    pub async fn verify(&self) -> Result<(), DbError> {
        verify_pool(&self.pool).await
    }

    /// Returns the durable event count.
    ///
    /// # Errors
    ///
    /// Returns a `SQLite` failure.
    pub async fn event_count(&self) -> Result<u64, DbError> {
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM trajectory_events")
            .fetch_one(&self.pool)
            .await
            .map_err(DbError::database)?;
        u64::try_from(count).map_err(DbError::integrity)
    }

    /// Flushes queued writes, checkpoints WAL and stops the writer.
    ///
    /// # Errors
    ///
    /// Returns an error when the writer cannot acknowledge shutdown or checkpointing fails.
    pub async fn shutdown(mut self) -> Result<(), DbError> {
        let (reply, response) = oneshot::channel();
        self.sender
            .send(WriterCommand::Shutdown { reply })
            .await
            .map_err(|_| DbError::writer_unavailable("trajectory writer already stopped"))?;
        response
            .await
            .map_err(|_| DbError::writer_unavailable("writer did not acknowledge shutdown"))?;
        if let Some(worker) = self.worker.take() {
            worker.await.map_err(DbError::database)?;
        }
        sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
            .execute(&self.pool)
            .await
            .map_err(DbError::database)?;
        self.pool.close().await;
        Ok(())
    }
}

fn connect_options(path: &Path, busy_timeout: Duration) -> Result<SqliteConnectOptions, DbError> {
    let url = format!("sqlite://{}", path.display());
    SqliteConnectOptions::from_str(&url)
        .map(|options| {
            options
                .create_if_missing(true)
                .foreign_keys(true)
                .journal_mode(SqliteJournalMode::Wal)
                .synchronous(SqliteSynchronous::Full)
                .busy_timeout(busy_timeout)
        })
        .map_err(DbError::database)
}

async fn run_writer(
    mut connection: SqliteConnection,
    mut receiver: mpsc::Receiver<WriterCommand>,
    config: LedgerConfig,
) {
    while let Some(command) = receiver.recv().await {
        let WriterCommand::Append { input, reply } = command else {
            if let WriterCommand::Shutdown { reply } = command {
                let _ = reply.send(());
            }
            return;
        };

        let mut batch = vec![(input, reply)];
        let deadline = Instant::now() + config.max_batch_delay;
        let mut shutdown_reply = None;
        while batch.len() < config.max_batch_events {
            match timeout_at(deadline, receiver.recv()).await {
                Ok(Some(WriterCommand::Append { input, reply })) => batch.push((input, reply)),
                Ok(Some(WriterCommand::Shutdown { reply })) => {
                    shutdown_reply = Some(reply);
                    break;
                }
                Ok(None) | Err(_) => break,
            }
        }

        match persist_batch(
            &mut connection,
            batch.iter().map(|(input, _)| input.clone()),
        )
        .await
        {
            Ok(events) => {
                for ((_, reply), event) in batch.into_iter().zip(events) {
                    let _ = reply.send(Ok(CommittedEvent::after_commit(event)));
                }
            }
            Err(error) => {
                for (_, reply) in batch {
                    let _ = reply.send(Err(error.clone()));
                }
            }
        }
        if let Some(reply) = shutdown_reply {
            let _ = reply.send(());
            return;
        }
    }
}

async fn persist_batch(
    connection: &mut SqliteConnection,
    inputs: impl Iterator<Item = EventInput>,
) -> Result<Vec<HashedEvent>, DbError> {
    sqlx::query("BEGIN IMMEDIATE")
        .execute(&mut *connection)
        .await
        .map_err(DbError::database)?;
    let result = persist_batch_in_transaction(connection, inputs).await;
    match result {
        Ok(events) => {
            if let Err(error) = sqlx::query("COMMIT").execute(&mut *connection).await {
                let _ = sqlx::query("ROLLBACK").execute(&mut *connection).await;
                return Err(DbError::database(error));
            }
            Ok(events)
        }
        Err(error) => {
            let _ = sqlx::query("ROLLBACK").execute(&mut *connection).await;
            Err(error)
        }
    }
}

async fn persist_batch_in_transaction(
    connection: &mut SqliteConnection,
    inputs: impl Iterator<Item = EventInput>,
) -> Result<Vec<HashedEvent>, DbError> {
    let state = sqlx::query(
        "SELECT next_sequence, head_hash FROM trajectory_chain_state WHERE singleton = 1",
    )
    .fetch_one(&mut *connection)
    .await
    .map_err(DbError::database)?;
    let next_sequence: i64 = state.try_get("next_sequence").map_err(DbError::database)?;
    let mut sequence = u64::try_from(next_sequence).map_err(DbError::integrity)?;
    let mut previous_hash: String = state.try_get("head_hash").map_err(DbError::database)?;
    let mut events = Vec::new();

    for input in inputs {
        let event =
            build_hashed_event(sequence, &previous_hash, input).map_err(DbError::integrity)?;
        let detail_json = serde_json::to_string(&event.detail).map_err(DbError::integrity)?;
        let stored_sequence = i64::try_from(event.sequence).map_err(DbError::integrity)?;
        sqlx::query(
            "INSERT INTO trajectory_events
             (sequence, event_id, trace_id, schema_version, event_type, occurred_at,
              detail_json, previous_hash, event_hash)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(stored_sequence)
        .bind(&event.id)
        .bind(&event.trace_id)
        .bind(&event.schema)
        .bind(event.kind.wire_name())
        .bind(&event.occurred_at)
        .bind(detail_json)
        .bind(&event.previous_hash)
        .bind(&event.hash)
        .execute(&mut *connection)
        .await
        .map_err(DbError::database)?;
        previous_hash.clone_from(&event.hash);
        sequence += 1;
        events.push(event);
    }

    let stored_next = i64::try_from(sequence).map_err(DbError::integrity)?;
    sqlx::query(
        "UPDATE trajectory_chain_state SET next_sequence = ?, head_hash = ? WHERE singleton = 1",
    )
    .bind(stored_next)
    .bind(previous_hash)
    .execute(&mut *connection)
    .await
    .map_err(DbError::database)?;
    Ok(events)
}

async fn verify_pool(pool: &SqlitePool) -> Result<(), DbError> {
    let rows = sqlx::query(
        "SELECT sequence, event_id, trace_id, schema_version, event_type, occurred_at,
                detail_json, previous_hash, event_hash
         FROM trajectory_events ORDER BY sequence",
    )
    .fetch_all(pool)
    .await
    .map_err(DbError::database)?;
    let mut events = Vec::with_capacity(rows.len());
    for row in rows {
        let sequence: i64 = row.try_get("sequence").map_err(DbError::database)?;
        let event_type: String = row.try_get("event_type").map_err(DbError::database)?;
        let detail_json: String = row.try_get("detail_json").map_err(DbError::database)?;
        events.push(HashedEvent {
            schema: row.try_get("schema_version").map_err(DbError::database)?,
            sequence: u64::try_from(sequence).map_err(DbError::integrity)?,
            id: row.try_get("event_id").map_err(DbError::database)?,
            trace_id: row.try_get("trace_id").map_err(DbError::database)?,
            occurred_at: row.try_get("occurred_at").map_err(DbError::database)?,
            kind: EventKind::from_wire_name(&event_type).map_err(DbError::integrity)?,
            detail: from_str::<BTreeMap<String, String>>(&detail_json)
                .map_err(DbError::integrity)?,
            previous_hash: row.try_get("previous_hash").map_err(DbError::database)?,
            hash: row.try_get("event_hash").map_err(DbError::database)?,
        });
    }
    TrajectoryChain::verify(&events).map_err(DbError::integrity)?;

    let state = sqlx::query(
        "SELECT next_sequence, head_hash FROM trajectory_chain_state WHERE singleton = 1",
    )
    .fetch_one(pool)
    .await
    .map_err(DbError::database)?;
    let next_sequence: i64 = state.try_get("next_sequence").map_err(DbError::database)?;
    let head_hash: String = state.try_get("head_hash").map_err(DbError::database)?;
    let expected_head = events
        .last()
        .map_or(GENESIS_HASH, |event| event.hash.as_str());
    if usize::try_from(next_sequence).ok() != Some(events.len()) || head_hash != expected_head {
        return Err(DbError::integrity(
            "durable trajectory head does not match event chain",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    fn input(id: String, secret: bool) -> EventInput {
        EventInput {
            id,
            trace_id: "trace-phase-1".into(),
            occurred_at: "2026-10-18T18:00:00Z".into(),
            kind: EventKind::ToolProposed,
            detail: BTreeMap::from([(
                "command".into(),
                if secret {
                    "curl -H sk-1234567890 password=hunter2".into()
                } else {
                    "cargo test".into()
                },
            )]),
        }
    }

    #[tokio::test]
    async fn persists_redacted_chain_across_reopen() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("trajectory.db");
        let database = TrajectoryDb::open(&path, LedgerConfig::default())
            .await
            .unwrap();
        let committed = database
            .appender()
            .append(input("event-1".into(), true))
            .await
            .unwrap();
        assert_eq!(committed.sequence(), 0);
        assert_eq!(committed.hash(), committed.event().hash);
        assert_eq!(committed.event().id, "event-1");
        database.verify().await.unwrap();
        database.shutdown().await.unwrap();

        let bytes = fs::read(&path).unwrap();
        let raw = String::from_utf8_lossy(&bytes);
        assert!(!raw.contains("sk-1234567890"));
        assert!(!raw.contains("hunter2"));

        let reopened = TrajectoryDb::open(&path, LedgerConfig::default())
            .await
            .unwrap();
        assert_eq!(reopened.event_count().await.unwrap(), 1);
        reopened.verify().await.unwrap();
        reopened.shutdown().await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_producers_create_one_gap_free_chain() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("concurrent.db");
        let database = TrajectoryDb::open(&path, LedgerConfig::default())
            .await
            .unwrap();
        let mut workers = Vec::new();
        for worker in 0..8 {
            let appender = database.appender();
            workers.push(tokio::spawn(async move {
                for index in 0..250 {
                    let _ = appender
                        .append(input(format!("event-{worker}-{index}"), false))
                        .await
                        .unwrap();
                }
            }));
        }
        for worker in workers {
            worker.await.unwrap();
        }
        assert_eq!(database.event_count().await.unwrap(), 2_000);
        database.verify().await.unwrap();
        database.shutdown().await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn duplicate_inside_batch_rolls_back_every_event() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("atomic.db");
        let config = LedgerConfig {
            max_batch_delay: Duration::from_millis(50),
            ..LedgerConfig::default()
        };
        let database = TrajectoryDb::open(&path, config).await.unwrap();
        let left = database.appender();
        let right = database.appender();
        let first =
            tokio::spawn(async move { left.append(input("duplicate".into(), false)).await });
        let second =
            tokio::spawn(async move { right.append(input("duplicate".into(), false)).await });
        assert!(first.await.unwrap().is_err());
        assert!(second.await.unwrap().is_err());
        assert_eq!(database.event_count().await.unwrap(), 0);
        database.verify().await.unwrap();
        database.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn modified_persisted_detail_prevents_reopen() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("tampered.db");
        let database = TrajectoryDb::open(&path, LedgerConfig::default())
            .await
            .unwrap();
        let _ = database
            .appender()
            .append(input("event-1".into(), false))
            .await
            .unwrap();
        database.shutdown().await.unwrap();

        let options = connect_options(&path, Duration::from_secs(1)).unwrap();
        let mut connection = SqliteConnection::connect_with(&options).await.unwrap();
        sqlx::query("UPDATE trajectory_events SET detail_json = '{\"command\":\"changed\"}'")
            .execute(&mut connection)
            .await
            .unwrap();
        connection.close().await.unwrap();

        let reopened = TrajectoryDb::open(&path, LedgerConfig::default()).await;
        assert!(matches!(
            reopened,
            Err(DbError {
                code: DbErrorCode::Integrity,
                ..
            })
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 6)]
    async fn ten_thousand_events_survive_close_reopen_and_verify() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("ten-thousand.db");
        let config = LedgerConfig {
            queue_capacity: 12_000,
            max_batch_events: 100,
            max_batch_delay: Duration::from_millis(5),
            ..LedgerConfig::default()
        };
        let database = TrajectoryDb::open(&path, config.clone()).await.unwrap();
        let mut workers = Vec::new();
        for worker in 0..100 {
            let appender = database.appender();
            workers.push(tokio::spawn(async move {
                for index in 0..100 {
                    let _ = appender
                        .append(input(format!("large-{worker}-{index}"), false))
                        .await
                        .unwrap();
                }
            }));
        }
        for worker in workers {
            worker.await.unwrap();
        }
        assert_eq!(database.event_count().await.unwrap(), 10_000);
        database.verify().await.unwrap();
        database.shutdown().await.unwrap();

        let reopened = TrajectoryDb::open(&path, config).await.unwrap();
        assert_eq!(reopened.event_count().await.unwrap(), 10_000);
        reopened.verify().await.unwrap();
        reopened.shutdown().await.unwrap();
    }
}
