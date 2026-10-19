//! Durable `SQLite` persistence for Viper's global trajectory ledger.

use serde_json::from_str;
use sqlx::migrate::Migrator;
use sqlx::sqlite::SqliteRow;
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
    /// A diagnostic LID observation failed validation.
    InvalidObservation,
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

/// LID metadata accepted for durable storage; it deliberately contains no prompt or embedding.
#[derive(Debug, Clone, PartialEq)]
pub struct LidObservationInput {
    /// Stable caller-generated identifier.
    pub observation_id: String,
    /// Already-committed trajectory event this observation describes.
    pub event_id: String,
    /// Observation timestamp in RFC 3339 form.
    pub observed_at: String,
    /// Raw provider-computed geometric LID value (diagnostic only).
    pub lid: f64,
    /// Number of nearest neighbors used by the estimator.
    pub neighbors_used: u16,
    /// Stable model identifier/revision.
    pub model_id: String,
    /// SHA-256 fingerprint of the exact embedding bundle.
    pub model_bundle_sha256: String,
    /// Verified reference corpus version.
    pub corpus_version: String,
    /// SHA-256 of the exact verified corpus manifest bytes.
    pub corpus_manifest_sha256: String,
}

/// Diagnostic LID observation persisted in `SQLite`.
#[derive(Debug, Clone, PartialEq)]
pub struct LidObservation {
    /// Stable observation identifier.
    pub observation_id: String,
    /// Associated committed trajectory event identifier.
    pub event_id: String,
    /// Trajectory event ID containing the hash-chained observation detail.
    pub audit_event_id: String,
    /// Global sequence of the hash-chained observation event.
    pub audit_event_sequence: u64,
    /// Hash of the hash-chained observation event.
    pub audit_event_hash: String,
    /// Observation timestamp.
    pub observed_at: String,
    /// Raw LID value, not a probability or verdict.
    pub lid: f64,
    /// Number of neighbors used.
    pub neighbors_used: u16,
    /// Model identity used for the embedding.
    pub model_id: String,
    /// Model bundle SHA-256.
    pub model_bundle_sha256: String,
    /// Verified reference corpus version.
    pub corpus_version: String,
    /// Exact corpus manifest SHA-256.
    pub corpus_manifest_sha256: String,
    /// Current fixed state; no calibrated interpretation exists yet.
    pub status: LidObservationStatus,
}

/// Calibration state for a persisted LID observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LidObservationStatus {
    /// No approved calibration has been applied.
    Uncalibrated,
}

/// Opaque receipt proving that an LID observation was committed.
#[derive(Debug, PartialEq)]
#[must_use = "a committed LID observation receipt should be explicitly inspected"]
pub struct CommittedLidObservation {
    observation: LidObservation,
    audit_event: HashedEvent,
}

impl CommittedLidObservation {
    fn after_commit(observation: LidObservation, audit_event: HashedEvent) -> Self {
        Self {
            observation,
            audit_event,
        }
    }

    /// Returns the durably committed, diagnostic-only observation.
    #[must_use]
    pub fn observation(&self) -> &LidObservation {
        &self.observation
    }

    /// Returns the trajectory event committed atomically with the observation row.
    #[must_use]
    pub fn audit_event(&self) -> &HashedEvent {
        &self.audit_event
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
    RecordLidObservation {
        input: LidObservationInput,
        reply: oneshot::Sender<Result<CommittedLidObservation, DbError>>,
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

    /// Persist a diagnostic observation through the same serialized writer as trajectory events.
    ///
    /// The referenced event must already be committed. The response is returned only after the
    /// observation transaction commits. Raw prompts, outputs and embeddings are not accepted.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed metadata, a missing event, database failure, or a stopped
    /// writer.
    pub async fn record_lid_observation(
        &self,
        input: LidObservationInput,
    ) -> Result<CommittedLidObservation, DbError> {
        validate_lid_observation(&input)?;
        let (reply, response) = oneshot::channel();
        self.sender
            .send(WriterCommand::RecordLidObservation { input, reply })
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

    /// Loads one persisted diagnostic LID observation by ID.
    ///
    /// # Errors
    ///
    /// Returns a sanitized `SQLite` failure or an integrity error for malformed stored metadata.
    pub async fn lid_observation_by_id(
        &self,
        observation_id: &str,
    ) -> Result<Option<LidObservation>, DbError> {
        let row = sqlx::query(
            "SELECT lid_observations.observation_id, lid_observations.event_id,
                    lid_observations.audit_event_id, lid_observations.observed_at,
                    lid_observations.lid, lid_observations.neighbors_used,
                    lid_observations.model_id, lid_observations.model_bundle_sha256,
                    lid_observations.corpus_version, lid_observations.corpus_manifest_sha256,
                    lid_observations.status,
                    trajectory_events.sequence AS audit_event_sequence,
                    trajectory_events.event_hash AS audit_event_hash
             FROM lid_observations
             JOIN trajectory_events ON trajectory_events.event_id = lid_observations.audit_event_id
             WHERE observation_id = ?",
        )
        .bind(observation_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(DbError::database)?;
        row.as_ref().map(lid_observation_from_row).transpose()
    }

    /// Looks up one persisted event by its globally unique identifier.
    ///
    /// # Errors
    ///
    /// Returns a sanitized `SQLite` failure or an invalid stored-event error.
    pub async fn event_by_id(&self, event_id: &str) -> Result<Option<HashedEvent>, DbError> {
        let row = sqlx::query(
            "SELECT sequence, event_id, trace_id, schema_version, event_type, occurred_at,
                    detail_json, previous_hash, event_hash
             FROM trajectory_events WHERE event_id = ?",
        )
        .bind(event_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(DbError::database)?;
        row.as_ref().map(hashed_event_from_row).transpose()
    }

    /// Reads a bounded page of committed events after the supplied global sequence.
    ///
    /// The limit is clamped to 100 events to keep the read API bounded.
    ///
    /// # Errors
    ///
    /// Returns a sanitized `SQLite` failure or an invalid stored-event error.
    pub async fn events_after(
        &self,
        after_sequence: u64,
        limit: usize,
    ) -> Result<Vec<HashedEvent>, DbError> {
        self.events_page(Some(after_sequence), limit).await
    }

    /// Reads the first bounded page, or a page after a committed sequence.
    ///
    /// # Errors
    ///
    /// Returns a sanitized `SQLite` failure or an invalid stored-event error.
    pub async fn events_page(
        &self,
        after_sequence: Option<u64>,
        limit: usize,
    ) -> Result<Vec<HashedEvent>, DbError> {
        let after_sequence = after_sequence
            .map(i64::try_from)
            .transpose()
            .map_err(DbError::integrity)?;
        let limit = i64::try_from(limit.clamp(1, 100)).map_err(DbError::integrity)?;
        let rows = if let Some(after_sequence) = after_sequence {
            sqlx::query(
                "SELECT sequence, event_id, trace_id, schema_version, event_type, occurred_at,
                        detail_json, previous_hash, event_hash
                 FROM trajectory_events WHERE sequence > ? ORDER BY sequence LIMIT ?",
            )
            .bind(after_sequence)
            .bind(limit)
            .fetch_all(&self.pool)
            .await
        } else {
            sqlx::query(
                "SELECT sequence, event_id, trace_id, schema_version, event_type, occurred_at,
                        detail_json, previous_hash, event_hash
                 FROM trajectory_events ORDER BY sequence LIMIT ?",
            )
            .bind(limit)
            .fetch_all(&self.pool)
            .await
        }
        .map_err(DbError::database)?;
        rows.iter().map(hashed_event_from_row).collect()
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

fn validate_lid_observation(input: &LidObservationInput) -> Result<(), DbError> {
    let valid_text = |value: &str, limit: usize| {
        !value.trim().is_empty() && value.len() <= limit && !value.chars().any(char::is_control)
    };
    let valid_sha256 = |value: &str| {
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    };
    let valid_id = |value: &str| {
        valid_text(value, 128)
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
    };
    if !valid_id(&input.observation_id)
        || !valid_text(&input.event_id, 128)
        || !valid_text(&input.observed_at, 64)
        || !input.lid.is_finite()
        || input.lid <= 0.0
        // Storage sanity bound only; this is not a classification or decision threshold.
        || input.lid > 1_000_000_000_000.0
        || !(2..=256).contains(&input.neighbors_used)
        || !valid_text(&input.model_id, 128)
        || !valid_sha256(&input.model_bundle_sha256)
        || !valid_text(&input.corpus_version, 64)
        || !valid_sha256(&input.corpus_manifest_sha256)
    {
        return Err(DbError {
            code: DbErrorCode::InvalidObservation,
            message: "LID observation metadata is invalid".into(),
        });
    }
    Ok(())
}

async fn run_writer(
    mut connection: SqliteConnection,
    mut receiver: mpsc::Receiver<WriterCommand>,
    config: LedgerConfig,
) {
    let mut pending = None;
    loop {
        let command = match pending.take() {
            Some(command) => command,
            None => match receiver.recv().await {
                Some(command) => command,
                None => return,
            },
        };
        match command {
            WriterCommand::Append { input, reply } => {
                let mut batch = vec![(input, reply)];
                let deadline = Instant::now() + config.max_batch_delay;
                let mut shutdown_reply = None;
                while batch.len() < config.max_batch_events {
                    match timeout_at(deadline, receiver.recv()).await {
                        Ok(Some(WriterCommand::Append { input, reply })) => {
                            batch.push((input, reply));
                        }
                        Ok(Some(command @ WriterCommand::RecordLidObservation { .. })) => {
                            pending = Some(command);
                            break;
                        }
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
            WriterCommand::RecordLidObservation { input, reply } => {
                let result = persist_lid_observation(&mut connection, input).await;
                let _ = reply.send(result.map(|(observation, event)| {
                    CommittedLidObservation::after_commit(observation, event)
                }));
            }
            WriterCommand::Shutdown { reply } => {
                let _ = reply.send(());
                return;
            }
        }
    }
}

async fn persist_lid_observation(
    connection: &mut SqliteConnection,
    input: LidObservationInput,
) -> Result<(LidObservation, HashedEvent), DbError> {
    validate_lid_observation(&input)?;
    let trace_id: Option<String> =
        sqlx::query_scalar("SELECT trace_id FROM trajectory_events WHERE event_id = ?")
            .bind(&input.event_id)
            .fetch_optional(&mut *connection)
            .await
            .map_err(DbError::database)?;
    let trace_id = trace_id.ok_or_else(|| DbError {
        code: DbErrorCode::InvalidObservation,
        message: "LID observation must reference a committed event".into(),
    })?;

    let audit_event_id = format!("lid-observation:{}", input.observation_id);
    let detail = BTreeMap::from([
        ("observation_id".into(), input.observation_id.clone()),
        ("source_event_id".into(), input.event_id.clone()),
        ("lid".into(), input.lid.to_string()),
        ("neighbors_used".into(), input.neighbors_used.to_string()),
        ("model_id".into(), input.model_id.clone()),
        (
            "model_bundle_sha256".into(),
            input.model_bundle_sha256.clone(),
        ),
        ("corpus_version".into(), input.corpus_version.clone()),
        (
            "corpus_manifest_sha256".into(),
            input.corpus_manifest_sha256.clone(),
        ),
        ("status".into(), "uncalibrated".into()),
    ]);
    let audit_event = EventInput {
        id: audit_event_id.clone(),
        trace_id,
        occurred_at: input.observed_at.clone(),
        kind: EventKind::QualityGate,
        detail,
    };

    sqlx::query("BEGIN IMMEDIATE")
        .execute(&mut *connection)
        .await
        .map_err(DbError::database)?;
    let persisted = async {
        let mut events =
            persist_batch_in_transaction(connection, std::iter::once(audit_event)).await?;
        let audit_event = events
            .pop()
            .ok_or_else(|| DbError::integrity("missing committed LID audit event"))?;
        sqlx::query(
            "INSERT INTO lid_observations
             (observation_id, event_id, audit_event_id, observed_at, lid, neighbors_used,
              model_id, model_bundle_sha256, corpus_version, corpus_manifest_sha256, status)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'uncalibrated')",
        )
        .bind(&input.observation_id)
        .bind(&input.event_id)
        .bind(&audit_event_id)
        .bind(&input.observed_at)
        .bind(input.lid)
        .bind(i64::from(input.neighbors_used))
        .bind(&input.model_id)
        .bind(&input.model_bundle_sha256)
        .bind(&input.corpus_version)
        .bind(&input.corpus_manifest_sha256)
        .execute(&mut *connection)
        .await
        .map_err(DbError::database)?;
        Ok::<_, DbError>(audit_event)
    }
    .await;
    let audit_event = match persisted {
        Ok(event) => {
            if let Err(error) = sqlx::query("COMMIT").execute(&mut *connection).await {
                let _ = sqlx::query("ROLLBACK").execute(&mut *connection).await;
                return Err(DbError::database(error));
            }
            event
        }
        Err(error) => {
            let _ = sqlx::query("ROLLBACK").execute(&mut *connection).await;
            return Err(error);
        }
    };
    let observation = LidObservation {
        observation_id: input.observation_id,
        event_id: input.event_id,
        audit_event_id: audit_event.id.clone(),
        audit_event_sequence: audit_event.sequence,
        audit_event_hash: audit_event.hash.clone(),
        observed_at: input.observed_at,
        lid: input.lid,
        neighbors_used: input.neighbors_used,
        model_id: input.model_id,
        model_bundle_sha256: input.model_bundle_sha256,
        corpus_version: input.corpus_version,
        corpus_manifest_sha256: input.corpus_manifest_sha256,
        status: LidObservationStatus::Uncalibrated,
    };
    Ok((observation, audit_event))
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
    let events = rows
        .iter()
        .map(hashed_event_from_row)
        .collect::<Result<Vec<_>, _>>()?;
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

fn hashed_event_from_row(row: &SqliteRow) -> Result<HashedEvent, DbError> {
    let sequence: i64 = row.try_get("sequence").map_err(DbError::database)?;
    let event_type: String = row.try_get("event_type").map_err(DbError::database)?;
    let detail_json: String = row.try_get("detail_json").map_err(DbError::database)?;
    Ok(HashedEvent {
        schema: row.try_get("schema_version").map_err(DbError::database)?,
        sequence: u64::try_from(sequence).map_err(DbError::integrity)?,
        id: row.try_get("event_id").map_err(DbError::database)?,
        trace_id: row.try_get("trace_id").map_err(DbError::database)?,
        occurred_at: row.try_get("occurred_at").map_err(DbError::database)?,
        kind: EventKind::from_wire_name(&event_type).map_err(DbError::integrity)?,
        detail: from_str::<BTreeMap<String, String>>(&detail_json).map_err(DbError::integrity)?,
        previous_hash: row.try_get("previous_hash").map_err(DbError::database)?,
        hash: row.try_get("event_hash").map_err(DbError::database)?,
    })
}

fn lid_observation_from_row(row: &SqliteRow) -> Result<LidObservation, DbError> {
    let status: String = row.try_get("status").map_err(DbError::database)?;
    if status != "uncalibrated" {
        return Err(DbError::integrity(
            "unknown persisted LID observation status",
        ));
    }
    let neighbors_used: i64 = row.try_get("neighbors_used").map_err(DbError::database)?;
    let audit_event_sequence: i64 = row
        .try_get("audit_event_sequence")
        .map_err(DbError::database)?;
    Ok(LidObservation {
        observation_id: row.try_get("observation_id").map_err(DbError::database)?,
        event_id: row.try_get("event_id").map_err(DbError::database)?,
        audit_event_id: row.try_get("audit_event_id").map_err(DbError::database)?,
        audit_event_sequence: u64::try_from(audit_event_sequence).map_err(DbError::integrity)?,
        audit_event_hash: row.try_get("audit_event_hash").map_err(DbError::database)?,
        observed_at: row.try_get("observed_at").map_err(DbError::database)?,
        lid: row.try_get("lid").map_err(DbError::database)?,
        neighbors_used: u16::try_from(neighbors_used).map_err(DbError::integrity)?,
        model_id: row.try_get("model_id").map_err(DbError::database)?,
        model_bundle_sha256: row
            .try_get("model_bundle_sha256")
            .map_err(DbError::database)?,
        corpus_version: row.try_get("corpus_version").map_err(DbError::database)?,
        corpus_manifest_sha256: row
            .try_get("corpus_manifest_sha256")
            .map_err(DbError::database)?,
        status: LidObservationStatus::Uncalibrated,
    })
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

    fn lid_input(observation_id: &str, event_id: &str) -> LidObservationInput {
        LidObservationInput {
            observation_id: observation_id.into(),
            event_id: event_id.into(),
            observed_at: "2026-10-19T12:00:00Z".into(),
            lid: 0.73,
            neighbors_used: 12,
            model_id: "test-model@revision-1".into(),
            model_bundle_sha256: "a".repeat(64),
            corpus_version: "v2".into(),
            corpus_manifest_sha256: "b".repeat(64),
        }
    }

    #[tokio::test]
    async fn persists_lid_observation_after_committed_event_and_reopens_it() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("lid-observation.db");
        let database = TrajectoryDb::open(&path, LedgerConfig::default())
            .await
            .unwrap();
        let appender = database.appender();
        let event = appender
            .append(input("decision-1".into(), false))
            .await
            .unwrap();
        let committed = appender
            .record_lid_observation(lid_input("observation-1", "decision-1"))
            .await
            .unwrap();
        assert_eq!(committed.observation().event_id, event.event().id);
        assert!((committed.observation().lid - 0.73).abs() < f64::EPSILON);
        assert_eq!(committed.observation().neighbors_used, 12);
        assert_eq!(committed.audit_event().kind, EventKind::QualityGate);
        assert_eq!(
            committed.observation().audit_event_hash,
            committed.audit_event().hash
        );
        assert_eq!(
            committed.observation().status,
            LidObservationStatus::Uncalibrated
        );
        let expected = committed.observation().clone();
        assert_eq!(database.event_count().await.unwrap(), 2);
        database.verify().await.unwrap();
        database.shutdown().await.unwrap();

        let reopened = TrajectoryDb::open(&path, LedgerConfig::default())
            .await
            .unwrap();
        assert_eq!(
            reopened
                .lid_observation_by_id("observation-1")
                .await
                .unwrap(),
            Some(expected)
        );
        assert_eq!(reopened.event_count().await.unwrap(), 2);
        reopened.verify().await.unwrap();
        reopened.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn rejects_bad_lid_metadata_and_uncommitted_event_reference() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("invalid-lid-observation.db");
        let database = TrajectoryDb::open(&path, LedgerConfig::default())
            .await
            .unwrap();
        let appender = database.appender();
        let mut invalid = lid_input("bad", "missing-event");
        invalid.model_bundle_sha256 = "not-a-digest".into();
        assert_eq!(
            appender
                .record_lid_observation(invalid)
                .await
                .unwrap_err()
                .code,
            DbErrorCode::InvalidObservation
        );
        let result = appender
            .record_lid_observation(lid_input("orphan", "missing-event"))
            .await
            .unwrap_err();
        assert_eq!(result.code, DbErrorCode::InvalidObservation);
        assert_eq!(database.event_count().await.unwrap(), 0);
        database.shutdown().await.unwrap();
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
