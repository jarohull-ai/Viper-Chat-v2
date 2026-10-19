//! Redacted, deterministic, tamper-evident trajectory records.

use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::OnceLock;
use thiserror::Error;

const DOMAIN: &[u8] = b"viper-trajectory/v1\0";
const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const HEX: &[u8; 16] = b"0123456789abcdef";

/// Auditable event vocabulary. New values require a schema/version decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    /// An orchestration plan was accepted for consideration.
    Plan,
    /// A tool side effect was proposed.
    ToolProposed,
    /// Policy and SEED produced a composed verdict.
    SeedVerdict,
    /// A user approved a pending proposal.
    UserApproval,
    /// A user rejected a pending proposal.
    UserRejection,
    /// Tool execution began.
    ToolExecution,
    /// Tool execution completed.
    ToolResult,
    /// Tool execution failed.
    ToolError,
    /// A quality gate produced a result.
    QualityGate,
    /// A trace forked from another trace.
    Fork,
    /// A trust relationship was granted.
    TrustGranted,
    /// A trust relationship was revoked.
    TrustRevoked,
}

impl EventKind {
    /// Stable value used by storage and transport protocols.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Plan => "plan",
            Self::ToolProposed => "tool_proposed",
            Self::SeedVerdict => "seed_verdict",
            Self::UserApproval => "user_approval",
            Self::UserRejection => "user_rejection",
            Self::ToolExecution => "tool_execution",
            Self::ToolResult => "tool_result",
            Self::ToolError => "tool_error",
            Self::QualityGate => "quality_gate",
            Self::Fork => "fork",
            Self::TrustGranted => "trust_granted",
            Self::TrustRevoked => "trust_revoked",
        }
    }

    /// Parses the stable storage/transport value.
    ///
    /// # Errors
    ///
    /// Returns an error for an event type outside the frozen vocabulary.
    pub fn from_wire_name(value: &str) -> Result<Self, ChainError> {
        match value {
            "plan" => Ok(Self::Plan),
            "tool_proposed" => Ok(Self::ToolProposed),
            "seed_verdict" => Ok(Self::SeedVerdict),
            "user_approval" => Ok(Self::UserApproval),
            "user_rejection" => Ok(Self::UserRejection),
            "tool_execution" => Ok(Self::ToolExecution),
            "tool_result" => Ok(Self::ToolResult),
            "tool_error" => Ok(Self::ToolError),
            "quality_gate" => Ok(Self::QualityGate),
            "fork" => Ok(Self::Fork),
            "trust_granted" => Ok(Self::TrustGranted),
            "trust_revoked" => Ok(Self::TrustRevoked),
            _ => Err(ChainError::UnknownEventKind(value.to_owned())),
        }
    }
}

/// Event content before redaction and hashing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventInput {
    /// Globally unique event identifier.
    pub id: String,
    /// Trace identifier.
    pub trace_id: String,
    /// Trusted RFC 3339 timestamp.
    pub occurred_at: String,
    /// Event classification.
    pub kind: EventKind,
    /// Ordered event detail. Values are redacted before storage.
    pub detail: BTreeMap<String, String>,
}

/// Stored trajectory record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HashedEvent {
    /// Canonical encoding schema.
    pub schema: String,
    /// Monotonic sequence within this chain.
    pub sequence: u64,
    /// Event identifier.
    pub id: String,
    /// Trace identifier.
    pub trace_id: String,
    /// Trusted timestamp.
    pub occurred_at: String,
    /// Event classification.
    pub kind: EventKind,
    /// Redacted detail.
    pub detail: BTreeMap<String, String>,
    /// SHA-256 of the previous event or the zero genesis value.
    pub previous_hash: String,
    /// SHA-256 of the canonical record content.
    pub hash: String,
}

/// Chain validation or append failure.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ChainError {
    /// A required identity or timestamp field is empty.
    #[error("event field {0} must not be empty")]
    EmptyField(&'static str),
    /// A sequence or predecessor does not match its position.
    #[error("chain linkage is invalid at sequence {0}")]
    InvalidLink(u64),
    /// A stored digest does not match canonical content.
    #[error("event hash is invalid at sequence {0}")]
    InvalidHash(u64),
    /// A built-in redaction expression could not be compiled.
    #[error("redaction policy is invalid: {0}")]
    InvalidRedactionPolicy(String),
    /// An append operation did not make the new record observable.
    #[error("trajectory append invariant failed")]
    AppendInvariant,
    /// A stored event type is outside the frozen vocabulary.
    #[error("unknown trajectory event kind: {0}")]
    UnknownEventKind(String),
    /// A predecessor is not a lowercase SHA-256 hex value.
    #[error("previous hash is not a lowercase SHA-256 value")]
    InvalidPreviousHash,
}

/// In-memory chain used by the first slice. A durable repository replaces storage, not hashing.
#[derive(Debug, Default)]
pub struct TrajectoryChain {
    events: Vec<HashedEvent>,
}

impl TrajectoryChain {
    /// Creates an empty chain.
    #[must_use]
    pub const fn new() -> Self {
        Self { events: Vec::new() }
    }

    /// Redacts, hashes and appends one event.
    ///
    /// # Errors
    ///
    /// Returns an error when required input is empty, redaction policy cannot be compiled, or the
    /// append invariant fails.
    pub fn append(&mut self, input: EventInput) -> Result<&HashedEvent, ChainError> {
        let sequence = self.events.len() as u64;
        let previous_hash = self
            .events
            .last()
            .map_or_else(|| GENESIS_HASH.to_owned(), |event| event.hash.clone());
        let event = build_hashed_event(sequence, &previous_hash, input)?;
        self.events.push(event);
        self.events.last().ok_or(ChainError::AppendInvariant)
    }

    /// Returns immutable records for persistence or inspection.
    #[must_use]
    pub fn events(&self) -> &[HashedEvent] {
        &self.events
    }

    /// Verifies linkage and content hashes for every record.
    ///
    /// # Errors
    ///
    /// Returns the first invalid sequence/link or content digest.
    pub fn verify(events: &[HashedEvent]) -> Result<(), ChainError> {
        let mut expected_previous = GENESIS_HASH;
        for (index, event) in events.iter().enumerate() {
            let expected_sequence = index as u64;
            if event.sequence != expected_sequence || event.previous_hash != expected_previous {
                return Err(ChainError::InvalidLink(expected_sequence));
            }
            if calculate_hash(event) != event.hash {
                return Err(ChainError::InvalidHash(expected_sequence));
            }
            expected_previous = &event.hash;
        }
        Ok(())
    }
}

/// Builds one canonical redacted record for durable storage.
///
/// # Errors
///
/// Returns an error for invalid identity fields, an invalid predecessor hash, or an invalid
/// built-in redaction policy.
pub fn build_hashed_event(
    sequence: u64,
    previous_hash: &str,
    input: EventInput,
) -> Result<HashedEvent, ChainError> {
    validate_input(&input)?;
    if !is_sha256_hex(previous_hash) {
        return Err(ChainError::InvalidPreviousHash);
    }
    let detail = input
        .detail
        .into_iter()
        .map(|(key, value)| mask_sensitive_detail(&value).map(|masked| (key, masked)))
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    let mut event = HashedEvent {
        schema: "viper.trajectory.v1".to_owned(),
        sequence,
        id: input.id,
        trace_id: input.trace_id,
        occurred_at: input.occurred_at,
        kind: input.kind,
        detail,
        previous_hash: previous_hash.to_owned(),
        hash: String::new(),
    };
    event.hash = calculate_hash(&event);
    Ok(event)
}

fn validate_input(input: &EventInput) -> Result<(), ChainError> {
    for (name, value) in [
        ("id", input.id.as_str()),
        ("trace_id", input.trace_id.as_str()),
        ("occurred_at", input.occurred_at.as_str()),
    ] {
        if value.trim().is_empty() {
            return Err(ChainError::EmptyField(name));
        }
    }
    Ok(())
}

fn calculate_hash(event: &HashedEvent) -> String {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(DOMAIN);
    push_field(&mut bytes, event.schema.as_bytes());
    push_field(&mut bytes, &event.sequence.to_be_bytes());
    push_field(&mut bytes, event.id.as_bytes());
    push_field(&mut bytes, event.trace_id.as_bytes());
    push_field(&mut bytes, event.occurred_at.as_bytes());
    push_field(&mut bytes, event.kind.wire_name().as_bytes());
    push_field(&mut bytes, event.previous_hash.as_bytes());
    push_field(&mut bytes, &(event.detail.len() as u64).to_be_bytes());
    for (key, value) in &event.detail {
        push_field(&mut bytes, key.as_bytes());
        push_field(&mut bytes, value.as_bytes());
    }
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn push_field(target: &mut Vec<u8>, value: &[u8]) {
    target.extend_from_slice(&(value.len() as u64).to_be_bytes());
    target.extend_from_slice(value);
}

/// Masks common credentials before they can enter trajectory storage.
///
/// # Errors
///
/// Returns an initialization error if a built-in redaction expression is invalid.
pub fn mask_sensitive_detail(value: &str) -> Result<String, ChainError> {
    static PATTERNS: OnceLock<Result<Vec<(Regex, &'static str)>, String>> = OnceLock::new();
    let patterns = PATTERNS.get_or_init(|| {
        [
            (r"sk-[A-Za-z0-9_-]{8,}", "[REDACTED_OPENAI_KEY]"),
            (r"ghp_[A-Za-z0-9]{8,}", "[REDACTED_GITHUB_TOKEN]"),
            (r"(?i)(password\s*=\s*)[^\s;&]+", "$1[REDACTED_PASSWORD]"),
            (
                r"(?s)-----BEGIN [^-]+ PRIVATE KEY-----.*?-----END [^-]+ PRIVATE KEY-----",
                "[REDACTED_PRIVATE_KEY]",
            ),
        ]
        .into_iter()
        .map(|(pattern, replacement)| {
            Regex::new(pattern)
                .map(|regex| (regex, replacement))
                .map_err(|error| error.to_string())
        })
        .collect()
    });
    let patterns = patterns
        .as_ref()
        .map_err(|message| ChainError::InvalidRedactionPolicy(message.clone()))?;
    let mut masked = value.to_owned();
    for (regex, replacement) in patterns {
        masked = regex.replace_all(&masked, *replacement).into_owned();
    }
    Ok(masked)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(detail: BTreeMap<String, String>) -> EventInput {
        EventInput {
            id: "event-1".into(),
            trace_id: "trace-1".into(),
            occurred_at: "2026-10-18T12:00:00Z".into(),
            kind: EventKind::ToolProposed,
            detail,
        }
    }

    #[test]
    fn masks_before_hashing_and_detects_tampering() {
        let mut detail = BTreeMap::new();
        detail.insert(
            "command".into(),
            "curl -H sk-1234567890 password=hunter2".into(),
        );
        let mut chain = TrajectoryChain::new();
        chain.append(event(detail)).unwrap();
        let stored = &chain.events()[0].detail["command"];
        assert!(!stored.contains("1234567890"));
        assert!(!stored.contains("hunter2"));
        TrajectoryChain::verify(chain.events()).unwrap();

        let mut altered = chain.events().to_vec();
        altered[0].detail.insert("command".into(), "changed".into());
        assert_eq!(
            TrajectoryChain::verify(&altered),
            Err(ChainError::InvalidHash(0))
        );
    }

    #[test]
    fn ordered_detail_produces_the_same_hash() {
        let first = BTreeMap::from([("a".into(), "1".into()), ("b".into(), "2".into())]);
        let second = BTreeMap::from([("b".into(), "2".into()), ("a".into(), "1".into())]);
        let mut left = TrajectoryChain::new();
        let mut right = TrajectoryChain::new();
        left.append(event(first)).unwrap();
        right.append(event(second)).unwrap();
        assert_eq!(left.events()[0].hash, right.events()[0].hash);
    }
}
