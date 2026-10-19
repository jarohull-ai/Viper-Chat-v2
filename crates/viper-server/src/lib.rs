//! Loopback HTTP API for decisions and durable trajectory inspection.
//!
//! This crate exposes no tool executor. Bind only to loopback until an authenticated remote API
//! contract is designed.

use axum::extract::rejection::{JsonRejection, PathRejection, QueryRejection};
use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use viper_core::{Decision, ToolName, ToolProposal, VerdictStatus};
use viper_db::{CommittedEvent, LedgerAppender, TrajectoryDb};
use viper_seed::{
    Assessment, DecisionPipeline, GuardAction, GuardVerdict, PipelineError, SeedGate, ToolGuard,
};
use viper_trajectory::{EventInput, EventKind, HashedEvent};

const MAX_BODY_BYTES: usize = 64 * 1024;
const MAX_PAGE_SIZE: usize = 100;
const MAX_ID_LENGTH: usize = 128;
const MAX_ACTOR_LENGTH: usize = 128;
const MAX_ARGUMENTS: usize = 128;

/// Shared dependencies for HTTP handlers.
pub struct ServerState<G> {
    database: Arc<TrajectoryDb>,
    appender: LedgerAppender,
    guard: Arc<ToolGuard>,
    seed: Arc<G>,
}

impl<G: SeedGate> ServerState<G> {
    /// Creates server state from an already-opened database and validated policy.
    #[must_use]
    pub fn new(database: Arc<TrajectoryDb>, guard: ToolGuard, seed: G) -> Self {
        let appender = database.appender();
        Self {
            database,
            appender,
            guard: Arc::new(guard),
            seed: Arc::new(seed),
        }
    }
}

impl<G> Clone for ServerState<G> {
    fn clone(&self) -> Self {
        Self {
            database: Arc::clone(&self.database),
            appender: self.appender.clone(),
            guard: Arc::clone(&self.guard),
            seed: Arc::clone(&self.seed),
        }
    }
}

/// Builds the versioned HTTP API router.
pub fn router<G: SeedGate + 'static>(state: ServerState<G>) -> Router {
    Router::new()
        .route("/healthz", get(health))
        .route("/v1/decisions", post(submit_decision::<G>))
        .route("/v1/decisions/{proposal_id}", get(read_decision::<G>))
        .route("/v1/trajectory/events", get(read_events::<G>))
        .route("/v1/trajectory/verify", get(verify_trajectory::<G>))
        .fallback(not_found)
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state)
}

/// Binds an HTTP listener to IPv4 loopback only. Port zero requests an ephemeral port.
///
/// # Errors
///
/// Returns an operating-system bind error.
pub async fn bind_loopback(port: u16) -> std::io::Result<tokio::net::TcpListener> {
    tokio::net::TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)).await
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateDecisionRequest {
    id: String,
    trace_id: String,
    actor: String,
    tool: ToolName,
    arguments: BTreeMap<String, String>,
}

#[derive(Debug, Serialize)]
struct DecisionCreated {
    decision: Decision,
    guard: GuardSummary,
    committed_events: [EventReceipt; 2],
}

#[derive(Debug, Serialize)]
struct GuardSummary {
    action: &'static str,
    rule_id: Option<String>,
    category: Option<String>,
    policy_version: String,
    policy_digest: String,
}

impl From<&GuardVerdict> for GuardSummary {
    fn from(verdict: &GuardVerdict) -> Self {
        Self {
            action: guard_action_name(verdict.action),
            rule_id: verdict.rule_id.clone(),
            category: verdict.category.clone(),
            policy_version: verdict.policy_version.clone(),
            policy_digest: verdict.policy_digest.clone(),
        }
    }
}

#[derive(Debug, Serialize)]
struct EventReceipt {
    event_type: &'static str,
    sequence: u64,
    hash: String,
}

impl EventReceipt {
    fn from_committed(event_type: &'static str, event: &CommittedEvent) -> Self {
        Self {
            event_type,
            sequence: event.sequence(),
            hash: event.hash().to_owned(),
        }
    }
}

#[derive(Debug, Serialize)]
struct DecisionView {
    proposal_id: String,
    status: VerdictStatus,
    source: String,
    reason: String,
    guard_action: String,
    guard_rule_id: Option<String>,
    guard_category: Option<String>,
    policy_version: String,
    policy_digest: String,
    event_sequence: u64,
    event_hash: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EventQuery {
    after_sequence: Option<u64>,
    limit: Option<usize>,
}

#[derive(Debug, Serialize)]
struct EventPage {
    events: Vec<HashedEvent>,
    next_after_sequence: Option<u64>,
}

#[derive(Debug, Serialize)]
struct VerificationResponse {
    verified: bool,
    event_count: u64,
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}

async fn submit_decision<G: SeedGate + 'static>(
    State(state): State<ServerState<G>>,
    request: Result<Json<CreateDecisionRequest>, JsonRejection>,
) -> Result<Json<DecisionCreated>, ApiError> {
    let Json(request) = request.map_err(|error| ApiError::json_rejection(&error))?;
    validate_request(&request)?;
    let requested_at = now_rfc3339()?;
    let proposal = ToolProposal {
        id: request.id,
        trace_id: request.trace_id,
        actor: request.actor,
        tool: request.tool,
        arguments: request.arguments,
        requested_at: requested_at.clone(),
    };
    let proposed_id = format!("viper-server/v1/proposal/{}", proposal.id);
    if state
        .database
        .event_by_id(&proposed_id)
        .await
        .map_err(|_| ApiError::unavailable())?
        .is_some()
    {
        return Err(ApiError::conflict());
    }

    // Persist the proposal before contacting SEED. No decision is returned until its verdict
    // event has also reached durable COMMIT.
    let proposed = EventInput {
        id: proposed_id,
        trace_id: proposal.trace_id.clone(),
        occurred_at: requested_at.clone(),
        kind: EventKind::ToolProposed,
        detail: BTreeMap::from([
            ("proposal_id".into(), proposal.id.clone()),
            ("actor".into(), proposal.actor.clone()),
            ("tool".into(), proposal.tool.wire_name().to_owned()),
            (
                "command".into(),
                proposal.command().unwrap_or_default().to_owned(),
            ),
        ]),
    };
    let proposed_receipt = state
        .appender
        .append(proposed)
        .await
        .map_err(|_| ApiError::unavailable())?;

    let seed = SharedSeed(Arc::clone(&state.seed));
    let mut pipeline = DecisionPipeline::new((*state.guard).clone(), seed);
    let assessment = pipeline
        .assess(&proposal, &requested_at)
        .await
        .map_err(|error| ApiError::pipeline(&error))?;
    let verdict_receipt = state
        .appender
        .append(verdict_event(&proposal, &assessment, now_rfc3339()?))
        .await
        .map_err(|_| ApiError::unavailable())?;

    Ok(Json(DecisionCreated {
        decision: assessment.decision,
        guard: GuardSummary::from(&assessment.guard),
        committed_events: [
            EventReceipt::from_committed("tool_proposed", &proposed_receipt),
            EventReceipt::from_committed("seed_verdict", &verdict_receipt),
        ],
    }))
}

async fn read_decision<G: SeedGate + 'static>(
    State(state): State<ServerState<G>>,
    proposal_id: Result<Path<String>, PathRejection>,
) -> Result<Json<DecisionView>, ApiError> {
    let Path(proposal_id) = proposal_id.map_err(|_| ApiError::invalid_request())?;
    if proposal_id.is_empty() || proposal_id.len() > MAX_ID_LENGTH {
        return Err(ApiError::invalid_request());
    }
    state
        .database
        .verify()
        .await
        .map_err(|_| ApiError::unavailable())?;
    let event_id = format!("viper-server/v1/verdict/{proposal_id}");
    let Some(event) = state
        .database
        .event_by_id(&event_id)
        .await
        .map_err(|_| ApiError::unavailable())?
    else {
        return Err(ApiError::not_found());
    };
    let detail = &event.detail;
    let status = match detail.get("final_status").map(String::as_str) {
        Some("APPROVED") => VerdictStatus::Approved,
        Some("VETO_DENIED") => VerdictStatus::VetoDenied,
        Some("ESCALATE_PARLIAMENT") => VerdictStatus::EscalateParliament,
        _ => return Err(ApiError::unavailable()),
    };
    Ok(Json(DecisionView {
        proposal_id,
        status,
        source: required_detail(detail, "source")?,
        reason: required_detail(detail, "reason")?,
        guard_action: required_detail(detail, "guard_action")?,
        guard_rule_id: optional_detail(detail, "guard_rule_id"),
        guard_category: optional_detail(detail, "guard_category"),
        policy_version: required_detail(detail, "policy_version")?,
        policy_digest: required_detail(detail, "policy_digest")?,
        event_sequence: event.sequence,
        event_hash: event.hash,
    }))
}

async fn read_events<G: SeedGate + 'static>(
    State(state): State<ServerState<G>>,
    query: Result<Query<EventQuery>, QueryRejection>,
) -> Result<Json<EventPage>, ApiError> {
    let Query(query) = query.map_err(|_| ApiError::invalid_request())?;
    let limit = query.limit.unwrap_or(50);
    if !(1..=MAX_PAGE_SIZE).contains(&limit) {
        return Err(ApiError::invalid_request());
    }
    state
        .database
        .verify()
        .await
        .map_err(|_| ApiError::unavailable())?;
    let events = state
        .database
        .events_page(query.after_sequence, limit)
        .await
        .map_err(|_| ApiError::unavailable())?;
    let next_after_sequence = events.last().map(|event| event.sequence);
    Ok(Json(EventPage {
        events,
        next_after_sequence,
    }))
}

async fn verify_trajectory<G: SeedGate + 'static>(
    State(state): State<ServerState<G>>,
) -> Result<Json<VerificationResponse>, ApiError> {
    state
        .database
        .verify()
        .await
        .map_err(|_| ApiError::unavailable())?;
    let event_count = state
        .database
        .event_count()
        .await
        .map_err(|_| ApiError::unavailable())?;
    Ok(Json(VerificationResponse {
        verified: true,
        event_count,
    }))
}

async fn not_found() -> ApiError {
    ApiError::not_found()
}

fn validate_request(request: &CreateDecisionRequest) -> Result<(), ApiError> {
    if request.id.trim().is_empty()
        || request.id.len() > MAX_ID_LENGTH
        || request.trace_id.trim().is_empty()
        || request.trace_id.len() > MAX_ID_LENGTH
        || request.actor.trim().is_empty()
        || request.actor.len() > MAX_ACTOR_LENGTH
        || request.arguments.len() > MAX_ARGUMENTS
        || request
            .arguments
            .iter()
            .any(|(key, value)| key.is_empty() || key.len() > 128 || value.len() > 16 * 1024)
    {
        return Err(ApiError::invalid_request());
    }
    Ok(())
}

fn verdict_event(
    proposal: &ToolProposal,
    assessment: &Assessment,
    occurred_at: String,
) -> EventInput {
    let guard = &assessment.guard;
    EventInput {
        id: format!("viper-server/v1/verdict/{}", proposal.id),
        trace_id: proposal.trace_id.clone(),
        occurred_at,
        kind: EventKind::SeedVerdict,
        detail: BTreeMap::from([
            ("proposal_id".into(), proposal.id.clone()),
            (
                "final_status".into(),
                assessment.decision.status.wire_name().to_owned(),
            ),
            ("source".into(), assessment.decision.source.clone()),
            ("reason".into(), assessment.decision.reason.clone()),
            (
                "guard_action".into(),
                guard_action_name(guard.action).into(),
            ),
            (
                "guard_rule_id".into(),
                guard.rule_id.clone().unwrap_or_default(),
            ),
            (
                "guard_category".into(),
                guard.category.clone().unwrap_or_default(),
            ),
            ("policy_version".into(), guard.policy_version.clone()),
            ("policy_digest".into(), guard.policy_digest.clone()),
        ]),
    }
}

const fn guard_action_name(action: GuardAction) -> &'static str {
    match action {
        GuardAction::Allow => "ALLOW",
        GuardAction::Escalate => "ESCALATE",
        GuardAction::Block => "BLOCK",
    }
}

fn required_detail(detail: &BTreeMap<String, String>, key: &str) -> Result<String, ApiError> {
    detail.get(key).cloned().ok_or_else(ApiError::unavailable)
}

fn optional_detail(detail: &BTreeMap<String, String>, key: &str) -> Option<String> {
    detail.get(key).filter(|value| !value.is_empty()).cloned()
}

fn now_rfc3339() -> Result<String, ApiError> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ApiError::unavailable())?;
    let days = i64::try_from(elapsed.as_secs() / 86_400).map_err(|_| ApiError::unavailable())?;
    let day_seconds = elapsed.as_secs() % 86_400;
    let z = days + 719_468;
    let era = z / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    let hour = day_seconds / 3_600;
    let minute = (day_seconds % 3_600) / 60;
    let second = day_seconds % 60;
    Ok(format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z"
    ))
}

struct SharedSeed<G>(Arc<G>);

impl<G: SeedGate> SeedGate for SharedSeed<G> {
    async fn evaluate(
        &self,
        proposal: &ToolProposal,
        guard: &GuardVerdict,
    ) -> Result<Decision, viper_seed::SeedFailure> {
        self.0.evaluate(proposal, guard).await
    }
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    code: &'static str,
}

impl ApiError {
    const fn invalid_request() -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: "INVALID_REQUEST",
        }
    }

    fn json_rejection(rejection: &JsonRejection) -> Self {
        if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE {
            Self {
                status: StatusCode::PAYLOAD_TOO_LARGE,
                code: "PAYLOAD_TOO_LARGE",
            }
        } else {
            Self::invalid_request()
        }
    }

    const fn not_found() -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            code: "NOT_FOUND",
        }
    }

    const fn conflict() -> Self {
        Self {
            status: StatusCode::CONFLICT,
            code: "PROPOSAL_ALREADY_RECORDED",
        }
    }

    const fn unavailable() -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: "SERVICE_UNAVAILABLE",
        }
    }

    fn pipeline(error: &PipelineError) -> Self {
        match error {
            PipelineError::InvalidProposal(_) => Self::invalid_request(),
            PipelineError::Trajectory(_) => Self::conflict(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = Json(ErrorEnvelope {
            error: ErrorDetail { code: self.code },
        });
        (self.status, body).into_response()
    }
}

#[derive(Debug, Serialize)]
struct ErrorEnvelope {
    error: ErrorDetail,
}

#[derive(Debug, Serialize)]
struct ErrorDetail {
    code: &'static str,
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{Body, to_bytes};
    use axum::http::{Request, header::CONTENT_TYPE};
    use std::fs::{self, Permissions};
    use std::net::SocketAddr;
    use std::os::unix::fs::PermissionsExt;
    use std::time::Duration;
    use tempfile::TempDir;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixListener;
    use tower::ServiceExt;
    use viper_db::LedgerConfig;
    use viper_seed::ipc::{SeedIpcClient, SeedIpcConfig};
    use viper_seed::ipc_auth::{AuthKeyring, AuthProof, AuthTranscript, PeerRole, SessionRegistry};
    use viper_seed::policy::load_embedded;
    use viper_seed::{GuardLevel, SeedFailure};

    #[derive(Clone)]
    struct FixedSeed(Result<VerdictStatus, SeedFailure>);

    impl SeedGate for FixedSeed {
        async fn evaluate(
            &self,
            proposal: &ToolProposal,
            _guard: &GuardVerdict,
        ) -> Result<Decision, SeedFailure> {
            self.0.clone().map(|status| Decision {
                proposal_id: proposal.id.clone(),
                status,
                source: "integration-test-seed".into(),
                reason: "fixture".into(),
            })
        }
    }

    struct Harness {
        app: Router,
        _temp: TempDir,
    }

    async fn harness(seed: Result<VerdictStatus, SeedFailure>) -> Harness {
        let temp = tempfile::tempdir().unwrap();
        let database = Arc::new(
            TrajectoryDb::open(
                &temp.path().join("trajectory.sqlite3"),
                LedgerConfig::default(),
            )
            .await
            .unwrap(),
        );
        let guard = load_embedded(GuardLevel::Balanced).unwrap();
        let state = ServerState::new(database, guard, FixedSeed(seed));
        Harness {
            app: router(state),
            _temp: temp,
        }
    }

    fn request(method: &str, uri: &str, body: String) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(body))
            .unwrap()
    }

    async fn read_frame(stream: &mut tokio::net::UnixStream) -> serde_json::Value {
        let length = stream.read_u32().await.unwrap() as usize;
        let mut bytes = vec![0; length];
        stream.read_exact(&mut bytes).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    async fn write_frame(stream: &mut tokio::net::UnixStream, value: &serde_json::Value) {
        let bytes = serde_json::to_vec(value).unwrap();
        stream
            .write_u32(u32::try_from(bytes.len()).unwrap())
            .await
            .unwrap();
        stream.write_all(&bytes).await.unwrap();
    }

    fn decode_hex_32(value: &str) -> Result<[u8; 32], ()> {
        let bytes = value.as_bytes();
        if bytes.len() != 64 {
            return Err(());
        }
        let mut decoded = [0; 32];
        for (index, pair) in bytes.chunks_exact(2).enumerate() {
            let high = decode_hex_nibble(pair[0]).ok_or(())?;
            let low = decode_hex_nibble(pair[1]).ok_or(())?;
            decoded[index] = (high << 4) | low;
        }
        Ok(decoded)
    }

    fn decode_hex_nibble(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            _ => None,
        }
    }

    fn encode_hex(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut encoded = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        encoded
    }

    async fn mock_seed_provider(listener: UnixListener) {
        let (mut stream, _) = listener.accept().await.unwrap();
        let hello = read_frame(&mut stream).await;
        let session_id = hello["session_id"].as_str().unwrap().to_owned();
        let client_nonce = decode_hex_32(hello["client_nonce"].as_str().unwrap()).unwrap();
        let provider_nonce = [0x22; 32];
        write_frame(
            &mut stream,
            &serde_json::json!({
                "protocol": "viper.seed.ipc.v1",
                "kind": "server_challenge",
                "session_id": &session_id,
                "provider_nonce": encode_hex(&provider_nonce),
            }),
        )
        .await;

        let client_auth = read_frame(&mut stream).await;
        let key_id = client_auth["key_id"].as_str().unwrap().to_owned();
        let keys = AuthKeyring::bootstrap("integration-key", [0x41; 32]).unwrap();
        let client_transcript = AuthTranscript {
            key_id: key_id.clone(),
            session_id: session_id.clone(),
            client_nonce,
            provider_nonce,
            role: PeerRole::Client,
        };
        let client_proof = AuthProof {
            key_id,
            tag: decode_hex_32(client_auth["tag"].as_str().unwrap()).unwrap(),
        };
        let mut sessions = SessionRegistry::new(4).unwrap();
        sessions
            .accept_new(&keys, &client_transcript, &client_proof, 100, 30)
            .unwrap();
        let provider_proof = keys
            .sign_new_session(AuthTranscript {
                role: PeerRole::Provider,
                ..client_transcript
            })
            .unwrap();
        write_frame(
            &mut stream,
            &serde_json::json!({
                "protocol": "viper.seed.ipc.v1",
                "kind": "server_authentication",
                "session_id": &session_id,
                "key_id": provider_proof.proof.key_id,
                "tag": encode_hex(&provider_proof.proof.tag),
            }),
        )
        .await;

        let decision_request = read_frame(&mut stream).await;
        assert_eq!(decision_request["proposal_id"], "http-ipc-proposal");
        assert_eq!(
            decision_request["guard"]["policy_digest"]
                .as_str()
                .unwrap()
                .len(),
            64
        );
        write_frame(
            &mut stream,
            &serde_json::json!({
                "protocol": "viper.seed.ipc.v1",
                "kind": "decision_response",
                "request_id": decision_request["request_id"],
                "proposal_id": decision_request["proposal_id"],
                "verdict": "APPROVED",
                "reason_code": "INTEGRATION_TEST",
                "explanation": "mock provider approved",
            }),
        )
        .await;
        stream.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn http_decision_uses_authenticated_ipc_and_commits_before_reply() {
        let temp = tempfile::tempdir().unwrap();
        let runtime = temp.path().join("runtime");
        fs::create_dir(&runtime).unwrap();
        fs::set_permissions(&runtime, Permissions::from_mode(0o700)).unwrap();
        let socket = runtime.join("seed.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        fs::set_permissions(&socket, Permissions::from_mode(0o600)).unwrap();
        let provider = tokio::spawn(mock_seed_provider(listener));
        let seed = SeedIpcClient::new(
            SeedIpcConfig {
                runtime_dir: runtime,
                socket_path: socket,
                connect_timeout: Duration::from_millis(250),
                response_timeout: Duration::from_secs(1),
            },
            AuthKeyring::bootstrap("integration-key", [0x41; 32]).unwrap(),
        )
        .unwrap();
        let database = Arc::new(
            TrajectoryDb::open(
                &temp.path().join("trajectory.sqlite3"),
                LedgerConfig::default(),
            )
            .await
            .unwrap(),
        );
        let guard = load_embedded(GuardLevel::Balanced).unwrap();
        let app = router(ServerState::new(database, guard, seed));

        let response = app
            .clone()
            .oneshot(request(
                "POST",
                "/v1/decisions",
                r#"{"id":"http-ipc-proposal","trace_id":"integration-trace","actor":"integration-test","tool":"terminal_run","arguments":{"command":"echo safe"}}"#.into(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), MAX_BODY_BYTES)
            .await
            .unwrap();
        let created: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(created["decision"]["status"], "APPROVED");
        assert_eq!(created["committed_events"][1]["sequence"], 1);
        provider.await.unwrap();

        let response = app
            .oneshot(request("GET", "/v1/trajectory/verify", String::new()))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), MAX_BODY_BYTES)
            .await
            .unwrap();
        let verification: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(verification["verified"], true);
        assert_eq!(verification["event_count"], 2);
    }

    #[tokio::test]
    async fn decision_is_committed_before_response_and_readable() {
        let harness = harness(Ok(VerdictStatus::Approved)).await;
        let response = harness
            .app
            .clone()
            .oneshot(request(
                "POST",
                "/v1/decisions",
                r#"{"id":"proposal-1","trace_id":"trace-1","actor":"test-agent","tool":"terminal_run","arguments":{"command":"echo safe"}}"#.into(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), MAX_BODY_BYTES)
            .await
            .unwrap();
        let created: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(created["decision"]["status"], "APPROVED");
        assert_eq!(created["committed_events"][0]["sequence"], 0);
        assert_eq!(created["committed_events"][1]["sequence"], 1);

        let response = harness
            .app
            .clone()
            .oneshot(request("GET", "/v1/decisions/proposal-1", String::new()))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), MAX_BODY_BYTES)
            .await
            .unwrap();
        let decision: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(decision["status"], "APPROVED");
        assert_eq!(decision["event_sequence"], 1);

        let response = harness
            .app
            .clone()
            .oneshot(request(
                "GET",
                "/v1/trajectory/events?limit=10",
                String::new(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), MAX_BODY_BYTES)
            .await
            .unwrap();
        let page: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(page["events"].as_array().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn unavailable_seed_returns_only_a_durable_veto() {
        let harness = harness(Err(SeedFailure {
            message: "fixture-unavailable".into(),
        }))
        .await;
        let response = harness
            .app
            .clone()
            .oneshot(request(
                "POST",
                "/v1/decisions",
                r#"{"id":"proposal-down","trace_id":"trace-1","actor":"test-agent","tool":"terminal_run","arguments":{"command":"echo safe"}}"#.into(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), MAX_BODY_BYTES)
            .await
            .unwrap();
        let created: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(created["decision"]["status"], "VETO_DENIED");

        let response = harness
            .app
            .oneshot(request("GET", "/v1/trajectory/verify", String::new()))
            .await
            .unwrap();
        let body = to_bytes(response.into_body(), MAX_BODY_BYTES)
            .await
            .unwrap();
        let verification: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(verification["verified"], true);
        assert_eq!(verification["event_count"], 2);
    }

    #[tokio::test]
    async fn unknown_fields_and_oversized_bodies_are_machine_readable() {
        let harness = harness(Ok(VerdictStatus::Approved)).await;
        let response = harness
            .app
            .clone()
            .oneshot(request(
                "POST",
                "/v1/decisions",
                r#"{"id":"proposal-1","trace_id":"trace-1","actor":"test-agent","tool":"terminal_run","arguments":{},"execute":true}"#.into(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(response.into_body(), MAX_BODY_BYTES)
            .await
            .unwrap();
        let error: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(error["error"]["code"], "INVALID_REQUEST");

        let response = harness
            .app
            .clone()
            .oneshot(request(
                "POST",
                "/v1/decisions",
                format!("{{\"padding\":\"{}\"}}", "x".repeat(MAX_BODY_BYTES)),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        let body = to_bytes(response.into_body(), 1024).await.unwrap();
        let error: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(error["error"]["code"], "PAYLOAD_TOO_LARGE");

        let response = harness
            .app
            .oneshot(request("GET", "/v1/trajectory/verify", String::new()))
            .await
            .unwrap();
        let body = to_bytes(response.into_body(), MAX_BODY_BYTES)
            .await
            .unwrap();
        let verification: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(verification["event_count"], 0);
    }

    #[tokio::test]
    async fn unknown_routes_use_stable_json_errors() {
        let harness = harness(Ok(VerdictStatus::Approved)).await;
        let response = harness
            .app
            .oneshot(request("GET", "/not-an-api", String::new()))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = to_bytes(response.into_body(), MAX_BODY_BYTES)
            .await
            .unwrap();
        let error: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(error["error"]["code"], "NOT_FOUND");
    }

    #[tokio::test]
    async fn loopback_binder_never_selects_a_wildcard_interface() {
        let listener = bind_loopback(0).await.unwrap();
        assert_eq!(
            listener.local_addr().unwrap(),
            SocketAddr::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                listener.local_addr().unwrap().port()
            )
        );
    }

    #[test]
    fn server_timestamp_is_rfc3339_utc() {
        let timestamp = now_rfc3339().unwrap();
        assert!(timestamp.ends_with('Z'));
        assert_eq!(timestamp.len(), 20);
    }
}
