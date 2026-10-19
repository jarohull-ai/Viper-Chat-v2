//! Authenticated, fail-closed Unix-socket transport for external SEED providers.

use crate::ipc_auth::{AuthKeyring, AuthProof, AuthTranscript, PeerRole};
use crate::{GuardAction, GuardVerdict, SeedFailure, SeedGate};
use getrandom::fill as fill_random;
use rustix::process::geteuid;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::ErrorKind;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::time::Duration;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::time::timeout;
use viper_core::{Decision, ToolProposal, VerdictStatus};

const PROTOCOL: &str = "viper.seed.ipc.v1";
const MAX_FRAME_BYTES: usize = 64 * 1024;
const MAX_TIMEOUT: Duration = Duration::from_secs(5);

/// Stable fail-closed IPC error categories. Raw payloads and OS details are never included.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpcErrorCode {
    /// Client configuration violates a hard security bound.
    InvalidConfiguration,
    /// Runtime directory or socket metadata is unsafe.
    UnsafeSocket,
    /// Connection did not complete inside its dedicated deadline.
    ConnectTimeout,
    /// The provider could not be reached or the stream failed.
    Unavailable,
    /// Authentication or peer identity validation failed.
    Authentication,
    /// The full authenticated exchange exceeded its deadline.
    ResponseTimeout,
    /// A frame was empty, truncated, oversized or followed by extra data.
    InvalidFrame,
    /// JSON, protocol version, message kind or a bound identifier was invalid.
    InvalidProtocol,
}

/// Sanitized transport failure suitable for conversion into a recorded VETO.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("SEED IPC failed closed: {code:?}")]
pub struct IpcError {
    /// Stable machine-readable category.
    pub code: IpcErrorCode,
}

impl IpcError {
    const fn new(code: IpcErrorCode) -> Self {
        Self { code }
    }
}

impl From<IpcError> for SeedFailure {
    fn from(error: IpcError) -> Self {
        Self {
            message: format!("ipc/{:?}", error.code),
        }
    }
}

/// Bounded Unix-socket client settings.
#[derive(Debug, Clone)]
pub struct SeedIpcConfig {
    /// Private mode-0700 directory containing the socket.
    pub runtime_dir: PathBuf,
    /// Socket path directly inside `runtime_dir`.
    pub socket_path: PathBuf,
    /// Deadline for establishing the Unix connection.
    pub connect_timeout: Duration,
    /// Deadline for authentication, request, response and clean EOF.
    pub response_timeout: Duration,
}

impl SeedIpcConfig {
    /// Creates settings with Phase 1 timeout defaults.
    #[must_use]
    pub fn with_defaults(runtime_dir: PathBuf, socket_path: PathBuf) -> Self {
        Self {
            runtime_dir,
            socket_path,
            connect_timeout: Duration::from_millis(250),
            response_timeout: Duration::from_secs(1),
        }
    }

    fn validate(&self) -> Result<(), IpcError> {
        if !self.runtime_dir.is_absolute()
            || !self.socket_path.is_absolute()
            || self.socket_path.parent() != Some(self.runtime_dir.as_path())
            || self.connect_timeout.is_zero()
            || self.response_timeout.is_zero()
            || self.connect_timeout > MAX_TIMEOUT
            || self.response_timeout > MAX_TIMEOUT
        {
            return Err(IpcError::new(IpcErrorCode::InvalidConfiguration));
        }
        Ok(())
    }
}

/// Tool Guard action sent as evidence, never as an execution authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SeedGuardAction {
    /// Tool Guard did not add a restriction.
    Allow,
    /// Human authorization is required.
    Escalate,
    /// Tool Guard refused the proposal.
    Block,
}

/// Versioned Tool Guard evidence bound into a SEED request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeedGuardEvidence {
    /// Guard action for this proposal.
    pub action: SeedGuardAction,
    /// Stable first-hit rule identifier, when one matched.
    pub matched_rule_id: Option<String>,
    /// Loaded policy version.
    pub policy_version: String,
    /// Lowercase SHA-256 digest of the policy artifact.
    pub policy_digest: String,
}

impl SeedGuardEvidence {
    /// Copies the evaluated, versioned Tool Guard result into the IPC request contract.
    #[must_use]
    pub fn from_verdict(verdict: &GuardVerdict) -> Self {
        Self {
            action: match verdict.action {
                GuardAction::Allow => SeedGuardAction::Allow,
                GuardAction::Escalate => SeedGuardAction::Escalate,
                GuardAction::Block => SeedGuardAction::Block,
            },
            matched_rule_id: verdict.rule_id.clone(),
            policy_version: verdict.policy_version.clone(),
            policy_digest: verdict.policy_digest.clone(),
        }
    }

    fn validate(&self) -> Result<(), IpcError> {
        if self.policy_version.trim().is_empty()
            || !is_lower_hex_32(&self.policy_digest)
            || self
                .matched_rule_id
                .as_ref()
                .is_some_and(|rule| rule.trim().is_empty())
        {
            return Err(IpcError::new(IpcErrorCode::InvalidProtocol));
        }
        Ok(())
    }
}

/// Async client for one authenticated decision per Unix connection.
pub struct SeedIpcClient {
    config: SeedIpcConfig,
    keys: AuthKeyring,
}

impl SeedIpcClient {
    /// Constructs a client. Filesystem state is revalidated for every connection.
    ///
    /// # Errors
    ///
    /// Rejects relative paths, a socket outside the runtime directory, zero timeouts, or timeout
    /// values above the five-second hard ceiling.
    pub fn new(config: SeedIpcConfig, keys: AuthKeyring) -> Result<Self, IpcError> {
        config.validate()?;
        Ok(Self { config, keys })
    }

    /// Authenticates a fresh single-request connection and obtains a bound SEED verdict.
    ///
    /// This method never retries. Every metadata, identity, framing, authentication, timeout or
    /// response-validation failure returns a sanitized error that the caller must record as VETO.
    ///
    /// # Errors
    ///
    /// Returns a fail-closed [`IpcError`] for any untrusted or unavailable provider behavior.
    pub async fn evaluate(
        &self,
        proposal: &ToolProposal,
        guard: &SeedGuardEvidence,
    ) -> Result<Decision, IpcError> {
        proposal
            .validate()
            .map_err(|_| IpcError::new(IpcErrorCode::InvalidProtocol))?;
        guard.validate()?;
        validate_socket_metadata(&self.config.runtime_dir, &self.config.socket_path)?;

        let mut stream = timeout(
            self.config.connect_timeout,
            UnixStream::connect(&self.config.socket_path),
        )
        .await
        .map_err(|_| IpcError::new(IpcErrorCode::ConnectTimeout))?
        .map_err(|_| IpcError::new(IpcErrorCode::Unavailable))?;
        validate_peer(&stream)?;

        timeout(
            self.config.response_timeout,
            self.exchange(&mut stream, proposal, guard),
        )
        .await
        .map_err(|_| IpcError::new(IpcErrorCode::ResponseTimeout))?
    }

    async fn exchange(
        &self,
        stream: &mut UnixStream,
        proposal: &ToolProposal,
        guard: &SeedGuardEvidence,
    ) -> Result<Decision, IpcError> {
        self.authenticate(stream).await?;
        self.request_decision(stream, proposal, guard).await
    }

    async fn authenticate(&self, stream: &mut UnixStream) -> Result<(), IpcError> {
        let session_id = random_identifier("session")?;
        let client_nonce = random_array()?;
        write_frame(
            stream,
            &ClientHello {
                protocol: PROTOCOL.to_owned(),
                kind: "client_hello".into(),
                session_id: session_id.clone(),
                client_nonce: encode_hex(&client_nonce),
            },
        )
        .await?;

        let challenge: ServerChallenge = read_frame(stream).await?;
        require_header(
            &challenge.protocol,
            &challenge.kind,
            "server_challenge",
            &challenge.session_id,
            &session_id,
        )?;
        let provider_nonce = decode_hex_32(&challenge.provider_nonce)?;
        let client_signed = self
            .keys
            .sign_new_session(AuthTranscript {
                key_id: String::new(),
                session_id: session_id.clone(),
                client_nonce,
                provider_nonce,
                role: PeerRole::Client,
            })
            .map_err(|_| IpcError::new(IpcErrorCode::Authentication))?;
        write_frame(
            stream,
            &ClientAuthentication {
                protocol: PROTOCOL.into(),
                kind: "client_authentication".into(),
                session_id: session_id.clone(),
                key_id: client_signed.proof.key_id.clone(),
                tag: encode_hex(&client_signed.proof.tag),
            },
        )
        .await?;

        let provider_auth: ServerAuthentication = read_frame(stream).await?;
        require_header(
            &provider_auth.protocol,
            &provider_auth.kind,
            "server_authentication",
            &provider_auth.session_id,
            &session_id,
        )?;
        if provider_auth.key_id != client_signed.proof.key_id {
            return Err(IpcError::new(IpcErrorCode::Authentication));
        }
        self.keys
            .verify_active_proof(
                &AuthTranscript {
                    key_id: provider_auth.key_id.clone(),
                    session_id: session_id.clone(),
                    client_nonce,
                    provider_nonce,
                    role: PeerRole::Provider,
                },
                &AuthProof {
                    key_id: provider_auth.key_id,
                    tag: decode_hex_32(&provider_auth.tag)?,
                },
            )
            .map_err(|_| IpcError::new(IpcErrorCode::Authentication))?;
        Ok(())
    }

    async fn request_decision(
        &self,
        stream: &mut UnixStream,
        proposal: &ToolProposal,
        guard: &SeedGuardEvidence,
    ) -> Result<Decision, IpcError> {
        let request_id = random_identifier("request")?;
        write_frame(
            stream,
            &DecisionRequest {
                protocol: PROTOCOL.into(),
                kind: "decision_request".into(),
                request_id: request_id.clone(),
                proposal_id: proposal.id.clone(),
                trace_id: proposal.trace_id.clone(),
                timestamp: proposal.requested_at.clone(),
                tool: proposal.tool.wire_name().to_owned(),
                arguments: proposal.arguments.clone(),
                guard: guard.clone(),
            },
        )
        .await?;

        let response: DecisionResponse = read_frame(stream).await?;
        require_message(&response.protocol, &response.kind, "decision_response")?;
        if response.request_id != request_id
            || response.proposal_id != proposal.id
            || response.reason_code.trim().is_empty()
            || response.explanation.trim().is_empty()
            || response.reason_code.len() > 128
            || response.explanation.len() > 1_024
        {
            return Err(IpcError::new(IpcErrorCode::InvalidProtocol));
        }

        let mut trailing = [0_u8; 1];
        match stream.read(&mut trailing).await {
            Ok(0) => {}
            Ok(_) => return Err(IpcError::new(IpcErrorCode::InvalidFrame)),
            Err(error) if error.kind() == ErrorKind::UnexpectedEof => {}
            Err(_) => return Err(IpcError::new(IpcErrorCode::Unavailable)),
        }
        Ok(Decision {
            proposal_id: response.proposal_id,
            status: response.verdict,
            source: "seed_ipc/v1".into(),
            reason: format!("{}: {}", response.reason_code, response.explanation),
        })
    }
}

impl SeedGate for SeedIpcClient {
    async fn evaluate(
        &self,
        proposal: &ToolProposal,
        guard: &GuardVerdict,
    ) -> Result<Decision, SeedFailure> {
        SeedIpcClient::evaluate(self, proposal, &SeedGuardEvidence::from_verdict(guard))
            .await
            .map_err(SeedFailure::from)
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientHello {
    protocol: String,
    kind: String,
    session_id: String,
    client_nonce: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServerChallenge {
    protocol: String,
    kind: String,
    session_id: String,
    provider_nonce: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientAuthentication {
    protocol: String,
    kind: String,
    session_id: String,
    key_id: String,
    tag: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServerAuthentication {
    protocol: String,
    kind: String,
    session_id: String,
    key_id: String,
    tag: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DecisionRequest {
    protocol: String,
    kind: String,
    request_id: String,
    proposal_id: String,
    trace_id: String,
    timestamp: String,
    tool: String,
    arguments: BTreeMap<String, String>,
    guard: SeedGuardEvidence,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DecisionResponse {
    protocol: String,
    kind: String,
    request_id: String,
    proposal_id: String,
    verdict: VerdictStatus,
    reason_code: String,
    explanation: String,
}

fn validate_socket_metadata(runtime_dir: &Path, socket_path: &Path) -> Result<(), IpcError> {
    let expected_uid = geteuid().as_raw();
    let runtime = std::fs::symlink_metadata(runtime_dir)
        .map_err(|_| IpcError::new(IpcErrorCode::UnsafeSocket))?;
    if !runtime.file_type().is_dir()
        || runtime.uid() != expected_uid
        || runtime.mode() & 0o777 != 0o700
    {
        return Err(IpcError::new(IpcErrorCode::UnsafeSocket));
    }
    let socket = std::fs::symlink_metadata(socket_path)
        .map_err(|_| IpcError::new(IpcErrorCode::UnsafeSocket))?;
    if !socket.file_type().is_socket() || socket.uid() != expected_uid || socket.mode() & 0o077 != 0
    {
        return Err(IpcError::new(IpcErrorCode::UnsafeSocket));
    }
    Ok(())
}

fn validate_peer(stream: &UnixStream) -> Result<(), IpcError> {
    let peer = stream
        .peer_cred()
        .map_err(|_| IpcError::new(IpcErrorCode::Authentication))?;
    validate_peer_uid(peer.uid(), geteuid().as_raw())
}

fn validate_peer_uid(peer_uid: u32, expected_uid: u32) -> Result<(), IpcError> {
    if peer_uid != expected_uid {
        return Err(IpcError::new(IpcErrorCode::Authentication));
    }
    Ok(())
}

async fn write_frame<T: Serialize>(stream: &mut UnixStream, value: &T) -> Result<(), IpcError> {
    let bytes =
        serde_json::to_vec(value).map_err(|_| IpcError::new(IpcErrorCode::InvalidProtocol))?;
    if bytes.is_empty() || bytes.len() > MAX_FRAME_BYTES {
        return Err(IpcError::new(IpcErrorCode::InvalidFrame));
    }
    let length =
        u32::try_from(bytes.len()).map_err(|_| IpcError::new(IpcErrorCode::InvalidFrame))?;
    stream
        .write_all(&length.to_be_bytes())
        .await
        .map_err(|_| IpcError::new(IpcErrorCode::Unavailable))?;
    stream
        .write_all(&bytes)
        .await
        .map_err(|_| IpcError::new(IpcErrorCode::Unavailable))?;
    Ok(())
}

async fn read_frame<T: DeserializeOwned>(stream: &mut UnixStream) -> Result<T, IpcError> {
    let mut prefix = [0_u8; 4];
    stream
        .read_exact(&mut prefix)
        .await
        .map_err(|error| map_read_error(&error))?;
    let length = usize::try_from(u32::from_be_bytes(prefix))
        .map_err(|_| IpcError::new(IpcErrorCode::InvalidFrame))?;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(IpcError::new(IpcErrorCode::InvalidFrame));
    }
    let mut bytes = vec![0_u8; length];
    stream
        .read_exact(&mut bytes)
        .await
        .map_err(|error| map_read_error(&error))?;
    let json =
        std::str::from_utf8(&bytes).map_err(|_| IpcError::new(IpcErrorCode::InvalidProtocol))?;
    serde_json::from_str(json).map_err(|_| IpcError::new(IpcErrorCode::InvalidProtocol))
}

fn map_read_error(error: &std::io::Error) -> IpcError {
    if error.kind() == ErrorKind::UnexpectedEof {
        IpcError::new(IpcErrorCode::InvalidFrame)
    } else {
        IpcError::new(IpcErrorCode::Unavailable)
    }
}

fn require_header(
    protocol: &str,
    kind: &str,
    expected_kind: &str,
    session_id: &str,
    expected_session_id: &str,
) -> Result<(), IpcError> {
    require_message(protocol, kind, expected_kind)?;
    if session_id != expected_session_id {
        return Err(IpcError::new(IpcErrorCode::Authentication));
    }
    Ok(())
}

fn require_message(protocol: &str, kind: &str, expected_kind: &str) -> Result<(), IpcError> {
    if protocol != PROTOCOL || kind != expected_kind {
        return Err(IpcError::new(IpcErrorCode::InvalidProtocol));
    }
    Ok(())
}

fn random_identifier(prefix: &str) -> Result<String, IpcError> {
    let bytes: [u8; 16] = random_array()?;
    Ok(format!("{prefix}-{}", encode_hex(&bytes)))
}

fn random_array<const N: usize>() -> Result<[u8; N], IpcError> {
    let mut bytes = [0_u8; N];
    fill_random(&mut bytes).map_err(|_| IpcError::new(IpcErrorCode::Authentication))?;
    Ok(bytes)
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn decode_hex_32(value: &str) -> Result<[u8; 32], IpcError> {
    if value.len() != 64 {
        return Err(IpcError::new(IpcErrorCode::Authentication));
    }
    let mut output = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (decode_nibble(pair[0])? << 4) | decode_nibble(pair[1])?;
    }
    Ok(output)
}

fn decode_nibble(byte: u8) -> Result<u8, IpcError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(IpcError::new(IpcErrorCode::Authentication)),
    }
}

fn is_lower_hex_32(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc_auth::SessionRegistry;
    use crate::policy;
    use std::fs::{self, Permissions};
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;
    use tempfile::TempDir;
    use tokio::net::UnixListener;

    const KEY: [u8; 32] = [0x41; 32];
    static SOCKET_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    struct Fixture {
        _temp: TempDir,
        runtime: PathBuf,
        socket: PathBuf,
        listener: UnixListener,
    }

    fn fixture() -> Fixture {
        let temp = tempfile::tempdir().unwrap();
        let runtime = temp.path().join("runtime");
        fs::create_dir(&runtime).unwrap();
        fs::set_permissions(&runtime, Permissions::from_mode(0o700)).unwrap();
        let socket = runtime.join("seed.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        fs::set_permissions(&socket, Permissions::from_mode(0o600)).unwrap();
        Fixture {
            _temp: temp,
            runtime,
            socket,
            listener,
        }
    }

    fn client(runtime: PathBuf, socket: PathBuf) -> SeedIpcClient {
        SeedIpcClient::new(
            SeedIpcConfig {
                runtime_dir: runtime,
                socket_path: socket,
                connect_timeout: Duration::from_millis(100),
                response_timeout: Duration::from_millis(500),
            },
            AuthKeyring::bootstrap("key-active", KEY).unwrap(),
        )
        .unwrap()
    }

    fn proposal() -> ToolProposal {
        ToolProposal {
            id: "proposal-1".into(),
            trace_id: "trace-1".into(),
            actor: "test-agent".into(),
            tool: viper_core::ToolName::TerminalRun,
            arguments: BTreeMap::from([("command".into(), "cargo test".into())]),
            requested_at: "2026-10-18T19:00:00Z".into(),
        }
    }

    fn guard() -> SeedGuardEvidence {
        SeedGuardEvidence {
            action: SeedGuardAction::Allow,
            matched_rule_id: None,
            policy_version: "phase1-test".into(),
            policy_digest: "a".repeat(64),
        }
    }

    #[test]
    fn guard_evidence_is_derived_from_loaded_policy_verdict() {
        let tool_guard = policy::load_embedded(crate::GuardLevel::Balanced).unwrap();
        let verdict = tool_guard.check_command("cat .env", false);
        let evidence = SeedGuardEvidence::from_verdict(&verdict);
        assert_eq!(evidence.action, SeedGuardAction::Block);
        assert_eq!(evidence.matched_rule_id.as_deref(), Some("TG-001"));
        assert_eq!(evidence.policy_version, "viper.tool_guard.v1");
        assert_eq!(evidence.policy_digest, tool_guard.policy_digest());
    }

    async fn authenticated_server(
        listener: UnixListener,
        verdict: VerdictStatus,
        mutate_proposal_id: bool,
        send_trailing_frame: bool,
    ) {
        let (mut stream, _) = listener.accept().await.unwrap();
        let hello: ClientHello = read_frame(&mut stream).await.unwrap();
        let client_nonce = decode_hex_32(&hello.client_nonce).unwrap();
        let provider_nonce = [0x22; 32];
        write_frame(
            &mut stream,
            &ServerChallenge {
                protocol: PROTOCOL.into(),
                kind: "server_challenge".into(),
                session_id: hello.session_id.clone(),
                provider_nonce: encode_hex(&provider_nonce),
            },
        )
        .await
        .unwrap();
        let authentication: ClientAuthentication = read_frame(&mut stream).await.unwrap();
        let keys = AuthKeyring::bootstrap("key-active", KEY).unwrap();
        let transcript = AuthTranscript {
            key_id: authentication.key_id.clone(),
            session_id: hello.session_id.clone(),
            client_nonce,
            provider_nonce,
            role: PeerRole::Client,
        };
        let proof = AuthProof {
            key_id: authentication.key_id,
            tag: decode_hex_32(&authentication.tag).unwrap(),
        };
        let mut sessions = SessionRegistry::new(4).unwrap();
        sessions
            .accept_new(&keys, &transcript, &proof, 100, 30)
            .unwrap();
        let provider = keys
            .sign_new_session(AuthTranscript {
                role: PeerRole::Provider,
                ..transcript
            })
            .unwrap();
        write_frame(
            &mut stream,
            &ServerAuthentication {
                protocol: PROTOCOL.into(),
                kind: "server_authentication".into(),
                session_id: hello.session_id,
                key_id: provider.proof.key_id,
                tag: encode_hex(&provider.proof.tag),
            },
        )
        .await
        .unwrap();
        let request: DecisionRequest = read_frame(&mut stream).await.unwrap();
        assert_eq!(request.guard.action, SeedGuardAction::Allow);
        assert!(!request.guard.policy_version.is_empty());
        assert_eq!(request.guard.policy_digest.len(), 64);
        assert!(request.guard.matched_rule_id.is_none());
        let response = DecisionResponse {
            protocol: PROTOCOL.into(),
            kind: "decision_response".into(),
            request_id: request.request_id,
            proposal_id: if mutate_proposal_id {
                "different-proposal".into()
            } else {
                request.proposal_id
            },
            verdict,
            reason_code: "TEST_FIXTURE".into(),
            explanation: "deterministic provider response".into(),
        };
        write_frame(&mut stream, &response).await.unwrap();
        if send_trailing_frame {
            write_frame(&mut stream, &response).await.unwrap();
        }
        stream.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn authenticates_and_returns_bound_verdict() {
        let _serial = SOCKET_TEST_LOCK.lock().await;
        let fixture = fixture();
        let client = client(fixture.runtime.clone(), fixture.socket.clone());
        let server = tokio::spawn(authenticated_server(
            fixture.listener,
            VerdictStatus::Approved,
            false,
            false,
        ));
        let decision = client.evaluate(&proposal(), &guard()).await.unwrap();
        assert_eq!(decision.proposal_id, "proposal-1");
        assert_eq!(decision.status, VerdictStatus::Approved);
        assert_eq!(decision.source, "seed_ipc/v1");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn decision_pipeline_uses_async_ipc_gate_with_loaded_guard_evidence() {
        let _serial = SOCKET_TEST_LOCK.lock().await;
        let fixture = fixture();
        let client = client(fixture.runtime.clone(), fixture.socket.clone());
        let server = tokio::spawn(authenticated_server(
            fixture.listener,
            VerdictStatus::Approved,
            false,
            false,
        ));
        let guard = policy::load_embedded(crate::GuardLevel::Balanced).unwrap();
        let expected_digest = guard.policy_digest().to_owned();
        let mut pipeline = crate::DecisionPipeline::new(guard, client);
        let assessment = pipeline
            .assess(&proposal(), "2026-10-18T19:00:01Z")
            .await
            .unwrap();
        assert_eq!(assessment.decision.status, VerdictStatus::Approved);
        assert_eq!(pipeline.trajectory().events().len(), 2);
        let verdict_event = &pipeline.trajectory().events()[1];
        assert_eq!(
            verdict_event
                .detail
                .get("tool_guard_version")
                .map(String::as_str),
            Some("viper.tool_guard.v1")
        );
        assert_eq!(
            verdict_event
                .detail
                .get("tool_guard_digest")
                .map(String::as_str),
            Some(expected_digest.as_str())
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn rejects_response_bound_to_another_proposal() {
        let _serial = SOCKET_TEST_LOCK.lock().await;
        let fixture = fixture();
        let client = client(fixture.runtime.clone(), fixture.socket.clone());
        let server = tokio::spawn(authenticated_server(
            fixture.listener,
            VerdictStatus::Approved,
            true,
            false,
        ));
        assert_eq!(
            client
                .evaluate(&proposal(), &guard())
                .await
                .unwrap_err()
                .code,
            IpcErrorCode::InvalidProtocol
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn rejects_duplicate_or_trailing_response_data() {
        let _serial = SOCKET_TEST_LOCK.lock().await;
        let fixture = fixture();
        let client = client(fixture.runtime.clone(), fixture.socket.clone());
        let server = tokio::spawn(authenticated_server(
            fixture.listener,
            VerdictStatus::VetoDenied,
            false,
            true,
        ));
        assert_eq!(
            client
                .evaluate(&proposal(), &guard())
                .await
                .unwrap_err()
                .code,
            IpcErrorCode::InvalidFrame
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn rejects_invalid_provider_hmac() {
        let _serial = SOCKET_TEST_LOCK.lock().await;
        let fixture = fixture();
        let client = client(fixture.runtime.clone(), fixture.socket.clone());
        let server = tokio::spawn(async move {
            let (mut stream, _) = fixture.listener.accept().await.unwrap();
            let hello: ClientHello = read_frame(&mut stream).await.unwrap();
            write_frame(
                &mut stream,
                &ServerChallenge {
                    protocol: PROTOCOL.into(),
                    kind: "server_challenge".into(),
                    session_id: hello.session_id.clone(),
                    provider_nonce: "2".repeat(64),
                },
            )
            .await
            .unwrap();
            let authentication: ClientAuthentication = read_frame(&mut stream).await.unwrap();
            write_frame(
                &mut stream,
                &ServerAuthentication {
                    protocol: PROTOCOL.into(),
                    kind: "server_authentication".into(),
                    session_id: hello.session_id,
                    key_id: authentication.key_id,
                    tag: "0".repeat(64),
                },
            )
            .await
            .unwrap();
            stream.shutdown().await.unwrap();
        });
        assert_eq!(
            client
                .evaluate(&proposal(), &guard())
                .await
                .unwrap_err()
                .code,
            IpcErrorCode::Authentication
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn response_deadline_covers_the_entire_handshake() {
        let _serial = SOCKET_TEST_LOCK.lock().await;
        let fixture = fixture();
        let client = SeedIpcClient::new(
            SeedIpcConfig {
                runtime_dir: fixture.runtime.clone(),
                socket_path: fixture.socket.clone(),
                connect_timeout: Duration::from_millis(100),
                response_timeout: Duration::from_millis(20),
            },
            AuthKeyring::bootstrap("key-active", KEY).unwrap(),
        )
        .unwrap();
        let server = tokio::spawn(async move {
            let (_stream, _) = fixture.listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_millis(100)).await;
        });
        assert_eq!(
            client
                .evaluate(&proposal(), &guard())
                .await
                .unwrap_err()
                .code,
            IpcErrorCode::ResponseTimeout
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn disconnect_mid_handshake_fails_closed() {
        let _serial = SOCKET_TEST_LOCK.lock().await;
        let fixture = fixture();
        let client = client(fixture.runtime.clone(), fixture.socket.clone());
        let server = tokio::spawn(async move {
            let (mut stream, _) = fixture.listener.accept().await.unwrap();
            let _: ClientHello = read_frame(&mut stream).await.unwrap();
            // EOF before the provider challenge simulates a crash/half-handshake disconnect.
            stream.shutdown().await.unwrap();
        });
        assert_eq!(
            client
                .evaluate(&proposal(), &guard())
                .await
                .unwrap_err()
                .code,
            IpcErrorCode::InvalidFrame
        );
        server.await.unwrap();
    }

    #[test]
    fn rejects_peer_uid_mismatch() {
        assert_eq!(
            validate_peer_uid(1001, 1000).unwrap_err().code,
            IpcErrorCode::Authentication
        );
        assert!(validate_peer_uid(1000, 1000).is_ok());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn peer_cred_rejects_real_connection_from_another_uid() {
        let _serial = SOCKET_TEST_LOCK.lock().await;
        if geteuid().as_raw() != 0 {
            eprintln!("skipped: real cross-UID peer_cred test requires root to drop child UID");
            return;
        }
        let setpriv = Path::new("/usr/bin/setpriv");
        assert!(
            setpriv.is_file(),
            "Linux cross-UID test requires util-linux setpriv"
        );

        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), Permissions::from_mode(0o711)).unwrap();
        let socket = temp.path().join("cross-uid.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        fs::set_permissions(&socket, Permissions::from_mode(0o666)).unwrap();

        let executable = std::env::current_exe().unwrap();
        let mut child = Command::new(setpriv)
            .args(["--reuid=65534", "--regid=65534", "--clear-groups", "--"])
            .arg(executable)
            .args([
                "--exact",
                "ipc::tests::peer_uid_child_connects",
                "--nocapture",
            ])
            .env("VIPER_SEED_TEST_SOCKET", &socket)
            .spawn()
            .unwrap();

        let (stream, _) = tokio::time::timeout(Duration::from_secs(3), listener.accept())
            .await
            .expect("cross-UID child did not connect")
            .unwrap();
        assert_eq!(
            validate_peer(&stream).unwrap_err().code,
            IpcErrorCode::Authentication
        );
        let status = tokio::task::spawn_blocking(move || child.wait())
            .await
            .unwrap()
            .unwrap();
        assert!(
            status.success(),
            "cross-UID fixture process failed: {status}"
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn peer_uid_child_connects() {
        let Ok(socket) = std::env::var("VIPER_SEED_TEST_SOCKET") else {
            return;
        };
        UnixStream::connect(socket).await.unwrap();
    }

    #[tokio::test]
    async fn rejects_unsafe_runtime_permissions_before_connecting() {
        let _serial = SOCKET_TEST_LOCK.lock().await;
        let fixture = fixture();
        fs::set_permissions(&fixture.runtime, Permissions::from_mode(0o755)).unwrap();
        let client = client(fixture.runtime.clone(), fixture.socket.clone());
        assert_eq!(
            client
                .evaluate(&proposal(), &guard())
                .await
                .unwrap_err()
                .code,
            IpcErrorCode::UnsafeSocket
        );
    }

    #[tokio::test]
    async fn frame_reader_handles_fragmentation_and_rejects_oversize() {
        let _serial = SOCKET_TEST_LOCK.lock().await;
        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        let payload = serde_json::to_vec(&ServerChallenge {
            protocol: PROTOCOL.into(),
            kind: "server_challenge".into(),
            session_id: "session-1".into(),
            provider_nonce: "2".repeat(64),
        })
        .unwrap();
        let length = u32::try_from(payload.len()).unwrap().to_be_bytes();
        let sender = tokio::spawn(async move {
            for byte in length.into_iter().chain(payload) {
                writer.write_all(&[byte]).await.unwrap();
                tokio::task::yield_now().await;
            }
        });
        let frame: ServerChallenge = read_frame(&mut reader).await.unwrap();
        assert_eq!(frame.session_id, "session-1");
        sender.await.unwrap();

        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        writer
            .write_all(&(u32::try_from(MAX_FRAME_BYTES).unwrap() + 1).to_be_bytes())
            .await
            .unwrap();
        assert_eq!(
            read_frame::<ServerChallenge>(&mut reader)
                .await
                .unwrap_err()
                .code,
            IpcErrorCode::InvalidFrame
        );

        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        let payload = br#"{"protocol":"viper.seed.ipc.v1","kind":"server_challenge","session_id":"session-1","provider_nonce":"2222222222222222222222222222222222222222222222222222222222222222","unexpected":true}"#;
        writer
            .write_all(&u32::try_from(payload.len()).unwrap().to_be_bytes())
            .await
            .unwrap();
        writer.write_all(payload).await.unwrap();
        assert_eq!(
            read_frame::<ServerChallenge>(&mut reader)
                .await
                .unwrap_err()
                .code,
            IpcErrorCode::InvalidProtocol
        );
    }

    #[test]
    fn rejects_timeout_above_hard_ceiling_and_invalid_policy_digest() {
        let config = SeedIpcConfig {
            runtime_dir: PathBuf::from("/tmp/viper-runtime"),
            socket_path: PathBuf::from("/tmp/viper-runtime/seed.sock"),
            connect_timeout: Duration::from_secs(6),
            response_timeout: Duration::from_secs(1),
        };
        assert_eq!(
            SeedIpcClient::new(config, AuthKeyring::bootstrap("key", KEY).unwrap())
                .err()
                .unwrap()
                .code,
            IpcErrorCode::InvalidConfiguration
        );
        let mut evidence = guard();
        evidence.policy_digest = "not-a-digest".into();
        assert_eq!(
            evidence.validate().unwrap_err().code,
            IpcErrorCode::InvalidProtocol
        );
    }
}
