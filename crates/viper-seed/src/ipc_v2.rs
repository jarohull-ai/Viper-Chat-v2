//! Ed25519-authenticated, fail-closed SEED IPC v2.

use crate::ipc::{SeedGuardAction, SeedGuardEvidence};
use crate::{GuardAction, GuardVerdict, SeedFailure, SeedGate, Severity};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use getrandom::fill as fill_random;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::{ErrorKind, Read};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::time::timeout;
use viper_core::{Decision, ToolName, ToolProposal, VerdictStatus};
use zeroize::Zeroizing;

const PROTOCOL: &str = "viper.seed.ipc.v2";
const REQUEST_DOMAIN: &[u8] = b"VIPER-SEED-IPC-V2-REQUEST\0";
const RESPONSE_DOMAIN: &[u8] = b"VIPER-SEED-IPC-V2-RESPONSE\0";
const MAX_FRAME_BYTES: usize = 65_536;
const MAX_KEYS: usize = 16;
const MAX_POLICY_REASON: usize = 1_024;
const MAX_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_GRACE_SECONDS: u64 = 300;
const MAX_CREDENTIAL_BYTES: usize = 256;
const MAX_KEYRING_BYTES: usize = 16_384;

/// Bounded settings for the v2 Unix-socket client.
#[derive(Debug, Clone)]
pub struct SeedIpcV2Config {
    /// Provider-owned runtime directory containing the socket.
    pub runtime_dir: PathBuf,
    /// Socket path directly inside `runtime_dir`.
    pub socket_path: PathBuf,
    /// Expected provider UID, distinct from the server UID in production.
    pub expected_provider_uid: u32,
    /// Deadline for establishing the Unix connection.
    pub connect_timeout: Duration,
    /// Deadline for the entire challenge/request/response exchange.
    pub response_timeout: Duration,
}

impl SeedIpcV2Config {
    /// Creates bounded default timeouts for the supplied IPC identity.
    #[must_use]
    pub fn with_defaults(
        runtime_dir: PathBuf,
        socket_path: PathBuf,
        expected_provider_uid: u32,
    ) -> Self {
        Self {
            runtime_dir,
            socket_path,
            expected_provider_uid,
            connect_timeout: Duration::from_millis(250),
            response_timeout: Duration::from_secs(1),
        }
    }

    fn validate(&self) -> Result<(), IpcV2Error> {
        if !self.runtime_dir.is_absolute()
            || !self.socket_path.is_absolute()
            || self.socket_path.parent() != Some(self.runtime_dir.as_path())
            || self.connect_timeout.is_zero()
            || self.response_timeout.is_zero()
            || self.connect_timeout > MAX_TIMEOUT
            || self.response_timeout > MAX_TIMEOUT
        {
            return Err(IpcV2Error::InvalidConfiguration);
        }
        Ok(())
    }
}

/// Sanitized v2 transport failure; callers must convert all variants to a durable VETO.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum IpcV2Error {
    /// Paths, UIDs, or timeout bounds are invalid.
    #[error("invalid IPC v2 configuration")]
    InvalidConfiguration,
    /// Runtime directory or socket ownership, type, or permissions are unsafe.
    #[error("unsafe IPC v2 socket metadata")]
    UnsafeSocket,
    /// The provider was unavailable or the connection failed.
    #[error("SEED IPC v2 provider unavailable")]
    Unavailable,
    /// A connection or response deadline elapsed.
    #[error("SEED IPC v2 timeout")]
    Timeout,
    /// The peer UID did not match the configured identity.
    #[error("SEED IPC v2 peer UID mismatch")]
    PeerIdentity,
    /// A message was malformed, unexpected, or exceeded protocol bounds.
    #[error("invalid SEED IPC v2 message")]
    InvalidMessage,
    /// The provider key is absent, revoked, or expired.
    #[error("SEED IPC v2 signing key is not trusted")]
    UntrustedKey,
    /// The provider signature did not verify strictly.
    #[error("SEED IPC v2 signature verification failed")]
    InvalidSignature,
    /// A credential or public trust bundle was invalid or unavailable.
    #[error("SEED IPC v2 key material unavailable or invalid")]
    InvalidKeyMaterial,
}

impl From<IpcV2Error> for SeedFailure {
    fn from(error: IpcV2Error) -> Self {
        Self {
            message: format!("ipc_v2/{error:?}"),
        }
    }
}

/// Trusted provider verification keys loaded by the orchestrator.
pub struct ProviderKeyring {
    active_key_id: String,
    keys: BTreeMap<String, VerificationRecord>,
}

struct VerificationRecord {
    key: VerifyingKey,
    accept_until_epoch: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyringDocument {
    schema: String,
    active: PublicKeyDocument,
    retiring: Vec<RetiringKeyDocument>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicKeyDocument {
    key_id: String,
    public_key: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RetiringKeyDocument {
    key_id: String,
    public_key: String,
    accept_until_epoch: u64,
}

impl ProviderKeyring {
    /// Parses the strict versioned public-key bundle at an injected epoch for deterministic tests.
    ///
    /// # Errors
    ///
    /// Rejects unknown fields, duplicate/invalid IDs, malformed keys, too many keys, and retiring
    /// keys whose acceptance deadline is expired or more than 300 seconds in the future.
    pub fn from_json_at(source: &str, now_epoch: u64) -> Result<Self, IpcV2Error> {
        if source.len() > MAX_KEYRING_BYTES {
            return Err(IpcV2Error::InvalidKeyMaterial);
        }
        let document: KeyringDocument =
            serde_json::from_str(source).map_err(|_| IpcV2Error::InvalidKeyMaterial)?;
        if document.schema != "VIPER_SEED_PUBLIC_KEYS_V2"
            || document.retiring.len() >= MAX_KEYS
            || !valid_key_id(&document.active.key_id)
        {
            return Err(IpcV2Error::InvalidKeyMaterial);
        }
        let active_key_id = document.active.key_id.clone();
        let active_key = decode_public_key(&document.active.public_key)?;
        let mut keys = BTreeMap::from([(
            active_key_id.clone(),
            VerificationRecord {
                key: active_key,
                accept_until_epoch: None,
            },
        )]);
        for record in document.retiring {
            if !valid_key_id(&record.key_id)
                || record.accept_until_epoch <= now_epoch
                || record.accept_until_epoch.saturating_sub(now_epoch) > MAX_GRACE_SECONDS
            {
                return Err(IpcV2Error::InvalidKeyMaterial);
            }
            let key = decode_public_key(&record.public_key)?;
            if keys
                .insert(
                    record.key_id,
                    VerificationRecord {
                        key,
                        accept_until_epoch: Some(record.accept_until_epoch),
                    },
                )
                .is_some()
            {
                return Err(IpcV2Error::InvalidKeyMaterial);
            }
        }
        Ok(Self {
            active_key_id,
            keys,
        })
    }

    /// Loads a non-symlink public trust bundle not writable by group or other users.
    ///
    /// # Errors
    ///
    /// Returns a sanitized error for unsafe metadata, oversized content, or invalid bundle data.
    pub fn load_file(path: &Path) -> Result<Self, IpcV2Error> {
        let metadata =
            std::fs::symlink_metadata(path).map_err(|_| IpcV2Error::InvalidKeyMaterial)?;
        let parent = path
            .parent()
            .and_then(|parent| std::fs::symlink_metadata(parent).ok())
            .ok_or(IpcV2Error::InvalidKeyMaterial)?;
        if !metadata.file_type().is_file()
            || metadata.mode() & 0o022 != 0
            || metadata.uid() != 0
            || metadata.len() > u64::try_from(MAX_KEYRING_BYTES).unwrap_or(u64::MAX)
            || !parent.file_type().is_dir()
            || parent.mode() & 0o022 != 0
            || parent.uid() != 0
        {
            return Err(IpcV2Error::InvalidKeyMaterial);
        }
        let bytes = std::fs::read(path).map_err(|_| IpcV2Error::InvalidKeyMaterial)?;
        let source = std::str::from_utf8(&bytes).map_err(|_| IpcV2Error::InvalidKeyMaterial)?;
        Self::from_json_at(source, unix_time()?)
    }

    fn verify(
        &self,
        key_id: &str,
        message: &[u8],
        signature: &[u8; 64],
        now_epoch: u64,
    ) -> Result<(), IpcV2Error> {
        let record = self.keys.get(key_id).ok_or(IpcV2Error::UntrustedKey)?;
        if record
            .accept_until_epoch
            .is_some_and(|accept_until| now_epoch >= accept_until)
        {
            return Err(IpcV2Error::UntrustedKey);
        }
        record
            .key
            .verify_strict(message, &Signature::from_bytes(signature))
            .map_err(|_| IpcV2Error::InvalidSignature)
    }

    /// Returns the ACTIVE public key identifier without exposing private key material.
    #[must_use]
    pub fn active_key_id(&self) -> &str {
        &self.active_key_id
    }
}

/// Provider-only Ed25519 signing identity loaded from an inherited descriptor.
pub struct ProviderSigningKey {
    key_id: String,
    signing_key: SigningKey,
}

impl ProviderSigningKey {
    /// Loads one strict `VIPER_SEED_SIGNING_KEY_V2` record and consumes the reader to EOF.
    ///
    /// # Errors
    ///
    /// Rejects malformed, oversized, truncated, extra, or all-zero records with sanitized errors.
    pub fn load<R: Read>(reader: R) -> Result<Self, IpcV2Error> {
        let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_CREDENTIAL_BYTES));
        let mut bounded_reader =
            reader.take(u64::try_from(MAX_CREDENTIAL_BYTES + 1).unwrap_or(u64::MAX));
        bounded_reader
            .read_to_end(&mut bytes)
            .map_err(|_| IpcV2Error::InvalidKeyMaterial)?;
        if bytes.len() > MAX_CREDENTIAL_BYTES {
            return Err(IpcV2Error::InvalidKeyMaterial);
        }
        let source = std::str::from_utf8(&bytes).map_err(|_| IpcV2Error::InvalidKeyMaterial)?;
        let body = source
            .strip_prefix("VIPER_SEED_SIGNING_KEY_V2\n")
            .and_then(|value| value.strip_suffix('\n'))
            .ok_or(IpcV2Error::InvalidKeyMaterial)?;
        let mut lines = body.split('\n');
        let key_id = lines.next().ok_or(IpcV2Error::InvalidKeyMaterial)?;
        let secret_hex = lines.next().ok_or(IpcV2Error::InvalidKeyMaterial)?;
        if lines.next().is_some() || !valid_key_id(key_id) {
            return Err(IpcV2Error::InvalidKeyMaterial);
        }
        let secret = Zeroizing::new(decode_hex_32(secret_hex)?);
        if secret.iter().all(|byte| *byte == 0) {
            return Err(IpcV2Error::InvalidKeyMaterial);
        }
        Ok(Self {
            key_id: key_id.to_owned(),
            signing_key: SigningKey::from_bytes(&secret),
        })
    }

    /// Returns the non-secret key identifier.
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Returns the public verification key in lowercase hexadecimal form.
    #[must_use]
    pub fn public_key_hex(&self) -> String {
        encode_hex(self.signing_key.verifying_key().as_bytes())
    }
}

/// Fail-closed client implementing the `SeedGate` boundary over IPC v2.
pub struct SeedIpcV2Client {
    config: SeedIpcV2Config,
    keys: Arc<ProviderKeyring>,
}

impl SeedIpcV2Client {
    /// Creates a client with a pinned public-key trust bundle.
    ///
    /// # Errors
    ///
    /// Rejects invalid or unbounded paths and timeout configuration.
    pub fn new(config: SeedIpcV2Config, keys: ProviderKeyring) -> Result<Self, IpcV2Error> {
        config.validate()?;
        Ok(Self {
            config,
            keys: Arc::new(keys),
        })
    }

    /// Exchanges one proposal with a provider and verifies the signed bound response.
    ///
    /// # Errors
    ///
    /// Returns a sanitized error for every filesystem, UID, timeout, framing, key, or signature
    /// failure. The caller must record it as `VETO_DENIED`.
    pub async fn evaluate(
        &self,
        proposal: &ToolProposal,
        guard: &GuardVerdict,
    ) -> Result<Decision, IpcV2Error> {
        proposal
            .validate()
            .map_err(|_| IpcV2Error::InvalidMessage)?;
        let guard = SeedGuardEvidence::from_verdict(guard);
        validate_guard(&guard)?;
        validate_socket_metadata(
            &self.config.runtime_dir,
            &self.config.socket_path,
            self.config.expected_provider_uid,
        )?;
        let mut stream = timeout(
            self.config.connect_timeout,
            UnixStream::connect(&self.config.socket_path),
        )
        .await
        .map_err(|_| IpcV2Error::Timeout)?
        .map_err(|_| IpcV2Error::Unavailable)?;
        validate_peer_uid(&stream, self.config.expected_provider_uid)?;
        timeout(
            self.config.response_timeout,
            client_exchange(&mut stream, proposal, &guard, &self.keys),
        )
        .await
        .map_err(|_| IpcV2Error::Timeout)?
    }
}

impl SeedGate for SeedIpcV2Client {
    async fn evaluate(
        &self,
        proposal: &ToolProposal,
        guard: &GuardVerdict,
    ) -> Result<Decision, SeedFailure> {
        SeedIpcV2Client::evaluate(self, proposal, guard)
            .await
            .map_err(SeedFailure::from)
    }
}

/// One-shot IPC v2 provider service using an injected decision gate.
///
/// `serve_one` accepts and serves one connection so a process can add its own bounded accept loop,
/// shutdown handling and supervision policy.
pub struct SeedIpcV2Provider<G> {
    expected_client_uid: u32,
    response_timeout: Duration,
    signing_key: Arc<ProviderSigningKey>,
    gate: Arc<G>,
}

impl<G: SeedGate + 'static> SeedIpcV2Provider<G> {
    /// Constructs a provider with provider-only signing identity and an evaluator.
    #[must_use]
    pub fn new(
        expected_client_uid: u32,
        response_timeout: Duration,
        signing_key: ProviderSigningKey,
        gate: G,
    ) -> Self {
        Self {
            expected_client_uid,
            response_timeout: response_timeout.min(MAX_TIMEOUT),
            signing_key: Arc::new(signing_key),
            gate: Arc::new(gate),
        }
    }

    /// Accepts and serves one authenticated-by-UID connection.
    ///
    /// # Errors
    ///
    /// Returns sanitized peer, timeout, framing, or protocol failures. Gate failures are returned
    /// as signed fail-closed VETO decisions.
    pub async fn serve_one(&self, listener: &UnixListener) -> Result<(), IpcV2Error> {
        let (mut stream, _) = timeout(self.response_timeout, listener.accept())
            .await
            .map_err(|_| IpcV2Error::Timeout)?
            .map_err(|_| IpcV2Error::Unavailable)?;
        validate_peer_uid(&stream, self.expected_client_uid)?;
        timeout(self.response_timeout, self.exchange(&mut stream))
            .await
            .map_err(|_| IpcV2Error::Timeout)?
    }

    async fn exchange(&self, stream: &mut UnixStream) -> Result<(), IpcV2Error> {
        let hello: ClientHello = read_frame(stream).await?;
        require_header(&hello.protocol, &hello.kind, "client_hello")?;
        validate_identifier(&hello.session_id)?;
        let client_nonce = decode_hex_32(&hello.client_nonce)?;
        let provider_nonce = random_array()?;
        write_frame(
            stream,
            &ServerChallenge {
                protocol: PROTOCOL.into(),
                kind: "server_challenge".into(),
                session_id: hello.session_id.clone(),
                provider_nonce: encode_hex(&provider_nonce),
            },
        )
        .await?;

        let request: DecisionRequest = read_frame(stream).await?;
        require_header(&request.protocol, &request.kind, "decision_request")?;
        if request.session_id != hello.session_id {
            return Err(IpcV2Error::InvalidMessage);
        }
        validate_request(&request)?;
        let request_digest = request_digest(&request);
        let proposal = proposal_from_request(&request)?;
        let guard = guard_from_evidence(&request.guard);
        let gate_result = self.gate.evaluate(&proposal, &guard).await;
        let (verdict, reason_code, explanation) = match gate_result {
            Ok(decision) if decision.proposal_id == proposal.id => (
                decision.status,
                "SEED_DECISION".to_owned(),
                bounded_explanation(&decision.reason),
            ),
            Ok(_) => (
                VerdictStatus::VetoDenied,
                "PROPOSAL_MISMATCH".to_owned(),
                "provider returned a verdict for another proposal".to_owned(),
            ),
            Err(_) => (
                VerdictStatus::VetoDenied,
                "SEED_UNAVAILABLE".to_owned(),
                "decision engine unavailable".to_owned(),
            ),
        };
        let unsigned = DecisionResponse {
            protocol: PROTOCOL.into(),
            kind: "decision_response".into(),
            session_id: hello.session_id,
            request_id: request.request_id.clone(),
            proposal_id: request.proposal_id.clone(),
            request_digest: encode_hex(&request_digest),
            verdict,
            reason_code,
            explanation,
            key_id: self.signing_key.key_id.clone(),
            signature: String::new(),
        };
        let transcript =
            response_transcript(&unsigned, &client_nonce, &provider_nonce, &request_digest);
        let mut signed = unsigned;
        signed.signature = encode_hex(&self.signing_key.signing_key.sign(&transcript).to_bytes());
        write_frame(stream, &signed).await?;
        stream.shutdown().await.map_err(|_| IpcV2Error::Unavailable)
    }
}

async fn client_exchange(
    stream: &mut UnixStream,
    proposal: &ToolProposal,
    guard: &SeedGuardEvidence,
    keys: &ProviderKeyring,
) -> Result<Decision, IpcV2Error> {
    let session_id = random_id("session")?;
    let client_nonce = random_array()?;
    write_frame(
        stream,
        &ClientHello {
            protocol: PROTOCOL.into(),
            kind: "client_hello".into(),
            session_id: session_id.clone(),
            client_nonce: encode_hex(&client_nonce),
        },
    )
    .await?;
    let challenge: ServerChallenge = read_frame(stream).await?;
    require_header(&challenge.protocol, &challenge.kind, "server_challenge")?;
    if challenge.session_id != session_id {
        return Err(IpcV2Error::InvalidMessage);
    }
    let provider_nonce = decode_hex_32(&challenge.provider_nonce)?;
    let request = DecisionRequest {
        protocol: PROTOCOL.into(),
        kind: "decision_request".into(),
        session_id: session_id.clone(),
        request_id: random_id("request")?,
        proposal_id: proposal.id.clone(),
        trace_id: proposal.trace_id.clone(),
        actor: proposal.actor.clone(),
        timestamp: proposal.requested_at.clone(),
        tool: proposal.tool.wire_name().to_owned(),
        arguments: proposal.arguments.clone(),
        guard: guard.clone(),
    };
    validate_request(&request)?;
    let request_digest = request_digest(&request);
    write_frame(stream, &request).await?;
    let response: DecisionResponse = read_frame(stream).await?;
    require_header(&response.protocol, &response.kind, "decision_response")?;
    if response.session_id != session_id
        || response.request_id != request.request_id
        || response.proposal_id != proposal.id
        || response.request_digest != encode_hex(&request_digest)
        || response.reason_code.trim().is_empty()
        || response.reason_code.len() > 128
        || response.explanation.trim().is_empty()
        || response.explanation.len() > MAX_POLICY_REASON
    {
        return Err(IpcV2Error::InvalidMessage);
    }
    let signature = decode_hex_64(&response.signature)?;
    let transcript =
        response_transcript(&response, &client_nonce, &provider_nonce, &request_digest);
    keys.verify(&response.key_id, &transcript, &signature, unix_time()?)?;
    let mut trailing = [0; 1];
    match stream.read(&mut trailing).await {
        Ok(0) => {}
        Ok(_) => return Err(IpcV2Error::InvalidMessage),
        Err(error) if error.kind() == ErrorKind::UnexpectedEof => {}
        Err(_) => return Err(IpcV2Error::Unavailable),
    }
    Ok(Decision {
        proposal_id: response.proposal_id,
        status: response.verdict,
        source: format!("seed_ipc/v2/{}", response.key_id),
        reason: format!("{}: {}", response.reason_code, response.explanation),
    })
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
struct DecisionRequest {
    protocol: String,
    kind: String,
    session_id: String,
    request_id: String,
    proposal_id: String,
    trace_id: String,
    actor: String,
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
    session_id: String,
    request_id: String,
    proposal_id: String,
    request_digest: String,
    verdict: VerdictStatus,
    reason_code: String,
    explanation: String,
    key_id: String,
    signature: String,
}

fn validate_request(request: &DecisionRequest) -> Result<(), IpcV2Error> {
    validate_guard(&request.guard)?;
    if request.request_id.is_empty()
        || request.request_id.len() > 128
        || request.proposal_id.is_empty()
        || request.proposal_id.len() > 128
        || request.trace_id.is_empty()
        || request.trace_id.len() > 128
        || request.actor.is_empty()
        || request.actor.len() > 128
        || request.timestamp.is_empty()
        || request.timestamp.len() > 64
        || request.tool.is_empty()
        || request.arguments.len() > 128
        || request
            .arguments
            .iter()
            .any(|(key, value)| key.is_empty() || key.len() > 128 || value.len() > 16_384)
    {
        return Err(IpcV2Error::InvalidMessage);
    }
    Ok(())
}

fn validate_guard(guard: &SeedGuardEvidence) -> Result<(), IpcV2Error> {
    if guard.policy_version.is_empty()
        || !is_lower_hex_32(&guard.policy_digest)
        || guard
            .matched_rule_id
            .as_ref()
            .is_some_and(|rule| rule.is_empty() || rule.len() > 128)
    {
        return Err(IpcV2Error::InvalidMessage);
    }
    Ok(())
}

fn proposal_from_request(request: &DecisionRequest) -> Result<ToolProposal, IpcV2Error> {
    let tool = match request.tool.as_str() {
        "terminal_run" => ToolName::TerminalRun,
        "network_run" => ToolName::NetworkRun,
        "browser_action" => ToolName::BrowserAction,
        "email_send_guarded" => ToolName::EmailSendGuarded,
        custom => ToolName::Custom(custom.to_owned()),
    };
    let proposal = ToolProposal {
        id: request.proposal_id.clone(),
        trace_id: request.trace_id.clone(),
        actor: request.actor.clone(),
        tool,
        arguments: request.arguments.clone(),
        requested_at: request.timestamp.clone(),
    };
    proposal
        .validate()
        .map_err(|_| IpcV2Error::InvalidMessage)?;
    Ok(proposal)
}

fn guard_from_evidence(evidence: &SeedGuardEvidence) -> GuardVerdict {
    let action = match evidence.action {
        SeedGuardAction::Allow => GuardAction::Allow,
        SeedGuardAction::Escalate => GuardAction::Escalate,
        SeedGuardAction::Block => GuardAction::Block,
    };
    GuardVerdict {
        action,
        rule_id: evidence.matched_rule_id.clone(),
        category: None,
        severity: if action == GuardAction::Block {
            Some(Severity::Critical)
        } else {
            None
        },
        reason: "validated remote Tool Guard evidence".into(),
        policy_version: evidence.policy_version.clone(),
        policy_digest: evidence.policy_digest.clone(),
    }
}

fn request_digest(request: &DecisionRequest) -> [u8; 32] {
    let mut canonical = CanonicalBytes::new(REQUEST_DOMAIN);
    for field in [
        request.protocol.as_str(),
        request.request_id.as_str(),
        request.proposal_id.as_str(),
        request.trace_id.as_str(),
        request.actor.as_str(),
        request.timestamp.as_str(),
        request.tool.as_str(),
        guard_action_name(request.guard.action),
        request.guard.matched_rule_id.as_deref().unwrap_or(""),
        request.guard.policy_version.as_str(),
        request.guard.policy_digest.as_str(),
    ] {
        canonical.field(field.as_bytes());
    }
    canonical.count(request.arguments.len());
    for (key, value) in &request.arguments {
        canonical.field(key.as_bytes());
        canonical.field(value.as_bytes());
    }
    Sha256::digest(canonical.0).into()
}

fn response_transcript(
    response: &DecisionResponse,
    client_nonce: &[u8; 32],
    provider_nonce: &[u8; 32],
    request_digest: &[u8; 32],
) -> Vec<u8> {
    let mut canonical = CanonicalBytes::new(RESPONSE_DOMAIN);
    for field in [
        response.protocol.as_str(),
        response.key_id.as_str(),
        response.session_id.as_str(),
    ] {
        canonical.field(field.as_bytes());
    }
    canonical.raw(client_nonce);
    canonical.raw(provider_nonce);
    canonical.raw(request_digest);
    for field in [
        response.request_id.as_str(),
        response.proposal_id.as_str(),
        response.verdict.wire_name(),
        response.reason_code.as_str(),
        response.explanation.as_str(),
    ] {
        canonical.field(field.as_bytes());
    }
    canonical.0
}

struct CanonicalBytes(Vec<u8>);

impl CanonicalBytes {
    fn new(domain: &[u8]) -> Self {
        Self(domain.to_vec())
    }

    fn field(&mut self, value: &[u8]) {
        let length = u64::try_from(value.len()).expect("field length fits protocol encoding");
        self.0.extend_from_slice(&length.to_be_bytes());
        self.0.extend_from_slice(value);
    }

    fn raw(&mut self, value: &[u8]) {
        self.0.extend_from_slice(value);
    }

    fn count(&mut self, value: usize) {
        let count = u32::try_from(value).expect("bounded argument count fits protocol encoding");
        self.0.extend_from_slice(&count.to_be_bytes());
    }
}

fn validate_socket_metadata(
    runtime_dir: &Path,
    socket_path: &Path,
    provider_uid: u32,
) -> Result<(), IpcV2Error> {
    let runtime = std::fs::symlink_metadata(runtime_dir).map_err(|_| IpcV2Error::UnsafeSocket)?;
    if !runtime.file_type().is_dir()
        || runtime.uid() != provider_uid
        || runtime.mode() & 0o022 != 0
        || runtime.mode() & 0o050 != 0o050
    {
        return Err(IpcV2Error::UnsafeSocket);
    }
    let socket = std::fs::symlink_metadata(socket_path).map_err(|_| IpcV2Error::UnsafeSocket)?;
    if !socket.file_type().is_socket()
        || socket.uid() != provider_uid
        || socket.gid() != runtime.gid()
        || socket.mode() & 0o077 != 0o060
    {
        return Err(IpcV2Error::UnsafeSocket);
    }
    Ok(())
}

fn validate_peer_uid(stream: &UnixStream, expected_uid: u32) -> Result<(), IpcV2Error> {
    let peer = stream.peer_cred().map_err(|_| IpcV2Error::PeerIdentity)?;
    if peer.uid() != expected_uid {
        return Err(IpcV2Error::PeerIdentity);
    }
    Ok(())
}

async fn write_frame<T: Serialize>(stream: &mut UnixStream, value: &T) -> Result<(), IpcV2Error> {
    let bytes = serde_json::to_vec(value).map_err(|_| IpcV2Error::InvalidMessage)?;
    if bytes.is_empty() || bytes.len() > MAX_FRAME_BYTES {
        return Err(IpcV2Error::InvalidMessage);
    }
    let length = u32::try_from(bytes.len()).map_err(|_| IpcV2Error::InvalidMessage)?;
    stream
        .write_all(&length.to_be_bytes())
        .await
        .map_err(|_| IpcV2Error::Unavailable)?;
    stream
        .write_all(&bytes)
        .await
        .map_err(|_| IpcV2Error::Unavailable)
}

async fn read_frame<T: for<'de> Deserialize<'de>>(
    stream: &mut UnixStream,
) -> Result<T, IpcV2Error> {
    let mut header = [0; 4];
    stream
        .read_exact(&mut header)
        .await
        .map_err(|_| IpcV2Error::InvalidMessage)?;
    let length = usize::try_from(u32::from_be_bytes(header)).unwrap_or(usize::MAX);
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(IpcV2Error::InvalidMessage);
    }
    let mut bytes = vec![0; length];
    stream
        .read_exact(&mut bytes)
        .await
        .map_err(|_| IpcV2Error::InvalidMessage)?;
    let source = std::str::from_utf8(&bytes).map_err(|_| IpcV2Error::InvalidMessage)?;
    serde_json::from_str(source).map_err(|_| IpcV2Error::InvalidMessage)
}

fn require_header(protocol: &str, kind: &str, expected_kind: &str) -> Result<(), IpcV2Error> {
    if protocol == PROTOCOL && kind == expected_kind {
        Ok(())
    } else {
        Err(IpcV2Error::InvalidMessage)
    }
}

fn validate_identifier(value: &str) -> Result<(), IpcV2Error> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
    {
        return Err(IpcV2Error::InvalidMessage);
    }
    Ok(())
}

fn valid_key_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
}

fn decode_public_key(value: &str) -> Result<VerifyingKey, IpcV2Error> {
    let bytes = decode_hex_32(value)?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| IpcV2Error::InvalidKeyMaterial)
}

fn decode_hex_32(value: &str) -> Result<[u8; 32], IpcV2Error> {
    let mut bytes = [0; 32];
    decode_hex(value, &mut bytes)?;
    Ok(bytes)
}

fn decode_hex_64(value: &str) -> Result<[u8; 64], IpcV2Error> {
    let mut bytes = [0; 64];
    decode_hex(value, &mut bytes)?;
    Ok(bytes)
}

fn decode_hex(value: &str, output: &mut [u8]) -> Result<(), IpcV2Error> {
    if value.len() != output.len() * 2 {
        return Err(IpcV2Error::InvalidMessage);
    }
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_nibble(pair[0]).ok_or(IpcV2Error::InvalidMessage)?;
        let low = hex_nibble(pair[1]).ok_or(IpcV2Error::InvalidMessage)?;
        output[index] = (high << 4) | low;
    }
    Ok(())
}

fn hex_nibble(byte: u8) -> Option<u8> {
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

fn random_array<const N: usize>() -> Result<[u8; N], IpcV2Error> {
    let mut bytes = [0; N];
    fill_random(&mut bytes).map_err(|_| IpcV2Error::Unavailable)?;
    Ok(bytes)
}

fn random_id(prefix: &str) -> Result<String, IpcV2Error> {
    Ok(format!("{prefix}_{}", encode_hex(&random_array::<16>()?)))
}

fn guard_action_name(action: SeedGuardAction) -> &'static str {
    match action {
        SeedGuardAction::Allow => "ALLOW",
        SeedGuardAction::Escalate => "ESCALATE",
        SeedGuardAction::Block => "BLOCK",
    }
}

fn bounded_explanation(reason: &str) -> String {
    let sanitized = reason
        .chars()
        .filter(|character| !character.is_control())
        .take(MAX_POLICY_REASON)
        .collect::<String>();
    if sanitized.trim().is_empty() {
        "decision returned without explanation".into()
    } else {
        sanitized
    }
}

fn is_lower_hex_32(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn unix_time() -> Result<u64, IpcV2Error> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| IpcV2Error::InvalidConfiguration)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, Permissions};
    use std::io::Cursor;
    use std::os::unix::fs::PermissionsExt;
    #[cfg(target_os = "linux")]
    use std::os::unix::net::UnixListener as StdUnixListener;
    use std::process::Command;

    fn bundle(active: &SigningKey, retiring: Option<(&str, &SigningKey, u64)>) -> String {
        let retiring_json = retiring.map_or_else(Vec::new, |(id, key, until)| {
            vec![serde_json::json!({
                "key_id": id,
                "public_key": encode_hex(key.verifying_key().as_bytes()),
                "accept_until_epoch": until,
            })]
        });
        serde_json::json!({
            "schema": "VIPER_SEED_PUBLIC_KEYS_V2",
            "active": {"key_id":"active", "public_key":encode_hex(active.verifying_key().as_bytes())},
            "retiring": retiring_json,
        })
        .to_string()
    }

    #[test]
    fn provider_signature_verifies_and_tampering_fails() {
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let bundle = bundle(&signing_key, None);
        let keyring = ProviderKeyring::from_json_at(&bundle, 100).unwrap();
        let message = b"bound decision";
        let signature = signing_key.sign(message).to_bytes();
        assert_eq!(keyring.active_key_id(), "active");
        assert_eq!(keyring.verify("active", message, &signature, 100), Ok(()));
        assert_eq!(
            keyring.verify("active", b"tampered decision", &signature, 100),
            Err(IpcV2Error::InvalidSignature)
        );
        assert_eq!(
            keyring.verify("unknown", message, &signature, 100),
            Err(IpcV2Error::UntrustedKey)
        );
    }

    #[test]
    fn public_key_rotation_accepts_retiring_key_only_before_exact_deadline() {
        let active = SigningKey::from_bytes(&[7; 32]);
        let retiring = SigningKey::from_bytes(&[8; 32]);
        let keyring =
            ProviderKeyring::from_json_at(&bundle(&active, Some(("old", &retiring, 120))), 100)
                .unwrap();
        let signature = retiring.sign(b"decision").to_bytes();
        assert_eq!(keyring.verify("old", b"decision", &signature, 119), Ok(()));
        assert_eq!(
            keyring.verify("old", b"decision", &signature, 120),
            Err(IpcV2Error::UntrustedKey)
        );
    }

    #[test]
    fn strict_private_credential_loads_and_rejects_extra_fields() {
        let record = format!("VIPER_SEED_SIGNING_KEY_V2\nactive\n{}\n", "07".repeat(32));
        let signing = ProviderSigningKey::load(Cursor::new(record.as_bytes())).unwrap();
        assert_eq!(signing.key_id(), "active");
        let invalid = format!("{record}extra\n");
        assert_eq!(
            ProviderSigningKey::load(Cursor::new(invalid.as_bytes())).err(),
            Some(IpcV2Error::InvalidKeyMaterial)
        );
    }

    #[test]
    fn malformed_and_duplicate_public_key_bundles_fail_closed() {
        let key = SigningKey::from_bytes(&[9; 32]);
        let duplicate = serde_json::json!({
            "schema": "VIPER_SEED_PUBLIC_KEYS_V2",
            "active": {"key_id":"same", "public_key":encode_hex(key.verifying_key().as_bytes())},
            "retiring": [{"key_id":"same", "public_key":encode_hex(key.verifying_key().as_bytes()), "accept_until_epoch":150}],
        });
        assert_eq!(
            ProviderKeyring::from_json_at(&duplicate.to_string(), 100).err(),
            Some(IpcV2Error::InvalidKeyMaterial)
        );
    }

    #[test]
    fn signature_is_bound_to_both_nonces_and_full_request_digest() {
        let signing = SigningKey::from_bytes(&[0x24; 32]);
        let keyring = ProviderKeyring::from_json_at(&bundle(&signing, None), 100).unwrap();
        let mut request = DecisionRequest {
            protocol: PROTOCOL.into(),
            kind: "decision_request".into(),
            session_id: "session-1".into(),
            request_id: "request-1".into(),
            proposal_id: "proposal-1".into(),
            trace_id: "trace-1".into(),
            actor: "test-agent".into(),
            timestamp: "2026-10-19T00:00:00Z".into(),
            tool: "terminal_run".into(),
            arguments: BTreeMap::from([("command".into(), "echo safe".into())]),
            guard: SeedGuardEvidence {
                action: SeedGuardAction::Allow,
                matched_rule_id: None,
                policy_version: "v1".into(),
                policy_digest: "a".repeat(64),
            },
        };
        let digest = request_digest(&request);
        let response = DecisionResponse {
            protocol: PROTOCOL.into(),
            kind: "decision_response".into(),
            session_id: request.session_id.clone(),
            request_id: request.request_id.clone(),
            proposal_id: request.proposal_id.clone(),
            request_digest: encode_hex(&digest),
            verdict: VerdictStatus::Approved,
            reason_code: "TEST".into(),
            explanation: "approved".into(),
            key_id: "active".into(),
            signature: String::new(),
        };
        let client_nonce = [0x31; 32];
        let provider_nonce = [0x42; 32];
        let transcript = response_transcript(&response, &client_nonce, &provider_nonce, &digest);
        let signature = signing.sign(&transcript).to_bytes();
        assert_eq!(
            keyring.verify("active", &transcript, &signature, 100),
            Ok(())
        );
        assert_eq!(
            keyring.verify(
                "active",
                &response_transcript(&response, &[0x32; 32], &provider_nonce, &digest),
                &signature,
                100
            ),
            Err(IpcV2Error::InvalidSignature)
        );
        request
            .arguments
            .insert("command".into(), "rm -rf /".into());
        let changed_digest = request_digest(&request);
        assert_ne!(digest, changed_digest);
        assert_eq!(
            keyring.verify(
                "active",
                &response_transcript(&response, &client_nonce, &provider_nonce, &changed_digest),
                &signature,
                100
            ),
            Err(IpcV2Error::InvalidSignature)
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn client_rejects_real_v2_provider_with_wrong_uid() {
        if rustix::process::geteuid().as_raw() != 0 {
            assert_ne!(
                std::env::var("VIPER_REQUIRE_CROSS_UID").as_deref(),
                Ok("1"),
                "required v2 cross-UID test must run as root"
            );
            eprintln!("skipped: real v2 cross-UID test requires root to drop child UID");
            return;
        }
        let setpriv = Path::new("/usr/bin/setpriv");
        assert!(
            setpriv.is_file(),
            "Linux cross-UID test requires util-linux setpriv"
        );

        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), Permissions::from_mode(0o711)).unwrap();
        let runtime = temp.path().join("provider-runtime");
        let socket = runtime.join("seed.sock");
        let executable = temp.path().join("cross-uid-test-bin");
        fs::copy(std::env::current_exe().unwrap(), &executable).unwrap();
        fs::set_permissions(&executable, Permissions::from_mode(0o755)).unwrap();
        let mut child = Command::new(setpriv)
            .args(["--reuid=65534", "--regid=65534", "--clear-groups", "--"])
            .arg(executable)
            .args([
                "--exact",
                "ipc_v2::tests::cross_uid_provider_child_hosts_socket",
                "--nocapture",
            ])
            .env("VIPER_SEED_V2_TEST_RUNTIME", &runtime)
            .spawn()
            .unwrap();

        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        while !socket.exists() && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            socket.exists(),
            "cross-UID v2 provider did not create its socket"
        );
        rustix::fs::chown(
            &runtime,
            Some(rustix::process::Uid::from_raw(0)),
            Some(rustix::process::Gid::from_raw(0)),
        )
        .unwrap();
        rustix::fs::chown(
            &socket,
            Some(rustix::process::Uid::from_raw(0)),
            Some(rustix::process::Gid::from_raw(0)),
        )
        .unwrap();
        let keyring =
            ProviderKeyring::from_json_at(&bundle(&SigningKey::from_bytes(&[0x17; 32]), None), 100)
                .unwrap();
        let client =
            SeedIpcV2Client::new(SeedIpcV2Config::with_defaults(runtime, socket, 0), keyring)
                .unwrap();
        let proposal = ToolProposal {
            id: "cross-uid-proposal".into(),
            trace_id: "cross-uid-trace".into(),
            actor: "cross-uid-test".into(),
            tool: ToolName::TerminalRun,
            arguments: BTreeMap::from([("command".into(), "echo safe".into())]),
            requested_at: "2026-10-19T00:00:00Z".into(),
        };
        let guard = GuardVerdict {
            action: GuardAction::Allow,
            rule_id: None,
            category: None,
            severity: None,
            reason: "test".into(),
            policy_version: "test-v1".into(),
            policy_digest: "a".repeat(64),
        };
        assert_eq!(
            client.evaluate(&proposal, &guard).await.unwrap_err(),
            IpcV2Error::PeerIdentity
        );
        let status = tokio::task::spawn_blocking(move || child.wait())
            .await
            .unwrap()
            .unwrap();
        assert!(
            status.success(),
            "cross-UID provider fixture failed: {status}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cross_uid_provider_child_hosts_socket() {
        let Ok(runtime) = std::env::var("VIPER_SEED_V2_TEST_RUNTIME") else {
            return;
        };
        let runtime = PathBuf::from(runtime);
        fs::create_dir(&runtime).unwrap();
        fs::set_permissions(&runtime, Permissions::from_mode(0o750)).unwrap();
        let socket = runtime.join("seed.sock");
        let listener = StdUnixListener::bind(&socket).unwrap();
        fs::set_permissions(&socket, Permissions::from_mode(0o660)).unwrap();
        let (_connection, _) = listener.accept().unwrap();
    }
}
