//! Deterministic HMAC authentication and bounded key rotation for SEED IPC.

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use std::collections::BTreeMap;
use thiserror::Error;
use zeroize::Zeroizing;

const PROTOCOL: &str = "viper.seed.ipc.v1";
const MAX_GRACE_SECONDS: u64 = 300;
type HmacSha256 = Hmac<Sha256>;

/// Side producing a handshake proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerRole {
    /// Viper's SEED client.
    Client,
    /// External SEED provider.
    Provider,
}

impl PeerRole {
    const fn wire_name(self) -> &'static str {
        match self {
            Self::Client => "client",
            Self::Provider => "provider",
        }
    }
}

/// Canonical handshake material. Nonces must be fresh random values from each peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthTranscript {
    /// Key selected by the producer.
    pub key_id: String,
    /// Unique session identity included in replay protection.
    pub session_id: String,
    /// Client-generated nonce.
    pub client_nonce: [u8; 32],
    /// Provider-generated nonce.
    pub provider_nonce: [u8; 32],
    /// Side producing this proof.
    pub role: PeerRole,
}

/// HMAC proof carrying no secret material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthProof {
    /// Key identifier used for verification.
    pub key_id: String,
    /// HMAC-SHA-256 tag.
    pub tag: [u8; 32],
}

/// Transcript and proof returned together so the selected ACTIVE key cannot be lost by the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedTranscript {
    /// Canonical transcript containing the selected key ID.
    pub transcript: AuthTranscript,
    /// Matching HMAC proof.
    pub proof: AuthProof,
}

/// Public lifecycle state for an IPC authentication key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyStatus {
    /// Used for new and existing sessions.
    Active,
    /// Accepted only for an already established session until this epoch second, exclusively.
    Retiring {
        /// Exclusive epoch-second boundary for an already established session.
        accept_until: u64,
    },
    /// Rejected immediately.
    Revoked,
}

struct KeyRecord {
    secret: Zeroizing<[u8; 32]>,
    status: KeyStatus,
}

/// Authentication/key lifecycle error.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AuthError {
    /// Identifier is empty or contains a disallowed character.
    #[error("invalid key or session identifier")]
    InvalidIdentifier,
    /// An all-zero key is treated as missing/corrupt provisioning.
    #[error("authentication key is invalid")]
    InvalidKey,
    /// A key identifier already exists and cannot be silently replaced.
    #[error("key identifier already exists")]
    DuplicateKey,
    /// No active signing key is available.
    #[error("no active authentication key")]
    NoActiveKey,
    /// Key is absent, expired, retiring for a new session, or revoked.
    #[error("authentication key is not accepted")]
    KeyNotAccepted,
    /// Transcript and proof name different keys.
    #[error("authentication proof key mismatch")]
    KeyMismatch,
    /// HMAC proof is invalid.
    #[error("authentication proof is invalid")]
    InvalidProof,
    /// Grace period exceeds the hard five-minute ceiling or overflows the clock.
    #[error("invalid key rotation grace period")]
    InvalidGracePeriod,
    /// Session identity/nonces were already accepted inside their replay window.
    #[error("authentication transcript was replayed")]
    Replay,
    /// Session was not previously authenticated or its lifetime ended.
    #[error("authentication session is not established")]
    SessionNotEstablished,
    /// Session lifetime is zero or overflows the supplied clock.
    #[error("invalid authentication session lifetime")]
    InvalidSessionLifetime,
    /// The revocation generation cannot advance safely.
    #[error("revocation epoch exhausted")]
    RevocationEpochExhausted,
}

/// In-memory keyring. Secrets are zeroized on replacement/drop and never implement `Debug`.
pub struct AuthKeyring {
    keys: BTreeMap<String, KeyRecord>,
    active_key_id: Option<String>,
    revocation_epoch: u64,
}

impl AuthKeyring {
    /// Creates a keyring with one active 256-bit key.
    ///
    /// # Errors
    ///
    /// Rejects an invalid identifier or an all-zero key.
    pub fn bootstrap(key_id: &str, secret: [u8; 32]) -> Result<Self, AuthError> {
        validate_identifier(key_id)?;
        validate_key(&secret)?;
        Ok(Self {
            keys: BTreeMap::from([(
                key_id.to_owned(),
                KeyRecord {
                    secret: Zeroizing::new(secret),
                    status: KeyStatus::Active,
                },
            )]),
            active_key_id: Some(key_id.to_owned()),
            revocation_epoch: 0,
        })
    }

    /// Moves the active key to RETIRING and installs a new ACTIVE key.
    ///
    /// `now` is an injected monotonic epoch used for deterministic testing. A grace period of 300
    /// seconds accepts the old key while `now < rotation_time + 300`, never at equality.
    ///
    /// # Errors
    ///
    /// Rejects invalid/duplicate keys, grace periods above 300 seconds, clock overflow, or a
    /// keyring without an active key.
    pub fn rotate(
        &mut self,
        new_key_id: &str,
        new_secret: [u8; 32],
        now: u64,
        grace_seconds: u64,
    ) -> Result<(), AuthError> {
        validate_identifier(new_key_id)?;
        validate_key(&new_secret)?;
        if grace_seconds > MAX_GRACE_SECONDS {
            return Err(AuthError::InvalidGracePeriod);
        }
        if self.keys.contains_key(new_key_id) {
            return Err(AuthError::DuplicateKey);
        }
        let accept_until = now
            .checked_add(grace_seconds)
            .ok_or(AuthError::InvalidGracePeriod)?;
        let old_id = self.active_key_id.as_ref().ok_or(AuthError::NoActiveKey)?;
        let old = self.keys.get_mut(old_id).ok_or(AuthError::NoActiveKey)?;
        old.status = KeyStatus::Retiring { accept_until };
        self.keys.insert(
            new_key_id.to_owned(),
            KeyRecord {
                secret: Zeroizing::new(new_secret),
                status: KeyStatus::Active,
            },
        );
        self.active_key_id = Some(new_key_id.to_owned());
        Ok(())
    }

    /// Immediately rejects a key for new and existing sessions.
    ///
    /// # Errors
    ///
    /// Returns an error when the key does not exist.
    pub fn revoke(&mut self, key_id: &str) -> Result<(), AuthError> {
        let key = self.keys.get_mut(key_id).ok_or(AuthError::KeyNotAccepted)?;
        key.status = KeyStatus::Revoked;
        if self.active_key_id.as_deref() == Some(key_id) {
            self.active_key_id = None;
        }
        self.revocation_epoch = self
            .revocation_epoch
            .checked_add(1)
            .ok_or(AuthError::RevocationEpochExhausted)?;
        Ok(())
    }

    /// Signs a new-session proof exclusively with the ACTIVE key.
    ///
    /// # Errors
    ///
    /// Rejects malformed transcript identifiers or a missing ACTIVE key.
    pub fn sign_new_session(
        &self,
        mut transcript: AuthTranscript,
    ) -> Result<SignedTranscript, AuthError> {
        validate_identifier(&transcript.session_id)?;
        let active_id = self.active_key_id.as_ref().ok_or(AuthError::NoActiveKey)?;
        transcript.key_id.clone_from(active_id);
        let record = self.keys.get(active_id).ok_or(AuthError::NoActiveKey)?;
        let tag = calculate_tag(record.secret.as_ref(), &transcript)?;
        Ok(SignedTranscript {
            transcript,
            proof: AuthProof {
                key_id: active_id.clone(),
                tag,
            },
        })
    }

    /// Verifies a proof against the current ACTIVE key for a new session.
    ///
    /// The caller must independently enforce the expected peer role and claim the session in its
    /// replay registry. This method validates only identifier, key lifecycle and HMAC integrity.
    ///
    /// # Errors
    ///
    /// Rejects an unknown, retiring or revoked key, mismatched identifiers, or an invalid proof.
    pub fn verify_active_proof(
        &self,
        transcript: &AuthTranscript,
        proof: &AuthProof,
    ) -> Result<(), AuthError> {
        let record = self.validate_proof_identity(transcript, proof)?;
        if record.status != KeyStatus::Active {
            return Err(AuthError::KeyNotAccepted);
        }
        verify_tag(record.secret.as_ref(), transcript, proof)
    }

    fn verify_existing_session(
        &self,
        transcript: &AuthTranscript,
        proof: &AuthProof,
        now: u64,
    ) -> Result<(), AuthError> {
        let record = self.validate_proof_identity(transcript, proof)?;
        let accepted = match record.status {
            KeyStatus::Active => true,
            KeyStatus::Retiring { accept_until } => now < accept_until,
            KeyStatus::Revoked => false,
        };
        if !accepted {
            return Err(AuthError::KeyNotAccepted);
        }
        verify_tag(record.secret.as_ref(), transcript, proof)
    }

    fn validate_proof_identity(
        &self,
        transcript: &AuthTranscript,
        proof: &AuthProof,
    ) -> Result<&KeyRecord, AuthError> {
        validate_identifier(&transcript.session_id)?;
        if transcript.key_id != proof.key_id {
            return Err(AuthError::KeyMismatch);
        }
        self.keys
            .get(&proof.key_id)
            .ok_or(AuthError::KeyNotAccepted)
    }

    /// Returns a counter changed by every emergency revocation so session managers can terminate
    /// already authenticated channels immediately.
    #[must_use]
    pub const fn revocation_epoch(&self) -> u64 {
        self.revocation_epoch
    }

    /// Returns non-secret lifecycle information.
    #[must_use]
    pub fn status(&self, key_id: &str) -> Option<KeyStatus> {
        self.keys.get(key_id).map(|record| record.status)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EstablishedSession {
    key_id: String,
    accept_until: u64,
}

/// Registry that prevents RETIRING keys from authenticating new sessions.
#[derive(Debug)]
pub struct SessionRegistry {
    sessions: BTreeMap<String, EstablishedSession>,
    replay: ReplayGuard,
    max_entries: usize,
}

impl SessionRegistry {
    /// Creates a bounded registry and replay cache.
    ///
    /// # Errors
    ///
    /// Rejects a zero session limit.
    pub fn new(max_entries: usize) -> Result<Self, AuthError> {
        Ok(Self {
            sessions: BTreeMap::new(),
            replay: ReplayGuard::new(max_entries)?,
            max_entries,
        })
    }

    /// Accepts a new session only when its proof uses the current ACTIVE key.
    ///
    /// # Errors
    ///
    /// Rejects invalid proofs, RETIRING/REVOKED keys, replay, invalid lifetime, or capacity
    /// exhaustion after expired sessions are pruned.
    pub fn accept_new(
        &mut self,
        keys: &AuthKeyring,
        transcript: &AuthTranscript,
        proof: &AuthProof,
        now: u64,
        lifetime_seconds: u64,
    ) -> Result<(), AuthError> {
        let accept_until = now
            .checked_add(lifetime_seconds)
            .filter(|expiry| *expiry > now)
            .ok_or(AuthError::InvalidSessionLifetime)?;
        self.sessions
            .retain(|_, session| session.accept_until > now);
        if self.sessions.len() >= self.max_entries {
            return Err(AuthError::Replay);
        }
        keys.verify_active_proof(transcript, proof)?;
        self.replay
            .claim(&transcript.session_id, now, accept_until)?;
        self.sessions.insert(
            transcript.session_id.clone(),
            EstablishedSession {
                key_id: proof.key_id.clone(),
                accept_until,
            },
        );
        Ok(())
    }

    /// Verifies a continuation only for a session registered before key retirement.
    ///
    /// # Errors
    ///
    /// Rejects unknown/expired sessions, key substitution, expired/revoked keys, or invalid proof.
    pub fn verify_continuation(
        &self,
        keys: &AuthKeyring,
        transcript: &AuthTranscript,
        proof: &AuthProof,
        now: u64,
    ) -> Result<(), AuthError> {
        let session = self
            .sessions
            .get(&transcript.session_id)
            .filter(|session| session.accept_until > now)
            .ok_or(AuthError::SessionNotEstablished)?;
        if session.key_id != proof.key_id {
            return Err(AuthError::KeyMismatch);
        }
        keys.verify_existing_session(transcript, proof, now)
    }
}

/// Bounded replay cache for accepted handshake session IDs.
#[derive(Debug)]
pub struct ReplayGuard {
    accepted_until: BTreeMap<String, u64>,
    max_entries: usize,
}

impl ReplayGuard {
    /// Creates a replay cache with a hard memory bound.
    ///
    /// # Errors
    ///
    /// Rejects a zero entry limit.
    pub fn new(max_entries: usize) -> Result<Self, AuthError> {
        if max_entries == 0 {
            return Err(AuthError::InvalidIdentifier);
        }
        Ok(Self {
            accepted_until: BTreeMap::new(),
            max_entries,
        })
    }

    /// Atomically claims a verified session ID until the supplied exclusive expiry.
    ///
    /// # Errors
    ///
    /// Rejects malformed IDs, expiry not after `now`, a live replay, or a full cache after expired
    /// entries have been pruned.
    pub fn claim(
        &mut self,
        session_id: &str,
        now: u64,
        accept_until: u64,
    ) -> Result<(), AuthError> {
        validate_identifier(session_id)?;
        if accept_until <= now {
            return Err(AuthError::Replay);
        }
        self.accepted_until.retain(|_, expiry| *expiry > now);
        if self.accepted_until.contains_key(session_id)
            || self.accepted_until.len() >= self.max_entries
        {
            return Err(AuthError::Replay);
        }
        self.accepted_until
            .insert(session_id.to_owned(), accept_until);
        Ok(())
    }
}

fn validate_identifier(value: &str) -> Result<(), AuthError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(AuthError::InvalidIdentifier);
    }
    Ok(())
}

fn validate_key(secret: &[u8; 32]) -> Result<(), AuthError> {
    if secret.iter().all(|byte| *byte == 0) {
        return Err(AuthError::InvalidKey);
    }
    Ok(())
}

fn calculate_tag(secret: &[u8], transcript: &AuthTranscript) -> Result<[u8; 32], AuthError> {
    let mut mac = HmacSha256::new_from_slice(secret).map_err(|_| AuthError::InvalidKey)?;
    mac.update(&canonical_transcript(transcript)?);
    Ok(mac.finalize().into_bytes().into())
}

fn verify_tag(
    secret: &[u8],
    transcript: &AuthTranscript,
    proof: &AuthProof,
) -> Result<(), AuthError> {
    let mut mac = HmacSha256::new_from_slice(secret).map_err(|_| AuthError::InvalidKey)?;
    mac.update(&canonical_transcript(transcript)?);
    mac.verify_slice(&proof.tag)
        .map_err(|_| AuthError::InvalidProof)
}

fn canonical_transcript(transcript: &AuthTranscript) -> Result<Vec<u8>, AuthError> {
    validate_identifier(&transcript.key_id)?;
    validate_identifier(&transcript.session_id)?;
    let mut bytes = Vec::with_capacity(256);
    for field in [
        PROTOCOL.as_bytes(),
        transcript.key_id.as_bytes(),
        transcript.session_id.as_bytes(),
        transcript.role.wire_name().as_bytes(),
        transcript.client_nonce.as_slice(),
        transcript.provider_nonce.as_slice(),
    ] {
        bytes.extend_from_slice(&(field.len() as u64).to_be_bytes());
        bytes.extend_from_slice(field);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn transcript(key_id: &str) -> AuthTranscript {
        AuthTranscript {
            key_id: key_id.into(),
            session_id: "session-1".into(),
            client_nonce: [0x11; 32],
            provider_nonce: [0x22; 32],
            role: PeerRole::Client,
        }
    }

    #[test]
    fn retiring_key_expires_exactly_at_grace_boundary() {
        let mut keys = AuthKeyring::bootstrap("key-old", [0x41; 32]).unwrap();
        let signed = keys.sign_new_session(transcript("ignored")).unwrap();
        let old_proof = signed.proof;
        let old_transcript = signed.transcript;
        keys.rotate("key-new", [0x42; 32], 1_000, 300).unwrap();
        keys.verify_existing_session(&old_transcript, &old_proof, 1_299)
            .unwrap();
        assert_eq!(
            keys.verify_existing_session(&old_transcript, &old_proof, 1_300),
            Err(AuthError::KeyNotAccepted)
        );
        assert_eq!(
            keys.sign_new_session(old_transcript).unwrap().proof.key_id,
            "key-new"
        );
    }

    #[test]
    fn emergency_revocation_is_immediate_and_observable() {
        let mut keys = AuthKeyring::bootstrap("key-active", [0x41; 32]).unwrap();
        let signed = keys.sign_new_session(transcript("ignored")).unwrap();
        let proof = signed.proof;
        let active = signed.transcript;
        keys.verify_existing_session(&active, &proof, 10).unwrap();
        let epoch = keys.revocation_epoch();
        keys.revoke("key-active").unwrap();
        assert_eq!(keys.revocation_epoch(), epoch + 1);
        assert_eq!(
            keys.verify_existing_session(&active, &proof, 10),
            Err(AuthError::KeyNotAccepted)
        );
        assert_eq!(keys.sign_new_session(active), Err(AuthError::NoActiveKey));
    }

    #[test]
    fn proof_binds_role_nonces_session_and_key() {
        let keys = AuthKeyring::bootstrap("key-active", [0x41; 32]).unwrap();
        let signed = keys.sign_new_session(transcript("ignored")).unwrap();
        let proof = signed.proof;
        let mut changed = signed.transcript;
        changed.role = PeerRole::Provider;
        assert_eq!(
            keys.verify_existing_session(&changed, &proof, 10),
            Err(AuthError::InvalidProof)
        );
    }

    #[test]
    fn replay_guard_rejects_live_session_and_reuses_after_expiry() {
        let mut guard = ReplayGuard::new(2).unwrap();
        guard.claim("session-1", 100, 200).unwrap();
        assert_eq!(guard.claim("session-1", 150, 250), Err(AuthError::Replay));
        guard.claim("session-1", 200, 300).unwrap();
    }

    #[test]
    fn session_registry_rejects_replayed_authenticated_handshake() {
        let keys = AuthKeyring::bootstrap("key-active", [0x41; 32]).unwrap();
        let signed = keys.sign_new_session(transcript("ignored")).unwrap();
        let mut sessions = SessionRegistry::new(4).unwrap();
        sessions
            .accept_new(&keys, &signed.transcript, &signed.proof, 100, 30)
            .unwrap();
        assert_eq!(
            sessions.accept_new(&keys, &signed.transcript, &signed.proof, 101, 30),
            Err(AuthError::Replay)
        );
    }

    #[test]
    fn rejects_zero_key_and_grace_above_ceiling() {
        assert!(matches!(
            AuthKeyring::bootstrap("key", [0; 32]),
            Err(AuthError::InvalidKey)
        ));
        let mut keys = AuthKeyring::bootstrap("key-old", [0x41; 32]).unwrap();
        assert_eq!(
            keys.rotate("key-new", [0x42; 32], 0, 301),
            Err(AuthError::InvalidGracePeriod)
        );
    }

    #[test]
    fn retiring_key_can_continue_but_cannot_open_a_new_session() {
        let mut keys = AuthKeyring::bootstrap("key-old", [0x41; 32]).unwrap();
        let existing = keys.sign_new_session(transcript("ignored")).unwrap();
        let mut sessions = SessionRegistry::new(10).unwrap();
        sessions
            .accept_new(&keys, &existing.transcript, &existing.proof, 999, 1_000)
            .unwrap();

        let forged_new = AuthTranscript {
            session_id: "session-2".into(),
            ..existing.transcript.clone()
        };
        let forged_proof = AuthProof {
            key_id: "key-old".into(),
            tag: calculate_tag(&[0x41; 32], &forged_new).unwrap(),
        };
        keys.rotate("key-new", [0x42; 32], 1_000, 300).unwrap();

        sessions
            .verify_continuation(&keys, &existing.transcript, &existing.proof, 1_299)
            .unwrap();
        assert_eq!(
            sessions.accept_new(&keys, &forged_new, &forged_proof, 1_001, 100),
            Err(AuthError::KeyNotAccepted)
        );
        assert_eq!(
            sessions.verify_continuation(&keys, &existing.transcript, &existing.proof, 1_300),
            Err(AuthError::KeyNotAccepted)
        );
    }
}
