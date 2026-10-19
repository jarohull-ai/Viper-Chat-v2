//! Strict bootstrap of one SEED IPC key from a pre-opened credential descriptor.

use crate::ipc_auth::AuthKeyring;
use std::io::{Read, Take};
use thiserror::Error;
use zeroize::Zeroizing;

const HEADER: &str = "VIPER_SEED_KEY_V1\n";
const MAX_RECORD_BYTES: usize = 256;
const READ_LIMIT: u64 = 257;

/// A sanitized credential-loading failure. It never includes source bytes or OS error details.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum CredentialLoadError {
    /// The descriptor could not be read or exceeded the hard record-size bound.
    #[error("credential source is unavailable or too large")]
    Unavailable,
    /// The versioned record is malformed or contains an invalid key.
    #[error("credential record is invalid")]
    InvalidRecord,
}

/// Loads a keyring from one already-opened inherited descriptor or OS credential stream.
///
/// The record is exactly three newline-terminated lines:
/// `VIPER_SEED_KEY_V1`, a key ID, and 64 lowercase hex characters. The caller is responsible for
/// securely provisioning the descriptor and ensuring it is inherited only by the intended
/// process. The reader is consumed once; secret-bearing buffers are zeroized on drop.
///
/// # Errors
///
/// Returns only a sanitized error; input bytes and underlying I/O details are never exposed.
pub fn load_keyring<R: Read>(reader: R) -> Result<AuthKeyring, CredentialLoadError> {
    let mut bounded = reader.take(READ_LIMIT);
    let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_RECORD_BYTES));
    read_bounded(&mut bounded, &mut bytes)?;
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(CredentialLoadError::Unavailable);
    }

    let text = std::str::from_utf8(&bytes).map_err(|_| CredentialLoadError::InvalidRecord)?;
    let Some(body) = text.strip_prefix(HEADER) else {
        return Err(CredentialLoadError::InvalidRecord);
    };
    let Some(body) = body.strip_suffix('\n') else {
        return Err(CredentialLoadError::InvalidRecord);
    };
    let mut lines = body.split('\n');
    let key_id = lines.next().ok_or(CredentialLoadError::InvalidRecord)?;
    let key_hex = lines.next().ok_or(CredentialLoadError::InvalidRecord)?;
    if lines.next().is_some() || key_id.is_empty() || key_hex.len() != 64 {
        return Err(CredentialLoadError::InvalidRecord);
    }

    let mut secret = Zeroizing::new([0u8; 32]);
    for (index, pair) in key_hex.as_bytes().chunks_exact(2).enumerate() {
        let high = decode_nibble(pair[0]).ok_or(CredentialLoadError::InvalidRecord)?;
        let low = decode_nibble(pair[1]).ok_or(CredentialLoadError::InvalidRecord)?;
        secret[index] = (high << 4) | low;
    }
    AuthKeyring::bootstrap(key_id, *secret).map_err(|_| CredentialLoadError::InvalidRecord)
}

fn read_bounded<R: Read>(
    reader: &mut Take<R>,
    bytes: &mut Vec<u8>,
) -> Result<(), CredentialLoadError> {
    reader
        .read_to_end(bytes)
        .map(|_| ())
        .map_err(|_| CredentialLoadError::Unavailable)
}

const fn decode_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn record(key: &str) -> Vec<u8> {
        format!("{HEADER}bootstrap-1\n{key}\n").into_bytes()
    }

    #[test]
    fn loads_one_strict_key_record() {
        let keyring = load_keyring(Cursor::new(record(&"41".repeat(32)))).unwrap();
        let signed = keyring
            .sign_new_session(crate::ipc_auth::AuthTranscript {
                key_id: String::new(),
                session_id: "session-1".into(),
                client_nonce: [1; 32],
                provider_nonce: [2; 32],
                role: crate::ipc_auth::PeerRole::Client,
            })
            .unwrap();
        assert_eq!(signed.proof.key_id, "bootstrap-1");
    }

    #[test]
    fn rejects_truncation_uppercase_extra_fields_and_zero_key() {
        for bytes in [
            b"VIPER_SEED_KEY_V1\nbroken".to_vec(),
            record(&"AA".repeat(32)),
            [record(&"41".repeat(32)), b"unexpected\n".to_vec()].concat(),
            record(&"00".repeat(32)),
        ] {
            assert_eq!(
                load_keyring(Cursor::new(bytes)).err().unwrap(),
                CredentialLoadError::InvalidRecord
            );
        }
    }

    #[test]
    fn rejects_oversized_secret_record() {
        assert_eq!(
            load_keyring(Cursor::new(vec![b'x'; MAX_RECORD_BYTES + 1]))
                .err()
                .unwrap(),
            CredentialLoadError::Unavailable
        );
    }
}
