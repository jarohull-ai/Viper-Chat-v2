//! Local-only Candle BERT sentence embeddings.
//!
//! Enable with `--features viper-seed/candle-embeddings`. The loader never downloads files:
//! callers provision a model bundle and pin SHA-256 digests out of band.

use candle_core::{Device, Tensor};
use candle_nn::VarBuilder;
use candle_transformers::models::bert::{BertModel, Config as BertConfig, DTYPE};
use sha2::{Digest, Sha256};
use std::{fs, path::Path};
use thiserror::Error;
use tokenizers::Tokenizer;

const MAX_CONFIG_BYTES: usize = 2 * 1024 * 1024;
const MAX_TOKENIZER_BYTES: usize = 32 * 1024 * 1024;
const MAX_WEIGHTS_BYTES: usize = 1024 * 1024 * 1024;
const MAX_EMBEDDING_DIMENSIONS: usize = 2048;

/// Locally provisioned BERT bundle and independently pinned file digests.
#[derive(Debug, Clone)]
pub struct CandleBertBundle {
    /// `config.json` path.
    pub config_path: std::path::PathBuf,
    /// `tokenizer.json` path.
    pub tokenizer_path: std::path::PathBuf,
    /// Single-file `model.safetensors` path.
    pub weights_path: std::path::PathBuf,
    /// Expected lowercase SHA-256 of `config.json`.
    pub config_sha256: String,
    /// Expected lowercase SHA-256 of `tokenizer.json`.
    pub tokenizer_sha256: String,
    /// Expected lowercase SHA-256 of `model.safetensors`.
    pub weights_sha256: String,
}

/// Sentence embedding backend contract used by provider-side semantic analysis.
pub trait TextEmbedder {
    /// Embed one input as a finite, L2-normalized sentence vector.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed input, tokenizer/model failures, or non-finite output.
    fn embed(&self, text: &str) -> Result<Vec<f32>, EmbeddingError>;
}

/// Model loading, tokenization, inference, or integrity failure.
#[derive(Debug, Error)]
pub enum EmbeddingError {
    /// A required bundle file could not be read.
    #[error("could not read embedding bundle file: {0}")]
    Io(#[from] std::io::Error),
    /// A bundle file exceeded its configured bound.
    #[error("embedding bundle file exceeds size limit")]
    FileTooLarge,
    /// A provided digest was malformed or did not match the file.
    #[error("embedding bundle digest mismatch")]
    DigestMismatch,
    /// Model or tokenizer metadata was invalid or unsupported.
    #[error("invalid embedding model bundle: {0}")]
    InvalidBundle(String),
    /// Candle could not load the model or run inference.
    #[error("Candle inference failed: {0}")]
    Candle(String),
    /// Tokenizer rejected the input.
    #[error("tokenizer failed: {0}")]
    Tokenizer(String),
    /// Input was empty, too long, or produced invalid numeric evidence.
    #[error("embedding input or output is invalid")]
    InvalidInput,
}

/// CPU Candle implementation for a single-file BERT safetensors bundle.
pub struct CandleBertEmbedder {
    model: BertModel,
    tokenizer: Tokenizer,
    max_tokens: usize,
    dimensions: usize,
}

impl CandleBertEmbedder {
    /// Load a local BERT bundle after checking all three pinned SHA-256 digests.
    ///
    /// This function performs no network access and refuses unpinned or mismatched assets.
    ///
    /// # Errors
    ///
    /// Returns an error if a bundle file is missing, oversized, has the wrong digest, or is not
    /// a supported BERT/tokenizer bundle.
    pub fn load(bundle: &CandleBertBundle) -> Result<Self, EmbeddingError> {
        let config_bytes =
            read_verified(&bundle.config_path, &bundle.config_sha256, MAX_CONFIG_BYTES)?;
        let tokenizer_bytes = read_verified(
            &bundle.tokenizer_path,
            &bundle.tokenizer_sha256,
            MAX_TOKENIZER_BYTES,
        )?;
        let weights_bytes = read_verified(
            &bundle.weights_path,
            &bundle.weights_sha256,
            MAX_WEIGHTS_BYTES,
        )?;

        let config: BertConfig = serde_json::from_slice(&config_bytes)
            .map_err(|error| EmbeddingError::InvalidBundle(error.to_string()))?;
        if config.max_position_embeddings < 2
            || config.hidden_size == 0
            || config.hidden_size > MAX_EMBEDDING_DIMENSIONS
            || config
                .model_type
                .as_deref()
                .is_some_and(|kind| kind != "bert")
        {
            return Err(EmbeddingError::InvalidBundle(
                "unsupported BERT dimensions or sequence limit".into(),
            ));
        }
        let tokenizer = Tokenizer::from_bytes(tokenizer_bytes)
            .map_err(|error| EmbeddingError::Tokenizer(error.to_string()))?;
        let device = Device::Cpu;
        let variables = VarBuilder::from_buffered_safetensors(weights_bytes, DTYPE, &device)
            .map_err(|error| EmbeddingError::Candle(error.to_string()))?;
        let model = BertModel::load(variables, &config)
            .map_err(|error| EmbeddingError::Candle(error.to_string()))?;

        Ok(Self {
            model,
            tokenizer,
            max_tokens: config.max_position_embeddings,
            dimensions: config.hidden_size,
        })
    }
}

impl TextEmbedder for CandleBertEmbedder {
    fn embed(&self, text: &str) -> Result<Vec<f32>, EmbeddingError> {
        if text.trim().is_empty() {
            return Err(EmbeddingError::InvalidInput);
        }
        let encoded = self
            .tokenizer
            .encode(text, true)
            .map_err(|error| EmbeddingError::Tokenizer(error.to_string()))?;
        let ids = encoded.get_ids();
        if ids.is_empty() || ids.len() > self.max_tokens {
            return Err(EmbeddingError::InvalidInput);
        }

        let device = Device::Cpu;
        let input_ids = Tensor::new(ids, &device)
            .and_then(|tensor| tensor.unsqueeze(0))
            .map_err(|error| EmbeddingError::Candle(error.to_string()))?;
        let attention_values = encoded.get_attention_mask();
        let attention = Tensor::new(attention_values, &device)
            .and_then(|tensor| tensor.unsqueeze(0))
            .map_err(|error| EmbeddingError::Candle(error.to_string()))?;
        let token_types = input_ids
            .zeros_like()
            .map_err(|error| EmbeddingError::Candle(error.to_string()))?;
        let token_embeddings = self
            .model
            .forward(&input_ids, &token_types, Some(&attention))
            .map_err(|error| EmbeddingError::Candle(error.to_string()))?
            .to_vec3::<f32>()
            .map_err(|error| EmbeddingError::Candle(error.to_string()))?
            .into_iter()
            .next()
            .ok_or(EmbeddingError::InvalidInput)?;

        let mut pooled = vec![0.0_f64; self.dimensions];
        let mut included = 0_u32;
        for (token, mask) in token_embeddings.iter().zip(attention_values) {
            if *mask == 0 {
                continue;
            }
            if token.len() != self.dimensions || !token.iter().all(|value| value.is_finite()) {
                return Err(EmbeddingError::InvalidInput);
            }
            for (sum, value) in pooled.iter_mut().zip(token) {
                *sum += f64::from(*value);
            }
            included += 1;
        }
        if included == 0 {
            return Err(EmbeddingError::InvalidInput);
        }
        let inverse_count = 1.0 / f64::from(included);
        let norm = pooled
            .iter()
            .map(|value| (value * inverse_count).powi(2))
            .sum::<f64>()
            .sqrt();
        if !norm.is_finite() || norm <= f64::EPSILON {
            return Err(EmbeddingError::InvalidInput);
        }
        // Candle's model tensors and public embedding contract are f32; this narrowing is the
        // intentional final conversion after pooling and normalization in f64.
        #[allow(clippy::cast_possible_truncation)]
        let normalized = pooled
            .into_iter()
            .map(|value| ((value * inverse_count) / norm) as f32)
            .collect::<Vec<_>>();
        if normalized.iter().all(|value| value.is_finite()) {
            Ok(normalized)
        } else {
            Err(EmbeddingError::InvalidInput)
        }
    }
}

fn read_verified(
    path: &Path,
    expected_digest: &str,
    limit: usize,
) -> Result<Vec<u8>, EmbeddingError> {
    if !is_lower_hex_digest(expected_digest) {
        return Err(EmbeddingError::DigestMismatch);
    }
    let metadata = fs::metadata(path)?;
    if !metadata.is_file() || metadata.len() > limit as u64 {
        return Err(EmbeddingError::FileTooLarge);
    }
    let bytes = fs::read(path)?;
    if bytes.len() > limit || encode_hex(&Sha256::digest(&bytes)) != expected_digest {
        return Err(EmbeddingError::DigestMismatch);
    }
    Ok(bytes)
}

fn is_lower_hex_digest(digest: &str) -> bool {
    digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn bundle_loader_rejects_unpinned_or_modified_files() {
        let directory = tempdir().unwrap();
        let config_path = directory.path().join("config.json");
        fs::write(&config_path, b"{}").unwrap();
        assert!(matches!(
            read_verified(&config_path, &"0".repeat(64), MAX_CONFIG_BYTES),
            Err(EmbeddingError::DigestMismatch)
        ));
        assert!(matches!(
            read_verified(&config_path, "not-a-digest", MAX_CONFIG_BYTES),
            Err(EmbeddingError::DigestMismatch)
        ));
    }
}
