//! Deterministic semantic geometry primitives for the provider-side SEED engine.
//!
//! This module deliberately accepts vectors only as in-process inputs. IPC clients must never be
//! allowed to submit LID values or embeddings as trusted evidence.

use thiserror::Error;

const MAX_LID_NEIGHBORS: usize = 256;
const MAX_LID_REFERENCE_VECTORS: usize = 4096;
const MAX_LID_DIMENSIONS: usize = 2048;

/// A provider-computed local intrinsic dimensionality estimate.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LidEstimate {
    /// Maximum-likelihood LID estimate over the selected nearest neighbors.
    pub value: f64,
    /// Number of neighbors used in the estimate.
    pub neighbors_used: usize,
}

/// Observation state for LID before empirical calibration.
///
/// This intentionally has no verdict-like variants. It cannot authorize, veto, or escalate an
/// action; consumers must treat the numeric value as diagnostic telemetry only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LidObservationStatus {
    /// Model/corpus evidence has not been calibrated against an approved real-data holdout.
    Uncalibrated,
}

/// Pinned identities that must accompany every diagnostic LID observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LidProvenance {
    /// Stable model identifier, including an upstream revision where applicable.
    pub model_id: String,
    /// SHA-256 fingerprint of the exact model bundle used to create the vectors.
    pub model_bundle_sha256: String,
    /// Version of the verified reference corpus.
    pub corpus_version: String,
    /// SHA-256 of the exact verified corpus manifest bytes.
    pub corpus_manifest_sha256: String,
}

/// Diagnostic-only evaluator result; it contains no policy recommendation or verdict.
#[derive(Debug, Clone, PartialEq)]
pub struct LidObservation {
    /// Raw geometric estimate and neighbor count.
    pub estimate: LidEstimate,
    /// The model/corpus identity supplied by the provider-side caller.
    pub provenance: LidProvenance,
    /// Explicit marker that no threshold calibration has been applied.
    pub status: LidObservationStatus,
}

/// Invalid or insufficient evidence for a local intrinsic dimensionality estimate.
#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum SemanticGeometryError {
    /// The query or a corpus vector is empty, non-finite, or has the wrong dimension.
    #[error("embedding is empty, non-finite, or has an inconsistent dimension")]
    InvalidEmbedding,
    /// The requested neighbor count is outside the supported range.
    #[error("neighbor count must be at least two and no greater than corpus size")]
    InvalidNeighborCount,
    /// The nearest-neighbor distances are degenerate, so an estimate is not trustworthy.
    #[error("nearest-neighbor distances are degenerate")]
    DegenerateDistances,
    /// Required model/corpus provenance is missing or malformed.
    #[error("semantic evidence provenance is invalid")]
    InvalidProvenance,
}

/// Computes a diagnostic LID observation and binds it to model/corpus identities.
///
/// This function deliberately performs no thresholding, verdict mapping, persistence, or
/// telemetry export. The caller must provide identities for the verified embedder and corpus
/// that produced the supplied vectors. Until a separately approved calibration exists, the
/// result is always marked [`LidObservationStatus::Uncalibrated`].
///
/// # Errors
///
/// Returns the same geometry errors as [`estimate_lid`], or `InvalidProvenance` when an
/// identity is empty, oversized, contains control characters, or has a malformed SHA-256.
pub fn evaluate_lid(
    query: &[f32],
    reference_vectors: &[Vec<f32>],
    neighbors: usize,
    provenance: LidProvenance,
) -> Result<LidObservation, SemanticGeometryError> {
    if provenance.model_id.trim().is_empty()
        || provenance.model_id.len() > 128
        || provenance.model_id.chars().any(char::is_control)
        || provenance.corpus_version.trim().is_empty()
        || provenance.corpus_version.len() > 64
        || provenance.corpus_version.chars().any(char::is_control)
        || !is_lower_sha256(&provenance.model_bundle_sha256)
        || !is_lower_sha256(&provenance.corpus_manifest_sha256)
    {
        return Err(SemanticGeometryError::InvalidProvenance);
    }
    let estimate = estimate_lid(query, reference_vectors, neighbors)?;
    Ok(LidObservation {
        estimate,
        provenance,
        status: LidObservationStatus::Uncalibrated,
    })
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Estimates local intrinsic dimensionality using the maximum-likelihood distance-ratio formula.
///
/// The `reference_vectors` must come from a provider-loaded, versioned corpus and `query` must be
/// encoded by the provider's pinned embedding implementation. This function performs no encoding,
/// corpus loading, threshold selection, or policy decision. Any malformed or degenerate evidence
/// is an error and must not be replaced with a default value.
///
/// # Errors
///
/// Returns an error for empty/non-finite/inconsistently sized vectors, an invalid neighbor count,
/// duplicate/zero nearest distances, or a non-finite estimate.
pub fn estimate_lid(
    query: &[f32],
    reference_vectors: &[Vec<f32>],
    neighbors: usize,
) -> Result<LidEstimate, SemanticGeometryError> {
    if query.is_empty()
        || query.len() > MAX_LID_DIMENSIONS
        || reference_vectors.len() > MAX_LID_REFERENCE_VECTORS
        || !query.iter().all(|value| value.is_finite())
    {
        return Err(SemanticGeometryError::InvalidEmbedding);
    }
    if !(2..=MAX_LID_NEIGHBORS).contains(&neighbors) || neighbors > reference_vectors.len() {
        return Err(SemanticGeometryError::InvalidNeighborCount);
    }

    let mut distances = Vec::with_capacity(reference_vectors.len());
    for vector in reference_vectors {
        if vector.len() != query.len() || !vector.iter().all(|value| value.is_finite()) {
            return Err(SemanticGeometryError::InvalidEmbedding);
        }
        let squared_distance = query
            .iter()
            .zip(vector)
            .map(|(left, right)| {
                let delta = f64::from(*left) - f64::from(*right);
                delta * delta
            })
            .sum::<f64>();
        let distance = squared_distance.sqrt();
        if !distance.is_finite() {
            return Err(SemanticGeometryError::InvalidEmbedding);
        }
        distances.push(distance);
    }

    distances.sort_by(f64::total_cmp);
    let nearest = &distances[..neighbors];
    let max_distance = nearest[neighbors - 1];
    if max_distance <= 0.0 || nearest.iter().any(|distance| *distance <= 0.0) {
        return Err(SemanticGeometryError::DegenerateDistances);
    }

    let log_distance_ratios = nearest
        .iter()
        .map(|distance| (distance / max_distance).ln())
        .sum::<f64>();
    if !log_distance_ratios.is_finite() || log_distance_ratios >= 0.0 {
        return Err(SemanticGeometryError::DegenerateDistances);
    }
    let neighbor_count =
        u32::try_from(neighbors).map_err(|_| SemanticGeometryError::InvalidNeighborCount)?;
    let value = -f64::from(neighbor_count) / log_distance_ratios;
    if !value.is_finite() || value <= 0.0 {
        return Err(SemanticGeometryError::DegenerateDistances);
    }
    Ok(LidEstimate {
        value,
        neighbors_used: neighbors,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn estimates_lid_from_nearest_distance_ratios_independent_of_corpus_order() {
        let query = [0.0_f32, 0.0];
        let corpus = vec![vec![0.4, 0.0], vec![0.1, 0.0], vec![0.2, 0.0]];
        let expected = 3.0 / (4.0_f64.ln() + 2.0_f64.ln());
        let estimate = estimate_lid(&query, &corpus, 3).unwrap();
        assert!((estimate.value - expected).abs() < 1.0e-12);
        assert_eq!(estimate.neighbors_used, 3);

        let reversed = corpus.into_iter().rev().collect::<Vec<_>>();
        assert_eq!(estimate_lid(&query, &reversed, 3).unwrap(), estimate);
    }

    #[test]
    fn malformed_and_degenerate_evidence_fails_closed() {
        let query = [0.0_f32, 0.0];
        assert_eq!(
            estimate_lid(&query, &[vec![1.0, 0.0]], 1),
            Err(SemanticGeometryError::InvalidNeighborCount)
        );
        assert_eq!(
            estimate_lid(&query, &[vec![1.0, 0.0], vec![1.0]], 2),
            Err(SemanticGeometryError::InvalidEmbedding)
        );
        assert_eq!(
            estimate_lid(&query, &[vec![1.0]], 2),
            Err(SemanticGeometryError::InvalidNeighborCount)
        );
        assert_eq!(
            estimate_lid(&query, &[vec![1.0, 0.0], vec![0.0, 1.0]], 2),
            Err(SemanticGeometryError::DegenerateDistances)
        );
        assert_eq!(
            estimate_lid(&[f32::NAN], &[vec![1.0]], 1),
            Err(SemanticGeometryError::InvalidEmbedding)
        );
    }

    #[test]
    fn rejects_non_finite_and_mismatched_vectors() {
        assert_eq!(
            estimate_lid(&[0.0], &[vec![f32::INFINITY], vec![1.0]], 2),
            Err(SemanticGeometryError::InvalidEmbedding)
        );
        assert_eq!(
            estimate_lid(&[0.0, 0.0], &[vec![1.0, 0.0], vec![1.0]], 2),
            Err(SemanticGeometryError::InvalidEmbedding)
        );
    }

    #[test]
    fn evaluator_returns_only_uncalibrated_observation_with_pinned_identities() {
        let provenance = LidProvenance {
            model_id: "test-model@revision-1".into(),
            model_bundle_sha256: "a".repeat(64),
            corpus_version: "v2".into(),
            corpus_manifest_sha256: "b".repeat(64),
        };
        let observation = evaluate_lid(
            &[0.0, 0.0],
            &[vec![0.1, 0.0], vec![0.2, 0.0], vec![0.4, 0.0]],
            3,
            provenance.clone(),
        )
        .unwrap();

        assert_eq!(observation.estimate.neighbors_used, 3);
        assert!(observation.estimate.value.is_finite());
        assert_eq!(observation.provenance, provenance);
        assert_eq!(observation.status, LidObservationStatus::Uncalibrated);
    }

    #[test]
    fn evaluator_rejects_missing_or_malformed_provenance() {
        let invalid = LidProvenance {
            model_id: "model".into(),
            model_bundle_sha256: "not-a-digest".into(),
            corpus_version: "v2".into(),
            corpus_manifest_sha256: "b".repeat(64),
        };
        assert_eq!(
            evaluate_lid(&[0.0], &[vec![0.1], vec![0.2]], 2, invalid),
            Err(SemanticGeometryError::InvalidProvenance)
        );
    }
}
