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
}
