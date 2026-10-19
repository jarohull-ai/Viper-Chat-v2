//! Integration coverage for loading the checked-in corpus and estimating LID.
#![cfg(feature = "candle-embeddings")]

use std::path::PathBuf;
use viper_seed::{
    corpus::CorpusLoader,
    embedding::{EmbeddingError, TextEmbedder},
    semantic::estimate_lid,
};

struct DeterministicFixtureEmbedder<'a> {
    texts: &'a [String],
}

impl TextEmbedder for DeterministicFixtureEmbedder<'_> {
    fn embed(&self, text: &str) -> Result<Vec<f32>, EmbeddingError> {
        let index = self
            .texts
            .iter()
            .position(|candidate| candidate == text)
            .ok_or(EmbeddingError::InvalidInput)?;
        if index == 0 {
            return Ok(vec![0.0, 0.0]);
        }
        let distance = match index {
            1 => 0.1,
            2 => 0.2,
            3 => 0.4,
            index => {
                1.0 + f32::from(u8::try_from(index).map_err(|_| EmbeddingError::InvalidInput)?)
            }
        };
        Ok(vec![distance, 0.0])
    }
}

#[test]
fn verified_corpus_sample_produces_expected_lid_range() {
    let corpus_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../corpus/v1");
    let corpus = CorpusLoader::new(corpus_path)
        .load()
        .expect("verified corpus v1");
    assert_eq!(corpus.version(), "v1");
    assert_eq!(corpus.samples().len(), 16);

    let texts = corpus
        .samples()
        .iter()
        .map(|sample| sample.text.clone())
        .collect::<Vec<_>>();
    let test_embedder = DeterministicFixtureEmbedder { texts: &texts };
    let query = test_embedder
        .embed(&corpus.samples()[0].text)
        .expect("fixture query embedding");
    let references = corpus.samples()[1..]
        .iter()
        .map(|sample| {
            test_embedder
                .embed(&sample.text)
                .expect("fixture reference embedding")
        })
        .collect::<Vec<_>>();

    let estimate = estimate_lid(&query, &references, 3).expect("LID over loaded references");
    assert!(
        (1.4..1.5).contains(&estimate.value),
        "unexpected LID: {}",
        estimate.value
    );
    assert_eq!(estimate.neighbors_used, 3);
}

#[test]
fn corpus_v2_has_diverse_tracked_provenance() {
    use viper_seed::corpus::CorpusCategory;

    let corpus_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../corpus/v2");
    let corpus = CorpusLoader::new(corpus_path)
        .load()
        .expect("verified corpus v2");
    assert_eq!(corpus.version(), "v2");
    assert_eq!(corpus.samples().len(), 100);
    assert_eq!(corpus.sources().len(), 6);
    assert!(
        corpus
            .samples()
            .iter()
            .all(|sample| sample.source_ref.is_some())
    );
    for category in [
        CorpusCategory::Code,
        CorpusCategory::Documentation,
        CorpusCategory::Email,
        CorpusCategory::General,
    ] {
        assert_eq!(
            corpus
                .samples()
                .iter()
                .filter(|sample| sample.category == category)
                .count(),
            25
        );
    }
}
