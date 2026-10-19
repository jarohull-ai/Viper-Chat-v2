//! Structural integrity checks for the separate synthetic evaluation benchmark.

use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fmt::Write as _, fs, path::PathBuf};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BenchmarkManifest {
    schema_version: u32,
    benchmark_version: String,
    status: String,
    created_at: String,
    ground_truth: String,
    sources: Vec<BenchmarkSource>,
    limitations: Vec<String>,
    files: Vec<BenchmarkFile>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BenchmarkFile {
    file: String,
    sha256_sidecar: String,
    samples: usize,
    labels: BTreeMap<String, usize>,
    splits: BTreeMap<String, usize>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BenchmarkSource {
    id: String,
    location: String,
    license: String,
    use_note: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    id: String,
    split: String,
    label: String,
    subcategory: String,
    context: String,
    prompt: String,
    candidate_text: String,
    ground_truth: String,
}

#[test]
fn synthetic_benchmark_is_pinned_balanced_and_has_ground_truth() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../evaluation/semantic-v1");
    let manifest: BenchmarkManifest =
        serde_json::from_slice(&fs::read(root.join("manifest.json")).unwrap()).unwrap();
    assert_eq!(manifest.schema_version, 1);
    assert_eq!(manifest.benchmark_version, "semantic-v1");
    assert_eq!(manifest.status, "synthetic_pilot_not_calibrated");
    assert_eq!(manifest.created_at, "2026-10-19");
    assert!(!manifest.ground_truth.is_empty());
    assert!(!manifest.limitations.is_empty());
    assert!(manifest.sources.iter().any(|source| {
        source.id == "synthetic-cases"
            && source.location.starts_with("authored-")
            && source.license == "Synthetic"
            && !source.use_note.is_empty()
    }));
    assert_eq!(manifest.files.len(), 1);

    let entry = &manifest.files[0];
    let bytes = fs::read(root.join(&entry.file)).unwrap();
    let sidecar = fs::read_to_string(root.join(&entry.sha256_sidecar)).unwrap();
    let digest = Sha256::digest(&bytes);
    let mut actual = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(&mut actual, "{byte:02x}").unwrap();
    }
    assert_eq!(sidecar.trim(), actual);

    let cases = bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice::<Case>(line).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(cases.len(), entry.samples);
    assert_eq!(cases.len(), 256);
    assert_eq!(
        entry.labels.values().copied().collect::<Vec<_>>(),
        vec![64; 4]
    );
    assert_eq!(entry.splits.get("development"), Some(&192));
    assert_eq!(entry.splits.get("holdout"), Some(&64));

    let mut labels = BTreeMap::<String, usize>::new();
    let mut splits = BTreeMap::<String, usize>::new();
    let mut label_splits = BTreeMap::<(String, String), usize>::new();
    let mut ids = std::collections::HashSet::new();
    let mut injection_techniques = std::collections::HashSet::new();
    for case in &cases {
        assert!(!case.id.is_empty() && ids.insert(&case.id));
        assert!(!case.context.is_empty());
        assert!(!case.prompt.is_empty());
        assert!(!case.subcategory.is_empty());
        assert!(!case.candidate_text.is_empty());
        assert!(!case.ground_truth.is_empty());
        assert!(matches!(case.split.as_str(), "development" | "holdout"));
        *labels.entry(case.label.clone()).or_default() += 1;
        *splits.entry(case.split.clone()).or_default() += 1;
        *label_splits
            .entry((case.label.clone(), case.split.clone()))
            .or_default() += 1;
        if case.label == "prompt_injection" {
            injection_techniques.insert(case.subcategory.as_str());
        }
    }
    assert_eq!(labels.values().copied().collect::<Vec<_>>(), vec![64; 4]);
    assert_eq!(labels, entry.labels);
    assert_eq!(splits.get("development"), Some(&192));
    assert_eq!(splits.get("holdout"), Some(&64));
    assert_eq!(splits, entry.splits);
    for label in [
        "in_distribution",
        "out_of_domain",
        "prompt_injection",
        "factual_error",
    ] {
        assert_eq!(
            label_splits.get(&(label.into(), "development".into())),
            Some(&48)
        );
        assert_eq!(
            label_splits.get(&(label.into(), "holdout".into())),
            Some(&16)
        );
    }
    assert_eq!(injection_techniques.len(), 16);
}
