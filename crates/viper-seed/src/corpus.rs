//! Offline, versioned semantic reference corpus with fail-closed integrity checks.

use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
};
use thiserror::Error;

const MAX_MANIFEST_BYTES: usize = 1024 * 1024;
const MAX_FILE_BYTES: usize = 8 * 1024 * 1024;
const MAX_CORPUS_BYTES: usize = 32 * 1024 * 1024;
const MAX_FILES: usize = 32;
const MAX_SAMPLES: usize = 10_000;
const MAX_SAMPLE_TEXT_BYTES: usize = 16 * 1024;

/// Content domain represented in the trusted reference set.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CorpusCategory {
    /// Source code and code-adjacent snippets.
    Code,
    /// Technical or project documentation.
    Documentation,
    /// Synthetic, non-personal email examples.
    Email,
    /// General prose and task descriptions.
    General,
}

/// A bounded corpus reference sample.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CorpusSample {
    /// Stable sample identifier unique in a corpus release.
    pub id: String,
    /// Content domain used for stratified evaluation.
    pub category: CorpusCategory,
    /// Representative text; corpus sources must not contain secrets or personal data.
    pub text: String,
    /// Stable key into the release manifest's provenance catalog.
    #[serde(default)]
    pub source_ref: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema_version: u32,
    corpus_version: String,
    created_at: String,
    #[serde(default)]
    sources: Vec<CorpusSource>,
    files: Vec<ManifestFile>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestFile {
    file: String,
    samples: usize,
}

/// Provenance record for a corpus source.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CorpusSource {
    /// Stable source key referenced by samples.
    pub id: String,
    /// Local repository path or public source URL.
    pub location: String,
    /// SPDX expression or `Synthetic` for authored examples.
    pub license: String,
    /// Whether sample text is original, paraphrased, or locally derived.
    pub use_note: String,
}

/// A fully verified, immutable-in-memory corpus release.
#[derive(Debug, Clone)]
pub struct Corpus {
    version: String,
    created_at: String,
    manifest_sha256: String,
    sources: Vec<CorpusSource>,
    samples: Vec<CorpusSample>,
}

impl Corpus {
    /// Version declared by the verified manifest, such as `v1`.
    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Creation date declared by the verified manifest.
    #[must_use]
    pub fn created_at(&self) -> &str {
        &self.created_at
    }

    /// SHA-256 digest of the exact manifest bytes used for this load.
    #[must_use]
    pub fn manifest_sha256(&self) -> &str {
        &self.manifest_sha256
    }

    /// Provenance catalog declared by the verified manifest.
    #[must_use]
    pub fn sources(&self) -> &[CorpusSource] {
        &self.sources
    }

    /// Verified samples in manifest/file order.
    #[must_use]
    pub fn samples(&self) -> &[CorpusSample] {
        &self.samples
    }
}

/// Offline corpus loader. It only reads the supplied local directory.
#[derive(Debug, Clone)]
pub struct CorpusLoader {
    root: PathBuf,
}

impl CorpusLoader {
    /// Create a loader rooted at one release directory, for example `corpus/v1`.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Load and verify the manifest, JSONL files, sample counts and companion hashes.
    ///
    /// # Errors
    ///
    /// Returns an error for missing/unsafe files, invalid manifest or JSONL, resource-limit
    /// violations, duplicate IDs, or any checksum mismatch.
    pub fn load(&self) -> Result<Corpus, CorpusError> {
        reject_symlink_directory(&self.root)?;
        let manifest_path = self.root.join("manifest.json");
        let manifest_bytes = read_regular_file(&manifest_path, MAX_MANIFEST_BYTES)?;
        let manifest: Manifest = serde_json::from_slice(&manifest_bytes)
            .map_err(|error| CorpusError::InvalidManifest(error.to_string()))?;
        validate_manifest(&manifest)?;
        let source_ids = manifest
            .sources
            .iter()
            .map(|source| source.id.as_str())
            .collect::<HashSet<_>>();

        let mut samples = Vec::new();
        let mut sample_ids = HashSet::new();
        let mut total_bytes = 0_usize;
        for entry in manifest.files {
            validate_filename(&entry.file)?;
            let file_path = self.root.join(&entry.file);
            let bytes = read_regular_file(&file_path, MAX_FILE_BYTES)?;
            total_bytes = total_bytes
                .checked_add(bytes.len())
                .ok_or(CorpusError::ResourceLimit)?;
            if total_bytes > MAX_CORPUS_BYTES {
                return Err(CorpusError::ResourceLimit);
            }

            let checksum_path = self.root.join(format!("{}.sha256", entry.file));
            let checksum_bytes = read_regular_file(&checksum_path, 128)?;
            let expected = std::str::from_utf8(&checksum_bytes)
                .map_err(|_| CorpusError::InvalidChecksum)?
                .trim_end_matches(['\r', '\n']);
            if !is_lower_hex_sha256(expected) || sha256_hex(&bytes) != expected {
                return Err(CorpusError::ChecksumMismatch(entry.file));
            }

            let mut file_samples = Vec::with_capacity(entry.samples);
            for line in bytes.split(|byte| *byte == b'\n') {
                if line.is_empty() || line == b"\r" {
                    continue;
                }
                let sample: CorpusSample = serde_json::from_slice(line)
                    .map_err(|error| CorpusError::InvalidSample(error.to_string()))?;
                validate_sample(&sample)?;
                if !manifest.sources.is_empty()
                    && sample
                        .source_ref
                        .as_deref()
                        .is_none_or(|source| !source_ids.contains(source))
                {
                    return Err(CorpusError::UnknownSourceReference(sample.id));
                }
                if !sample_ids.insert(sample.id.clone()) {
                    return Err(CorpusError::DuplicateSampleId(sample.id));
                }
                file_samples.push(sample);
            }
            if file_samples.len() != entry.samples {
                return Err(CorpusError::SampleCountMismatch {
                    file: entry.file,
                    expected: entry.samples,
                    actual: file_samples.len(),
                });
            }
            samples.extend(file_samples);
            if samples.len() > MAX_SAMPLES {
                return Err(CorpusError::ResourceLimit);
            }
        }

        if samples.is_empty() {
            return Err(CorpusError::EmptyCorpus);
        }
        Ok(Corpus {
            version: manifest.corpus_version,
            created_at: manifest.created_at,
            manifest_sha256: sha256_hex(&manifest_bytes),
            sources: manifest.sources,
            samples,
        })
    }
}

/// Fail-closed corpus loading error.
#[derive(Debug, Error)]
pub enum CorpusError {
    /// A required corpus file could not be read.
    #[error("corpus file I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// Manifest bytes or fields are malformed or unsupported.
    #[error("invalid corpus manifest: {0}")]
    InvalidManifest(String),
    /// Manifest file entries must be simple local JSONL filenames.
    #[error("invalid corpus filename")]
    InvalidFilename,
    /// Companion checksum content is malformed.
    #[error("invalid .sha256 companion file")]
    InvalidChecksum,
    /// A JSONL entry is malformed or violates its schema.
    #[error("invalid JSONL sample: {0}")]
    InvalidSample(String),
    /// The content digest did not match its sidecar.
    #[error("SHA-256 mismatch for corpus file {0}")]
    ChecksumMismatch(String),
    /// Number of records differs from the manifest.
    #[error("sample count mismatch in {file}: expected {expected}, got {actual}")]
    SampleCountMismatch {
        /// Name of the JSONL file.
        file: String,
        /// Count declared by the manifest.
        expected: usize,
        /// Number of parsed samples.
        actual: usize,
    },
    /// A sample identifier is repeated across the release.
    #[error("duplicate corpus sample ID: {0}")]
    DuplicateSampleId(String),
    /// A sample references a source absent from its release manifest.
    #[error("sample has unknown or missing source reference: {0}")]
    UnknownSourceReference(String),
    /// Symlinks are not permitted in corpus roots or data files.
    #[error("symlinks are not allowed in a corpus release")]
    Symlink,
    /// File or corpus limits were exceeded.
    #[error("corpus resource limit exceeded")]
    ResourceLimit,
    /// A valid release must contain at least one sample.
    #[error("corpus release is empty")]
    EmptyCorpus,
}

fn validate_manifest(manifest: &Manifest) -> Result<(), CorpusError> {
    let valid_version = manifest
        .corpus_version
        .strip_prefix('v')
        .is_some_and(|number| {
            !number.is_empty() && number.bytes().all(|byte| byte.is_ascii_digit())
        });
    let date = manifest.created_at.as_bytes();
    let valid_date = date.len() == 10
        && date[4] == b'-'
        && date[7] == b'-'
        && date
            .iter()
            .enumerate()
            .all(|(index, byte)| index == 4 || index == 7 || byte.is_ascii_digit());
    if manifest.schema_version != 1
        || !valid_version
        || !valid_date
        || manifest.files.is_empty()
        || manifest.files.len() > MAX_FILES
    {
        return Err(CorpusError::InvalidManifest(
            "unsupported schema, version/date format, or file count".into(),
        ));
    }
    let mut source_ids = HashSet::new();
    for source in &manifest.sources {
        if source.id.is_empty()
            || source.id.len() > 64
            || source.location.is_empty()
            || source.location.len() > 512
            || source.license.is_empty()
            || source.use_note.is_empty()
            || !source_ids.insert(&source.id)
        {
            return Err(CorpusError::InvalidManifest(
                "invalid or duplicate source provenance entry".into(),
            ));
        }
    }
    let mut names = HashSet::new();
    let mut declared_samples = 0_usize;
    for entry in &manifest.files {
        validate_filename(&entry.file)?;
        if !names.insert(&entry.file) {
            return Err(CorpusError::InvalidManifest("duplicate file entry".into()));
        }
        declared_samples = declared_samples
            .checked_add(entry.samples)
            .ok_or(CorpusError::ResourceLimit)?;
        if entry.samples == 0 || declared_samples > MAX_SAMPLES {
            return Err(CorpusError::ResourceLimit);
        }
    }
    Ok(())
}

fn validate_filename(filename: &str) -> Result<(), CorpusError> {
    let stem = filename
        .strip_suffix(".jsonl")
        .ok_or(CorpusError::InvalidFilename)?;
    if stem.is_empty()
        || !stem
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(CorpusError::InvalidFilename);
    }
    Ok(())
}

fn validate_sample(sample: &CorpusSample) -> Result<(), CorpusError> {
    if sample.id.is_empty()
        || sample.id.len() > 128
        || !sample
            .id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        || sample.text.trim().is_empty()
        || sample.text.len() > MAX_SAMPLE_TEXT_BYTES
    {
        return Err(CorpusError::InvalidSample(
            "sample ID or text is empty/oversized/invalid".into(),
        ));
    }
    Ok(())
}

fn reject_symlink_directory(path: &Path) -> Result<(), CorpusError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(CorpusError::Symlink);
    }
    if !metadata.is_dir() {
        return Err(CorpusError::InvalidManifest(
            "corpus root is not a directory".into(),
        ));
    }
    Ok(())
}

fn read_regular_file(path: &Path, limit: usize) -> Result<Vec<u8>, CorpusError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(CorpusError::Symlink);
    }
    if !metadata.is_file() || metadata.len() > limit as u64 {
        return Err(CorpusError::ResourceLimit);
    }
    let contents = fs::read(path)?;
    if contents.len() > limit {
        return Err(CorpusError::ResourceLimit);
    }
    Ok(contents)
}

fn is_lower_hex_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        // Writing into a String is infallible.
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn fixture(root: &Path, file_bytes: &[u8], sidecar: Option<&str>) {
        fs::create_dir_all(root).unwrap();
        fs::write(
            root.join("manifest.json"),
            r#"{"schema_version":1,"corpus_version":"v1","created_at":"2026-10-19","files":[{"file":"general.jsonl","samples":1}]}"#,
        )
        .unwrap();
        fs::write(root.join("general.jsonl"), file_bytes).unwrap();
        if let Some(value) = sidecar {
            fs::write(root.join("general.jsonl.sha256"), value).unwrap();
        }
    }

    fn valid_record() -> &'static [u8] {
        b"{\"id\":\"general-001\",\"category\":\"general\",\"text\":\"A representative sample.\"}\n"
    }

    #[test]
    fn loads_local_version_and_reports_manifest_digest() {
        let temp = tempdir().unwrap();
        let bytes = valid_record();
        fixture(
            temp.path(),
            bytes,
            Some(&format!("{}\n", sha256_hex(bytes))),
        );
        let corpus = CorpusLoader::new(temp.path()).load().unwrap();
        assert_eq!(corpus.version(), "v1");
        assert_eq!(corpus.created_at(), "2026-10-19");
        assert_eq!(corpus.samples().len(), 1);
        assert_eq!(corpus.manifest_sha256().len(), 64);
    }

    #[test]
    fn checksum_mismatch_and_missing_sidecar_fail_closed() {
        let temp = tempdir().unwrap();
        fixture(
            temp.path(),
            valid_record(),
            Some(&format!("{}\n", "0".repeat(64))),
        );
        assert!(matches!(
            CorpusLoader::new(temp.path()).load(),
            Err(CorpusError::ChecksumMismatch(_))
        ));

        let missing = tempdir().unwrap();
        fixture(missing.path(), valid_record(), None);
        assert!(CorpusLoader::new(missing.path()).load().is_err());
    }

    #[test]
    fn rejects_traversal_and_mismatched_sample_count() {
        let temp = tempdir().unwrap();
        fixture(
            temp.path(),
            valid_record(),
            Some(&format!("{}\n", sha256_hex(valid_record()))),
        );
        let manifest_path = temp.path().join("manifest.json");
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
        value["files"][0]["file"] = serde_json::Value::String("../general.jsonl".into());
        fs::write(&manifest_path, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(matches!(
            CorpusLoader::new(temp.path()).load(),
            Err(CorpusError::InvalidFilename)
        ));

        value["files"][0]["file"] = serde_json::Value::String("general.jsonl".into());
        value["files"][0]["samples"] = serde_json::Value::from(2);
        fs::write(&manifest_path, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(matches!(
            CorpusLoader::new(temp.path()).load(),
            Err(CorpusError::SampleCountMismatch { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_corpus_files() {
        use std::os::unix::fs::symlink;
        let temp = tempdir().unwrap();
        let outside = temp.path().join("outside.jsonl");
        fs::write(&outside, valid_record()).unwrap();
        let root = temp.path().join("corpus");
        fs::create_dir(&root).unwrap();
        fs::write(
            root.join("manifest.json"),
            r#"{"schema_version":1,"corpus_version":"v1","created_at":"2026-10-19","files":[{"file":"general.jsonl","samples":1}]}"#,
        )
        .unwrap();
        symlink(outside, root.join("general.jsonl")).unwrap();
        assert!(matches!(
            CorpusLoader::new(root).load(),
            Err(CorpusError::Symlink)
        ));
    }
}
