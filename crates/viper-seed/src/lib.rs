//! Deterministic Tool Guard and fail-closed SEED composition.

/// Offline, integrity-checked semantic reference corpus loader.
pub mod corpus;
pub mod credential;
/// Local, integrity-pinned Candle embedding backend (opt-in feature).
#[cfg(feature = "candle-embeddings")]
pub mod embedding;
#[cfg(unix)]
pub mod ipc;
pub mod ipc_auth;
#[cfg(unix)]
pub mod ipc_v2;
pub mod policy;
/// Provider-side semantic geometry primitives.
pub mod semantic;

use regex::Regex;
use std::collections::BTreeMap;
use thiserror::Error;
use viper_core::{Decision, ToolName, ToolProposal, VerdictStatus};
use viper_trajectory::{ChainError, EventInput, EventKind, TrajectoryChain};

/// User-selectable sensitivity. Critical rules remain active at every level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardLevel {
    /// High-severity warnings become hard blocks.
    Strict,
    /// Apply configured actions.
    Balanced,
    /// Skip non-critical discretionary warnings.
    Off,
}

/// Tool Guard contribution to the composed decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardAction {
    /// Policy refuses the request.
    Block,
    /// Human authorization is required.
    Escalate,
    /// Tool Guard does not add a restriction.
    Allow,
}

impl GuardAction {
    const fn wire_name(self) -> &'static str {
        match self {
            Self::Block => "BLOCK",
            Self::Escalate => "ESCALATE",
            Self::Allow => "ALLOW",
        }
    }
}

/// Rule severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// Advisory risk.
    Medium,
    /// High-impact risk.
    High,
    /// Constitutional rule that cannot be disabled.
    Critical,
}

/// Result of ordered Tool Guard evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardVerdict {
    /// Required action.
    pub action: GuardAction,
    /// Stable ID of the first matching rule.
    pub rule_id: Option<String>,
    /// Stable rule category when a rule matched.
    pub category: Option<String>,
    /// Severity of the first matching rule.
    pub severity: Option<Severity>,
    /// Human-readable reason.
    pub reason: String,
    /// Version of the evaluated policy.
    pub policy_version: String,
    /// SHA-256 digest of the evaluated policy artifact.
    pub policy_digest: String,
}

#[derive(Debug, Clone)]
enum RuleMatcher {
    Regex(Regex),
    NetworkClientMissingTimeout,
}

impl RuleMatcher {
    fn is_match(&self, command: &str) -> bool {
        match self {
            Self::Regex(pattern) => pattern.is_match(command),
            Self::NetworkClientMissingTimeout => {
                let lower = command.to_ascii_lowercase();
                lower.split([';', '&', '|', '\n']).any(|segment| {
                    let has_client = segment
                        .split_whitespace()
                        .any(|token| matches!(token, "curl" | "wget"));
                    has_client
                        && (segment.contains("http://") || segment.contains("https://"))
                        && !segment.contains("--max-time")
                        && !segment.contains("--connect-timeout")
                })
            }
        }
    }
}

/// One compiled first-hit-wins rule.
#[derive(Debug, Clone)]
pub struct Rule {
    id: String,
    matcher: RuleMatcher,
    excludes: Vec<Regex>,
    severity: Severity,
    category: String,
    action: GuardAction,
    message: String,
}

impl Rule {
    /// Compiles a policy rule. Invalid regex is a startup error, never a skipped rule.
    ///
    /// # Errors
    ///
    /// Returns the regex parser error for the main expression or any exclusion.
    pub fn compile(
        pattern: &str,
        excludes: &[&str],
        severity: Severity,
        category: &str,
        action: GuardAction,
        message: &str,
    ) -> Result<Self, regex::Error> {
        Self::compile_with_id(
            "inline-rule",
            pattern,
            excludes,
            severity,
            category,
            action,
            message,
        )
    }

    pub(crate) fn compile_with_id(
        id: &str,
        pattern: &str,
        excludes: &[&str],
        severity: Severity,
        category: &str,
        action: GuardAction,
        message: &str,
    ) -> Result<Self, regex::Error> {
        Ok(Self {
            id: id.to_owned(),
            matcher: RuleMatcher::Regex(Regex::new(&format!("(?i:{pattern})"))?),
            excludes: excludes
                .iter()
                .map(|pattern| Regex::new(&format!("(?i:{pattern})")))
                .collect::<Result<_, _>>()?,
            severity,
            category: category.to_owned(),
            action,
            message: message.to_owned(),
        })
    }

    pub(crate) fn structured_timeout(
        id: &str,
        excludes: &[&str],
        severity: Severity,
        category: &str,
        action: GuardAction,
        message: &str,
    ) -> Result<Self, regex::Error> {
        Ok(Self {
            id: id.to_owned(),
            matcher: RuleMatcher::NetworkClientMissingTimeout,
            excludes: excludes
                .iter()
                .map(|pattern| Regex::new(&format!("(?i:{pattern})")))
                .collect::<Result<_, _>>()?,
            severity,
            category: category.to_owned(),
            action,
            message: message.to_owned(),
        })
    }
}

/// Ordered deterministic command policy.
#[derive(Debug, Clone)]
pub struct ToolGuard {
    level: GuardLevel,
    rules: Vec<Rule>,
    policy_version: String,
    policy_digest: String,
    private_address: Regex,
    raw_socket: Regex,
}

impl ToolGuard {
    /// Creates a guard from already validated ordered rules.
    ///
    /// # Errors
    ///
    /// Returns a regex parser error if an invariant built into the network policy is invalid.
    pub fn new(level: GuardLevel, rules: Vec<Rule>) -> Result<Self, regex::Error> {
        Self::from_compiled(
            level,
            rules,
            "inline/v1".into(),
            "0000000000000000000000000000000000000000000000000000000000000000".into(),
        )
    }

    pub(crate) fn from_compiled(
        level: GuardLevel,
        rules: Vec<Rule>,
        policy_version: String,
        policy_digest: String,
    ) -> Result<Self, regex::Error> {
        Ok(Self {
            level,
            rules,
            policy_version,
            policy_digest,
            private_address: Regex::new(
                r"(?i)https?://(?:localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|169\.254\.\d+\.\d+|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|\[::1\]|[^/\s]+\.(?:local|internal)\b)",
            )?,
            raw_socket: Regex::new(
                r#"(?i)(?:\bimport\s+socket\b|\bfrom\s+socket\s+import\b|\bsocket\.socket\s*\(|\brequire\s*\(\s*['\"](?:node:)?net['\"]\s*\)|\bnet\.connect\s*\()"#,
            )?,
        })
    }

    /// Compatibility baseline for the current v1.12 safety tests.
    ///
    /// # Errors
    ///
    /// Returns a regex parser error if any bundled compatibility rule is invalid.
    pub fn v1_compatibility_baseline(level: GuardLevel) -> Result<Self, regex::Error> {
        let specs = [
            (
                r"(?i)\brm\s+(?:-[a-z]+\s+)+(?:\.|\./|\*)(?:\s|$)",
                "destructive",
                "whole-project deletion",
            ),
            (
                r"(?i)\brm\s+[^\n]*(?:/|/\*|~|\$HOME)(?:\s|$)",
                "destructive",
                "root or home deletion",
            ),
            (
                r"(?i)\b(?:mkfs(?:\.\w+)?|dd\s+[^\n]*of=/dev/)",
                "destructive",
                "block-device mutation",
            ),
            (
                r"(?i)(?:^|[\s=;|&])(?:cat|less|more|head|tail|cp|scp|rsync|mv)\s+[^\n]*\.env(?:\s|$)",
                "sensitive_file_access",
                "secret file access",
            ),
            (
                r"(?i)(?:^|[\s;&|(])(?:sudo|doas|pkexec)(?:\s|$)",
                "privilege_escalation",
                "privilege escalation",
            ),
            (
                r"(?i)(?:curl|wget)\s+[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z|k)?sh\b",
                "code_execution",
                "download piped to shell",
            ),
        ];
        let rules = specs
            .into_iter()
            .map(|(pattern, category, message)| {
                Rule::compile(
                    pattern,
                    &[],
                    Severity::Critical,
                    category,
                    GuardAction::Block,
                    message,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        Self::new(level, rules)
    }

    /// Checks a command without granting execution authority.
    #[must_use]
    pub fn check_command(&self, command: &str, network: bool) -> GuardVerdict {
        if network && self.private_address.is_match(command) {
            return GuardVerdict {
                action: GuardAction::Block,
                rule_id: Some("TG-NETWORK-PRIVATE-ADDRESS".into()),
                category: Some("network_abuse".into()),
                severity: Some(Severity::Critical),
                reason: "private, local, link-local, or metadata target is denied".into(),
                policy_version: self.policy_version.clone(),
                policy_digest: self.policy_digest.clone(),
            };
        }
        if network && self.raw_socket.is_match(command) {
            return GuardVerdict {
                action: GuardAction::Block,
                rule_id: Some("TG-NETWORK-RAW-SOCKET".into()),
                category: Some("network_abuse".into()),
                severity: Some(Severity::Critical),
                reason: "raw sockets are denied in the network sandbox".into(),
                policy_version: self.policy_version.clone(),
                policy_digest: self.policy_digest.clone(),
            };
        }
        for rule in &self.rules {
            if rule
                .excludes
                .iter()
                .any(|exclude| exclude.is_match(command))
                || !rule.matcher.is_match(command)
            {
                continue;
            }
            if self.level == GuardLevel::Off && rule.severity != Severity::Critical {
                continue;
            }
            let strict_upgrade = self.level == GuardLevel::Strict
                && rule.severity == Severity::High
                && rule.action == GuardAction::Escalate;
            let action = if rule.severity == Severity::Critical || strict_upgrade {
                GuardAction::Block
            } else {
                rule.action
            };
            return GuardVerdict {
                action,
                rule_id: Some(rule.id.clone()),
                category: Some(rule.category.clone()),
                severity: Some(rule.severity),
                reason: rule.message.clone(),
                policy_version: self.policy_version.clone(),
                policy_digest: self.policy_digest.clone(),
            };
        }
        GuardVerdict {
            action: GuardAction::Allow,
            rule_id: None,
            category: None,
            severity: None,
            reason: "no Tool Guard rule matched".into(),
            policy_version: self.policy_version.clone(),
            policy_digest: self.policy_digest.clone(),
        }
    }

    /// Returns the number of ordered policy rules, excluding built-in network invariants.
    #[must_use]
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Returns the loaded policy version.
    #[must_use]
    pub fn policy_version(&self) -> &str {
        &self.policy_version
    }

    /// Returns the SHA-256 digest of the loaded policy artifact.
    #[must_use]
    pub fn policy_digest(&self) -> &str {
        &self.policy_digest
    }
}

/// External deterministic decider boundary.
pub trait SeedGate: Send + Sync {
    /// Evaluates one proposal. Transport or validation failure is distinct from a verdict.
    ///
    /// # Errors
    ///
    /// Returns a sanitized failure when SEED is unavailable or its response cannot be trusted.
    fn evaluate(
        &self,
        proposal: &ToolProposal,
        guard: &GuardVerdict,
    ) -> impl std::future::Future<Output = Result<Decision, SeedFailure>> + Send;
}

/// Failure communicating with or validating SEED.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
#[error("SEED unavailable or invalid: {message}")]
pub struct SeedFailure {
    /// Sanitized failure explanation.
    pub message: String,
}

/// Decision-pipeline failure before a final verdict can be safely recorded.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum PipelineError {
    /// Proposal validation failed.
    #[error("invalid proposal: {0}")]
    InvalidProposal(&'static str),
    /// Trajectory rejected an event.
    #[error(transparent)]
    Trajectory(#[from] ChainError),
}

/// Result of a decision plus its Tool Guard evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assessment {
    /// Final composed decision.
    pub decision: Decision,
    /// Independent Tool Guard result.
    pub guard: GuardVerdict,
}

/// Pure decision slice. It deliberately owns no executor.
pub struct DecisionPipeline<G> {
    guard: ToolGuard,
    seed: G,
    trajectory: TrajectoryChain,
}

impl<G: SeedGate> DecisionPipeline<G> {
    /// Creates a pipeline with an empty trajectory.
    pub fn new(guard: ToolGuard, seed: G) -> Self {
        Self {
            guard,
            seed,
            trajectory: TrajectoryChain::new(),
        }
    }

    /// Evaluates and records a proposal. SEED failure becomes a recorded VETO.
    ///
    /// # Errors
    ///
    /// Returns an error when proposal validation or mandatory trajectory recording fails.
    pub async fn assess(
        &mut self,
        proposal: &ToolProposal,
        decided_at: &str,
    ) -> Result<Assessment, PipelineError> {
        proposal
            .validate()
            .map_err(PipelineError::InvalidProposal)?;
        if decided_at.trim().is_empty() {
            return Err(PipelineError::InvalidProposal(
                "decision timestamp must not be empty",
            ));
        }
        let command = proposal.command().unwrap_or("");
        let network = proposal.tool == ToolName::NetworkRun;
        let guard = self.guard.check_command(command, network);

        self.trajectory.append(EventInput {
            id: format!("{}:proposed", proposal.id),
            trace_id: proposal.trace_id.clone(),
            occurred_at: proposal.requested_at.clone(),
            kind: EventKind::ToolProposed,
            detail: BTreeMap::from([
                ("actor".into(), proposal.actor.clone()),
                ("command".into(), command.to_owned()),
                ("tool".into(), proposal.tool.wire_name().to_owned()),
            ]),
        })?;

        let seed_result = self.seed.evaluate(proposal, &guard).await;
        let (seed_status, seed_reason, seed_source) = match seed_result {
            Ok(decision) if decision.proposal_id == proposal.id => {
                (decision.status, decision.reason, decision.source)
            }
            Ok(_) => (
                VerdictStatus::VetoDenied,
                "SEED returned a verdict for another proposal".into(),
                "seed_protocol_error".into(),
            ),
            Err(error) => (
                VerdictStatus::VetoDenied,
                error.to_string(),
                "seed_unavailable".into(),
            ),
        };

        let status = compose(guard.action, seed_status);
        let decision = Decision {
            proposal_id: proposal.id.clone(),
            status,
            source: "viper_policy_composer/v1".into(),
            reason: format!(
                "guard={:?} ({}); seed={seed_status:?} via {seed_source} ({seed_reason})",
                guard.action, guard.reason
            ),
        };
        self.trajectory.append(EventInput {
            id: format!("{}:verdict", proposal.id),
            trace_id: proposal.trace_id.clone(),
            occurred_at: decided_at.to_owned(),
            kind: EventKind::SeedVerdict,
            detail: BTreeMap::from([
                (
                    "final_status".into(),
                    decision.status.wire_name().to_owned(),
                ),
                ("guard_action".into(), guard.action.wire_name().to_owned()),
                (
                    "guard_category".into(),
                    guard.category.as_deref().unwrap_or("none").to_owned(),
                ),
                (
                    "guard_rule_id".into(),
                    guard.rule_id.as_deref().unwrap_or("none").to_owned(),
                ),
                ("tool_guard_digest".into(), guard.policy_digest.clone()),
                ("tool_guard_version".into(), guard.policy_version.clone()),
                ("reason".into(), decision.reason.clone()),
                ("seed_status".into(), seed_status.wire_name().to_owned()),
            ]),
        })?;
        Ok(Assessment { decision, guard })
    }

    /// Returns the append-only trajectory produced by assessments.
    #[must_use]
    pub const fn trajectory(&self) -> &TrajectoryChain {
        &self.trajectory
    }
}

const fn compose(guard: GuardAction, seed: VerdictStatus) -> VerdictStatus {
    if matches!(guard, GuardAction::Block) || matches!(seed, VerdictStatus::VetoDenied) {
        VerdictStatus::VetoDenied
    } else if matches!(guard, GuardAction::Escalate)
        || matches!(seed, VerdictStatus::EscalateParliament)
    {
        VerdictStatus::EscalateParliament
    } else {
        VerdictStatus::Approved
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FixedSeed(Result<VerdictStatus, SeedFailure>);

    impl SeedGate for FixedSeed {
        async fn evaluate(
            &self,
            proposal: &ToolProposal,
            _guard: &GuardVerdict,
        ) -> Result<Decision, SeedFailure> {
            self.0.clone().map(|status| Decision {
                proposal_id: proposal.id.clone(),
                status,
                source: "fixed-test-seed".into(),
                reason: "fixture".into(),
            })
        }
    }

    fn proposal(command: &str, network: bool) -> ToolProposal {
        ToolProposal {
            id: "proposal-1".into(),
            trace_id: "trace-1".into(),
            actor: "test-agent".into(),
            tool: if network {
                ToolName::NetworkRun
            } else {
                ToolName::TerminalRun
            },
            arguments: BTreeMap::from([("command".into(), command.into())]),
            requested_at: "2026-10-18T12:00:00Z".into(),
        }
    }

    const DECIDED_AT: &str = "2026-10-18T12:00:01Z";

    #[test]
    fn v1_destructive_and_secret_vectors_are_blocked() {
        let guard = ToolGuard::v1_compatibility_baseline(GuardLevel::Balanced).unwrap();
        for command in [
            "rm -rf .",
            "rm -r -f *",
            "rm  -rf /",
            "dd of=/dev/sda",
            "cat .env",
            "mkfs.ext4 /dev/sdb1",
        ] {
            assert_eq!(
                guard.check_command(command, false).action,
                GuardAction::Block,
                "{command}"
            );
        }
    }

    #[test]
    fn network_private_targets_and_raw_sockets_are_always_blocked() {
        let guard = ToolGuard::v1_compatibility_baseline(GuardLevel::Off).unwrap();
        assert_eq!(
            guard
                .check_command("curl https://169.254.169.254/latest", true)
                .action,
            GuardAction::Block
        );
        assert_eq!(
            guard
                .check_command("python3 -c 'import socket'", true)
                .action,
            GuardAction::Block
        );
        assert_eq!(
            guard
                .check_command("python3 -c 'import socket'", false)
                .action,
            GuardAction::Allow
        );
    }

    #[tokio::test]
    async fn seed_failure_is_a_recorded_veto() {
        let mut pipeline = DecisionPipeline::new(
            ToolGuard::v1_compatibility_baseline(GuardLevel::Balanced).unwrap(),
            FixedSeed(Err(SeedFailure {
                message: "timeout".into(),
            })),
        );
        let result = pipeline
            .assess(&proposal("cargo test", false), DECIDED_AT)
            .await
            .unwrap();
        assert_eq!(result.decision.status, VerdictStatus::VetoDenied);
        assert_eq!(pipeline.trajectory().events().len(), 2);
        TrajectoryChain::verify(pipeline.trajectory().events()).unwrap();
    }

    #[tokio::test]
    async fn veto_precedes_seed_approval() {
        let mut pipeline = DecisionPipeline::new(
            ToolGuard::v1_compatibility_baseline(GuardLevel::Balanced).unwrap(),
            FixedSeed(Ok(VerdictStatus::Approved)),
        );
        let result = pipeline
            .assess(&proposal("cat .env", false), DECIDED_AT)
            .await
            .unwrap();
        assert_eq!(result.decision.status, VerdictStatus::VetoDenied);
    }

    #[tokio::test]
    async fn both_layers_must_approve() {
        let mut pipeline = DecisionPipeline::new(
            ToolGuard::v1_compatibility_baseline(GuardLevel::Balanced).unwrap(),
            FixedSeed(Ok(VerdictStatus::Approved)),
        );
        let result = pipeline
            .assess(&proposal("cargo test", false), DECIDED_AT)
            .await
            .unwrap();
        assert_eq!(result.decision.status, VerdictStatus::Approved);
    }

    #[tokio::test]
    async fn guard_warning_escalates_even_when_seed_approves() {
        let rule = Rule::compile(
            r"(?i)\bcargo\s+publish\b",
            &[],
            Severity::High,
            "release",
            GuardAction::Escalate,
            "publishing requires a human",
        )
        .unwrap();
        let guard = ToolGuard::new(GuardLevel::Balanced, vec![rule]).unwrap();
        let mut pipeline = DecisionPipeline::new(guard, FixedSeed(Ok(VerdictStatus::Approved)));
        let result = pipeline
            .assess(&proposal("cargo publish", false), DECIDED_AT)
            .await
            .unwrap();
        assert_eq!(result.decision.status, VerdictStatus::EscalateParliament);
    }
}
