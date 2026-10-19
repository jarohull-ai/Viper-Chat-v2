//! Provider-neutral domain contracts for Viper Chat.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A closed set of built-in tool families with an explicit extension point.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolName {
    /// Offline command execution.
    TerminalRun,
    /// Explicitly network-enabled command execution.
    NetworkRun,
    /// A browser interaction.
    BrowserAction,
    /// Guarded outbound e-mail.
    EmailSendGuarded,
    /// A future tool whose identifier remains visible to policy.
    Custom(String),
}

impl ToolName {
    /// Stable value used by audit and transport protocols.
    #[must_use]
    pub fn wire_name(&self) -> &str {
        match self {
            Self::TerminalRun => "terminal_run",
            Self::NetworkRun => "network_run",
            Self::BrowserAction => "browser_action",
            Self::EmailSendGuarded => "email_send_guarded",
            Self::Custom(name) => name,
        }
    }
}

/// An immutable request for a side effect. It grants no authority by itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolProposal {
    /// Stable identifier used to bind decisions and future approvals.
    pub id: String,
    /// Trace to which audit records belong.
    pub trace_id: String,
    /// Identity of the proposing agent or user.
    pub actor: String,
    /// Requested tool.
    pub tool: ToolName,
    /// Deterministically ordered, untrusted arguments.
    pub arguments: BTreeMap<String, String>,
    /// RFC 3339 timestamp supplied by the trusted orchestrator clock.
    pub requested_at: String,
}

impl ToolProposal {
    /// Validates the required identity and timestamp fields before the proposal crosses a trust
    /// boundary.
    ///
    /// # Errors
    ///
    /// Returns a stable message naming the first empty required field.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.id.trim().is_empty() {
            return Err("proposal id must not be empty");
        }
        if self.trace_id.trim().is_empty() {
            return Err("trace id must not be empty");
        }
        if self.actor.trim().is_empty() {
            return Err("actor must not be empty");
        }
        if self.requested_at.trim().is_empty() {
            return Err("requested_at must not be empty");
        }
        Ok(())
    }

    /// Returns the command argument for command tools.
    #[must_use]
    pub fn command(&self) -> Option<&str> {
        self.arguments.get("command").map(String::as_str)
    }
}

/// Final status produced by deterministic policy composition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VerdictStatus {
    /// The proposal may advance to the next boundary.
    Approved,
    /// The proposal is refused.
    VetoDenied,
    /// The proposal waits for explicit human authorization.
    EscalateParliament,
}

impl VerdictStatus {
    /// Stable value used by audit and transport protocols.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Approved => "APPROVED",
            Self::VetoDenied => "VETO_DENIED",
            Self::EscalateParliament => "ESCALATE_PARLIAMENT",
        }
    }
}

/// A decision bound to exactly one proposal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decision {
    /// Proposal identifier.
    pub proposal_id: String,
    /// Composed status.
    pub status: VerdictStatus,
    /// Stable source identifier.
    pub source: String,
    /// Sanitizable explanation for operators and audit.
    pub reason: String,
}
