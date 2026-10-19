//! Dedicated fail-closed SEED IPC v2 provider process.

use clap::{Parser, ValueEnum};
use std::fs::{self, File, Permissions};
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::net::UnixListener;
use viper_core::{Decision, ToolName, ToolProposal, VerdictStatus};
use viper_seed::ipc_v2::{ProviderSigningKey, SeedIpcV2Provider};
use viper_seed::policy;
use viper_seed::{GuardAction, GuardLevel, GuardVerdict, SeedFailure, SeedGate, ToolGuard};

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliGuardLevel {
    Strict,
    Balanced,
    Off,
}

impl From<CliGuardLevel> for GuardLevel {
    fn from(value: CliGuardLevel) -> Self {
        match value {
            CliGuardLevel::Strict => Self::Strict,
            CliGuardLevel::Balanced => Self::Balanced,
            CliGuardLevel::Off => Self::Off,
        }
    }
}

#[derive(Debug, Parser)]
#[command(about = "Fail-closed Ed25519 SEED IPC v2 provider")]
struct Args {
    /// Provider-owned runtime directory shared only with the designated IPC group.
    #[arg(long)]
    runtime_dir: PathBuf,
    /// Unix socket path directly inside --runtime-dir.
    #[arg(long)]
    socket: PathBuf,
    /// Expected viper-server UID; production requires a distinct UID.
    #[arg(long)]
    client_uid: u32,
    /// Inherited credential descriptor containing the strict Ed25519 key record.
    #[arg(long, default_value_t = 0)]
    credential_fd: u32,
    /// Optional validated Tool Guard policy file; defaults to the embedded frozen policy.
    #[arg(long)]
    policy: Option<PathBuf>,
    /// Tool Guard sensitivity level.
    #[arg(long, value_enum, default_value_t = CliGuardLevel::Balanced)]
    guard_level: CliGuardLevel,
    /// Permit same-UID operation for local development only.
    #[arg(long)]
    allow_same_uid_development: bool,
}

struct PolicySeedGate {
    guard: ToolGuard,
}

impl SeedGate for PolicySeedGate {
    async fn evaluate(
        &self,
        proposal: &ToolProposal,
        remote_guard: &GuardVerdict,
    ) -> Result<Decision, SeedFailure> {
        let expected = self.guard.check_command(
            proposal.command().unwrap_or(""),
            proposal.tool == ToolName::NetworkRun,
        );
        if expected.action != remote_guard.action
            || expected.rule_id != remote_guard.rule_id
            || expected.policy_version != remote_guard.policy_version
            || expected.policy_digest != remote_guard.policy_digest
        {
            return Err(SeedFailure {
                message: "client Tool Guard evidence does not match provider policy".into(),
            });
        }
        let status = match expected.action {
            GuardAction::Allow => VerdictStatus::Approved,
            GuardAction::Block => VerdictStatus::VetoDenied,
            GuardAction::Escalate => VerdictStatus::EscalateParliament,
        };
        Ok(Decision {
            proposal_id: proposal.id.clone(),
            status,
            source: "viper-seed-provider/policy-v1".into(),
            reason: expected.reason,
        })
    }
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("viper-seed-provider: {error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), &'static str> {
    let args = Args::parse();
    validate_paths(&args.runtime_dir, &args.socket)?;
    let provider_uid = rustix::process::geteuid().as_raw();
    if provider_uid == args.client_uid && !args.allow_same_uid_development {
        return Err("provider and client must run under distinct UIDs");
    }

    let key = ProviderSigningKey::load(open_credential(args.credential_fd)?)
        .map_err(|_| "provider signing credential is invalid or unavailable")?;
    let level = GuardLevel::from(args.guard_level);
    let guard = match args.policy.as_deref() {
        Some(path) => policy::load_file(path, level)
            .map_err(|_| "configured Tool Guard policy failed validation")?,
        None => policy::load_embedded(level)
            .map_err(|_| "embedded Tool Guard policy failed validation")?,
    };

    let listener = UnixListener::bind(&args.socket)
        .map_err(|_| "cannot bind SEED socket; stale paths are never removed automatically")?;
    let runtime = fs::symlink_metadata(&args.runtime_dir)
        .map_err(|_| "provider runtime directory is unavailable")?;
    rustix::fs::chown(
        &args.socket,
        Some(rustix::process::geteuid()),
        Some(rustix::process::Gid::from_raw(runtime.gid())),
    )
    .map_err(|_| "cannot assign socket to the configured IPC group")?;
    fs::set_permissions(&args.socket, Permissions::from_mode(0o660))
        .map_err(|_| "cannot set restrictive SEED socket permissions")?;

    let provider = SeedIpcV2Provider::new(
        args.client_uid,
        Duration::from_secs(5),
        key,
        PolicySeedGate { guard },
    );
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|_| "cannot register provider termination signal")?;
    eprintln!("viper-seed-provider: ready; policy and IPC v2 loaded");
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            _ = terminate.recv() => break,
            result = provider.serve_one(&listener) => {
                if let Err(error) = result {
                    eprintln!("viper-seed-provider: rejected or failed IPC exchange ({error})");
                }
            }
        }
    }
    drop(listener);
    fs::remove_file(&args.socket)
        .map_err(|_| "cannot remove provider-owned socket during shutdown")?;
    Ok(())
}

fn validate_paths(runtime_dir: &Path, socket: &Path) -> Result<(), &'static str> {
    if !runtime_dir.is_absolute() || !socket.is_absolute() || socket.parent() != Some(runtime_dir) {
        return Err("runtime directory and socket must be absolute, with socket directly inside");
    }
    let runtime = fs::symlink_metadata(runtime_dir)
        .map_err(|_| "provider runtime directory is unavailable")?;
    if !runtime.file_type().is_dir()
        || runtime.uid() != rustix::process::geteuid().as_raw()
        || runtime.mode() & 0o022 != 0
        || runtime.mode() & 0o050 != 0o050
    {
        return Err("provider runtime directory ownership or permissions are unsafe");
    }
    if fs::symlink_metadata(socket).is_ok() {
        return Err("SEED socket path already exists; stale paths are never removed automatically");
    }
    Ok(())
}

fn open_credential(fd: u32) -> Result<Box<dyn Read>, &'static str> {
    if fd == 0 {
        return Ok(Box::new(io::stdin()));
    }
    File::open(format!("/proc/self/fd/{fd}"))
        .map(|file| Box::new(file) as Box<dyn Read>)
        .map_err(|_| "inherited credential descriptor is unavailable")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn proposal(command: &str) -> ToolProposal {
        ToolProposal {
            id: "provider-test-proposal".into(),
            trace_id: "provider-test-trace".into(),
            actor: "provider-test".into(),
            tool: ToolName::TerminalRun,
            arguments: BTreeMap::from([("command".into(), command.into())]),
            requested_at: "2026-10-19T00:00:00Z".into(),
        }
    }

    fn evidence_for(guard: &ToolGuard, proposal: &ToolProposal) -> GuardVerdict {
        guard.check_command(proposal.command().unwrap_or(""), false)
    }

    #[tokio::test]
    async fn provider_approves_only_matching_local_policy_evidence() {
        let guard = policy::load_embedded(GuardLevel::Balanced).unwrap();
        let gate = PolicySeedGate { guard };
        let proposal = proposal("echo safe");
        let evidence = evidence_for(&gate.guard, &proposal);
        let decision = gate.evaluate(&proposal, &evidence).await.unwrap();
        assert_eq!(decision.status, VerdictStatus::Approved);

        let mut tampered = evidence;
        tampered.policy_digest = "f".repeat(64);
        assert!(gate.evaluate(&proposal, &tampered).await.is_err());
    }

    #[tokio::test]
    async fn provider_vetoes_policy_blocks_and_escalates_warnings() {
        let guard = policy::load_embedded(GuardLevel::Balanced).unwrap();
        let gate = PolicySeedGate { guard };
        let blocked = proposal("rm -rf /");
        let decision = gate
            .evaluate(&blocked, &evidence_for(&gate.guard, &blocked))
            .await
            .unwrap();
        assert_eq!(decision.status, VerdictStatus::VetoDenied);

        let warning = proposal("pkill -f worker");
        let decision = gate
            .evaluate(&warning, &evidence_for(&gate.guard, &warning))
            .await
            .unwrap();
        assert_eq!(decision.status, VerdictStatus::EscalateParliament);
    }
}
