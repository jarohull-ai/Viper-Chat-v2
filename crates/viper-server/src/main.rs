//! Command-line entry point for the loopback-only Viper API.

use clap::{Parser, ValueEnum};
use rustix::process::geteuid;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;
use viper_db::{LedgerConfig, TrajectoryDb};
use viper_seed::GuardLevel;
use viper_seed::ipc_v2::{ProviderKeyring, SeedIpcV2Client, SeedIpcV2Config};
use viper_seed::policy::{load_embedded, load_file};
use viper_server::{ServerState, bind_loopback, router};

#[derive(Debug, Parser)]
#[command(version, about = "Loopback-only Viper decision and trajectory API")]
struct Args {
    /// HTTP port on IPv4 loopback. Port 0 asks the OS for an ephemeral port.
    #[arg(long, default_value_t = 3000)]
    port: u16,

    /// `SQLite` trajectory database path.
    #[arg(long)]
    db: PathBuf,

    /// Private runtime directory containing the SEED Unix socket.
    #[arg(long)]
    seed_runtime_dir: PathBuf,

    /// SEED Unix socket path, directly inside --seed-runtime-dir.
    #[arg(long)]
    seed_socket: PathBuf,

    /// Expected provider's distinct Linux UID.
    #[arg(long)]
    seed_provider_uid: u32,

    /// Trusted, administrator-provisioned Ed25519 public-key bundle for the SEED provider.
    #[arg(long)]
    seed_provider_keyring: PathBuf,

    /// Allow same-UID IPC for local development only; never use in production.
    #[arg(long, default_value_t = false)]
    allow_same_uid_development: bool,

    /// Optional versioned Tool Guard policy YAML. Uses the embedded policy when omitted.
    #[arg(long)]
    policy: Option<PathBuf>,

    /// Tool Guard sensitivity level.
    #[arg(long, value_enum, default_value_t = GuardLevelArg::Balanced)]
    guard_level: GuardLevelArg,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum GuardLevelArg {
    Strict,
    Balanced,
    Off,
}

impl From<GuardLevelArg> for GuardLevel {
    fn from(value: GuardLevelArg) -> Self {
        match value {
            GuardLevelArg::Strict => Self::Strict,
            GuardLevelArg::Balanced => Self::Balanced,
            GuardLevelArg::Off => Self::Off,
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    match run(Args::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("viper-server: {message}");
            ExitCode::FAILURE
        }
    }
}

async fn run(args: Args) -> Result<(), &'static str> {
    if args.seed_provider_uid == geteuid().as_raw() && !args.allow_same_uid_development {
        return Err("server and provider must use distinct UIDs");
    }
    let keyring = ProviderKeyring::load_file(&args.seed_provider_keyring)
        .map_err(|_| "invalid SEED provider public-key bundle")?;
    let seed_config = SeedIpcV2Config {
        runtime_dir: args.seed_runtime_dir,
        socket_path: args.seed_socket,
        expected_provider_uid: args.seed_provider_uid,
        connect_timeout: Duration::from_millis(250),
        response_timeout: Duration::from_secs(1),
    };
    let seed = SeedIpcV2Client::new(seed_config, keyring)
        .map_err(|_| "invalid SEED IPC v2 configuration")?;

    let level = args.guard_level.into();
    let guard = match args.policy {
        Some(path) => load_file(&path, level).map_err(|_| "could not load Tool Guard policy")?,
        None => load_embedded(level).map_err(|_| "could not load embedded Tool Guard policy")?,
    };
    let database = Arc::new(
        TrajectoryDb::open(&args.db, LedgerConfig::default())
            .await
            .map_err(|_| "could not open trajectory database")?,
    );
    database
        .verify()
        .await
        .map_err(|_| "trajectory database verification failed")?;

    let listener = bind_loopback(args.port)
        .await
        .map_err(|_| "could not bind HTTP listener on IPv4 loopback")?;
    let address = listener
        .local_addr()
        .map_err(|_| "could not inspect HTTP listener")?;
    eprintln!("viper-server listening on {address}");

    let state = ServerState::new(database, guard, seed);
    axum::serve(listener, router(state))
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(|_| "HTTP server stopped unexpectedly")
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}
