//! Command-line entry point for the loopback-only Viper API.

use clap::{Parser, ValueEnum};
use std::fs::File;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;
use viper_db::{LedgerConfig, TrajectoryDb};
use viper_seed::GuardLevel;
use viper_seed::credential::load_keyring;
use viper_seed::ipc::{SeedIpcClient, SeedIpcConfig};
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

    /// Inherited descriptor for the strict `VIPER_SEED_KEY_V1` credential record (must be >= 3).
    #[arg(long)]
    seed_credential_fd: u32,

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
    if args.seed_credential_fd < 3 {
        return Err("credential descriptor must be >= 3");
    }

    let credential = File::open(format!("/proc/self/fd/{}", args.seed_credential_fd))
        .map_err(|_| "could not open inherited credential descriptor")?;
    let keyring = load_keyring(credential).map_err(|_| "invalid SEED credential record")?;
    let seed_config = SeedIpcConfig {
        runtime_dir: args.seed_runtime_dir,
        socket_path: args.seed_socket,
        connect_timeout: Duration::from_millis(250),
        response_timeout: Duration::from_secs(1),
    };
    let seed =
        SeedIpcClient::new(seed_config, keyring).map_err(|_| "invalid SEED IPC configuration")?;

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
