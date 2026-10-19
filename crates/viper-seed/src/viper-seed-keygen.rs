//! Root-only first-run provisioner for SEED IPC v2 Ed25519 credentials.

use clap::Parser;
use ed25519_dalek::SigningKey;
use std::fs::{self, File, OpenOptions, Permissions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

#[derive(Debug, Parser)]
#[command(about = "Provision a provider-only signing key and server public keyring")]
struct Args {
    /// Stable identifier for this key; use a new identifier for each rotation.
    #[arg(long)]
    key_id: String,
    /// Linux UID that will own and read the provider's private credential.
    #[arg(long)]
    provider_uid: u32,
    /// Linux GID that grants the provider traversal of the private credential directory.
    #[arg(long)]
    provider_gid: u32,
    /// Destination for the private credential record (mode 0400, provider-owned).
    #[arg(long)]
    private_output: PathBuf,
    /// Destination for the public keyring (mode 0644, root-owned).
    #[arg(long)]
    public_output: PathBuf,
}

fn main() {
    if let Err(error) = run(&Args::parse()) {
        eprintln!("viper-seed-keygen: {error}");
        std::process::exit(1);
    }
}

fn run(args: &Args) -> Result<(), &'static str> {
    if rustix::process::geteuid().as_raw() != 0 {
        return Err("must run as root to provision separate service identities");
    }
    if args.provider_uid == 0 || args.provider_gid == 0 {
        return Err("provider UID/GID must be dedicated non-root identities");
    }
    if !valid_key_id(&args.key_id) {
        return Err("key ID must be 1-64 ASCII letters, digits, '.', '_' or '-'");
    }
    if !args.private_output.is_absolute()
        || !args.public_output.is_absolute()
        || args.private_output == args.public_output
    {
        return Err("output paths must be distinct absolute paths");
    }

    validate_parent(&args.private_output, Some(args.provider_gid))?;
    validate_parent(&args.public_output, None)?;
    for path in [&args.private_output, &args.public_output] {
        if fs::symlink_metadata(path).is_ok() {
            return Err("refusing to overwrite an existing output or symlink");
        }
    }

    let mut seed = Zeroizing::new([0_u8; 32]);
    getrandom::fill(seed.as_mut()).map_err(|_| "operating-system key generation failed")?;
    if seed.iter().all(|byte| *byte == 0) {
        return Err("operating system returned invalid key material");
    }
    let signing_key = SigningKey::from_bytes(&seed);
    let seed_hex = Zeroizing::new(encode_hex(&seed[..]));
    let private_record = Zeroizing::new(format!(
        "VIPER_SEED_SIGNING_KEY_V2\n{}\n{}\n",
        args.key_id,
        seed_hex.as_str()
    ));
    let public_keyring = format!(
        "{{\n  \"schema\": \"VIPER_SEED_PUBLIC_KEYS_V2\",\n  \"active\": {{\n    \"key_id\": \"{}\",\n    \"public_key\": \"{}\"\n  }},\n  \"retiring\": []\n}}\n",
        args.key_id,
        encode_hex(signing_key.verifying_key().as_bytes())
    );

    let private_temp = temp_path(&args.private_output)?;
    let public_temp = temp_path(&args.public_output)?;
    let result = (|| {
        write_temp(&private_temp, private_record.as_bytes(), 0o600)?;
        rustix::fs::chown(
            &private_temp,
            Some(rustix::process::Uid::from_raw(args.provider_uid)),
            Some(rustix::process::Gid::from_raw(args.provider_gid)),
        )
        .map_err(|_| "cannot assign private credential to provider UID")?;
        fs::set_permissions(&private_temp, Permissions::from_mode(0o400))
            .map_err(|_| "cannot restrict private credential permissions")?;

        write_temp(&public_temp, public_keyring.as_bytes(), 0o600)?;
        fs::set_permissions(&public_temp, Permissions::from_mode(0o644))
            .map_err(|_| "cannot set public keyring permissions")?;

        publish_no_replace(&private_temp, &args.private_output)?;
        if let Err(error) = publish_no_replace(&public_temp, &args.public_output) {
            let _ = fs::remove_file(&args.private_output);
            return Err(error);
        }
        sync_parent(&args.private_output)?;
        if args.private_output.parent() != args.public_output.parent() {
            sync_parent(&args.public_output)?;
        }
        Ok(())
    })();
    let _ = fs::remove_file(&private_temp);
    let _ = fs::remove_file(&public_temp);
    result?;

    println!("Provisioned key ID: {}", args.key_id);
    println!(
        "Private credential: {} (provider UID {}, mode 0400)",
        args.private_output.display(),
        args.provider_uid
    );
    println!(
        "Public keyring: {} (root-owned, mode 0644)",
        args.public_output.display()
    );
    println!("No private key material was printed.");
    Ok(())
}

fn validate_parent(output: &Path, required_group: Option<u32>) -> Result<(), &'static str> {
    let parent = output.parent().ok_or("output has no parent directory")?;
    let metadata = fs::symlink_metadata(parent).map_err(|_| "output parent is unavailable")?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
        || metadata.mode() & 0o500 != 0o500
        || required_group
            .is_some_and(|group| metadata.gid() != group || metadata.mode() & 0o010 == 0)
    {
        return Err(
            "output parents must be secure; private parent must be traversable by provider GID",
        );
    }
    Ok(())
}

fn write_temp(path: &Path, bytes: &[u8], mode: u32) -> Result<(), &'static str> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
        .map_err(|_| "cannot create temporary output; refusing unsafe or conflicting path")?;
    file.write_all(bytes)
        .map_err(|_| "cannot write provisioned output")?;
    file.sync_all()
        .map_err(|_| "cannot sync provisioned output")?;
    Ok(())
}

fn publish_no_replace(source: &Path, destination: &Path) -> Result<(), &'static str> {
    fs::hard_link(source, destination).map_err(|_| "cannot publish output without overwriting")?;
    fs::remove_file(source).map_err(|_| "cannot finalize provisioned output")
}

fn sync_parent(output: &Path) -> Result<(), &'static str> {
    File::open(output.parent().ok_or("output has no parent directory")?)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| "cannot sync output directory")
}

fn temp_path(destination: &Path) -> Result<PathBuf, &'static str> {
    let parent = destination
        .parent()
        .ok_or("output has no parent directory")?;
    let name = destination
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("output filename must be valid UTF-8")?;
    for _ in 0..8 {
        let mut random = [0_u8; 8];
        getrandom::fill(&mut random).map_err(|_| "operating-system random source failed")?;
        let candidate = parent.join(format!(".{name}.{}.tmp", encode_hex(&random)));
        if fs::symlink_metadata(&candidate).is_err() {
            return Ok(candidate);
        }
    }
    Err("cannot allocate unique temporary output name")
}

fn valid_key_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_records_use_protocol_formats_and_matching_keypair() {
        let seed = [0x2a; 32];
        let key = SigningKey::from_bytes(&seed);
        let private = format!(
            "VIPER_SEED_SIGNING_KEY_V2\ntest-key\n{}\n",
            encode_hex(&seed)
        );
        let public = format!(
            "{{\"schema\":\"VIPER_SEED_PUBLIC_KEYS_V2\",\"active\":{{\"key_id\":\"test-key\",\"public_key\":\"{}\"}},\"retiring\":[]}}",
            encode_hex(key.verifying_key().as_bytes())
        );
        let loaded = viper_seed::ipc_v2::ProviderSigningKey::load(private.as_bytes()).unwrap();
        let parsed = viper_seed::ipc_v2::ProviderKeyring::from_json_at(&public, 100).unwrap();
        assert_eq!(
            loaded.public_key_hex(),
            encode_hex(key.verifying_key().as_bytes())
        );
        assert_eq!(parsed.active_key_id(), "test-key");
    }

    #[test]
    fn key_ids_are_restricted_to_safe_protocol_identifiers() {
        assert!(valid_key_id("provider-2026_10.a"));
        assert!(!valid_key_id("../private"));
        assert!(!valid_key_id(""));
        assert!(!valid_key_id(&"x".repeat(65)));
    }
}
