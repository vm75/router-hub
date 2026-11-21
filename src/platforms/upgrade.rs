//! Router-only, command-line Entware upgrades. No HTTP route exposes this operation.
use std::{
    io::Write,
    os::unix::process::CommandExt,
    path::{Path, PathBuf},
    process::Command as ProcessCommand,
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

use crate::{
    backup,
    config::{AppConfig, Platform},
};

const RELEASE_API: &str = "https://api.github.com/repos/vm75/router-hub/releases/latest";
const RELEASE_BASE: &str = "https://github.com/vm75/router-hub/releases/download";
const ARCH: &str = "aarch64-3.10";
const OPKG: &str = "/opt/bin/opkg";
const MAX_IPK_BYTES: u64 = 64 * 1024 * 1024;
const MAX_CHECKSUM_BYTES: u64 = 1024;

#[derive(Debug, Deserialize)]
struct Release {
    tag_name: String,
    assets: Vec<Asset>,
}

#[derive(Debug, Deserialize)]
struct Asset {
    name: String,
}

pub fn require_router(platform: Platform, test_mode: bool) -> Result<()> {
    ensure!(
        platform == Platform::Asuswrt && !test_mode,
        "upgrade is available only on a live Asuswrt-Merlin router, not Linux or test mode"
    );
    Ok(())
}

fn stable_version(tag: &str) -> Option<[u64; 3]> {
    let mut parts = tag.strip_prefix('v')?.split('.');
    let mut numbers = [0u64; 3];
    for number in &mut numbers {
        let part = parts.next()?;
        if part.is_empty()
            || (part.len() > 1 && part.starts_with('0'))
            || !part.bytes().all(|byte| byte.is_ascii_digit())
        {
            return None;
        }
        *number = part.parse().ok()?;
    }
    if parts.next().is_some() {
        return None;
    }
    Some(numbers)
}

fn ipk_name(tag: &str) -> Result<String> {
    ensure!(
        stable_version(tag).is_some(),
        "invalid stable release tag: {tag}"
    );
    Ok(format!("maestro_{}-1_{ARCH}.ipk", &tag[1..]))
}

fn checksum_digest(contents: &str, filename: &str) -> Result<String> {
    let mut lines = contents.lines();
    let line = lines.next().context("empty IPK checksum")?;
    ensure!(lines.next().is_none(), "unexpected multiple checksum lines");
    let mut parts = line.split_whitespace();
    let digest = parts.next().context("missing SHA-256 digest")?;
    let file = parts.next().context("missing IPK checksum filename")?;
    ensure!(parts.next().is_none(), "unexpected checksum fields");
    ensure!(
        digest.len() == 64 && digest.bytes().all(|c| c.is_ascii_hexdigit()),
        "invalid SHA-256 digest"
    );
    ensure!(
        file.trim_start_matches('*') == filename,
        "checksum filename mismatch"
    );
    Ok(digest.to_ascii_lowercase())
}

async fn request_bytes(client: &reqwest::Client, url: &str, limit: u64) -> Result<Vec<u8>> {
    let mut response = client.get(url).send().await?.error_for_status()?;
    if let Some(length) = response.content_length() {
        ensure!(
            length <= limit,
            "download is larger than the permitted limit"
        );
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        ensure!(
            bytes.len() as u64 + chunk.len() as u64 <= limit,
            "download exceeded the permitted limit"
        );
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

fn check_opkg_architecture() -> Result<bool> {
    if !Path::new(OPKG).is_file() {
        return Ok(false);
    }
    let output = ProcessCommand::new(OPKG)
        .arg("print-architecture")
        .output()
        .context("unable to inspect Entware architectures")?;
    ensure!(output.status.success(), "opkg print-architecture failed");
    let printed = String::from_utf8(output.stdout)?;
    ensure!(
        printed.lines().any(|line| {
            let mut fields = line.split_whitespace();
            fields.next() == Some("arch") && fields.next() == Some(ARCH)
        }),
        "this Entware installation does not support {ARCH}; refusing to install an incompatible IPK"
    );
    Ok(true)
}

pub async fn run(
    config: &AppConfig,
    config_path: &Path,
    download_only: bool,
    no_backup: bool,
) -> Result<()> {
    // The runtime guard is also enforced by the CLI before starting this operation.
    let opkg_available = check_opkg_architecture()?;
    let client = reqwest::Client::builder()
        .user_agent(concat!("maestro/", env!("CARGO_PKG_VERSION")))
        .timeout(Duration::from_secs(120))
        .build()?;
    let release: Release = client
        .get(RELEASE_API)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await
        .context("unable to read GitHub's latest stable release")?;
    let latest = stable_version(&release.tag_name)
        .context("latest GitHub release does not have a stable vMAJOR.MINOR.PATCH tag")?;
    let current = stable_version(concat!("v", env!("CARGO_PKG_VERSION")))
        .context("invalid compiled Maestro version")?;
    if latest <= current {
        println!(
            "Maestro {} is up to date (latest stable: {}).",
            env!("CARGO_PKG_VERSION"),
            release.tag_name
        );
        return Ok(());
    }

    let name = ipk_name(&release.tag_name)?;
    let checksum_name = format!("{name}.sha256");
    for asset in [&name, &checksum_name] {
        ensure!(
            release.assets.iter().any(|entry| entry.name == *asset),
            "release {} does not contain {}; no upgrade was attempted",
            release.tag_name,
            asset
        );
    }
    let base = format!("{RELEASE_BASE}/{}/", release.tag_name);
    let checksum_url = format!("{base}{checksum_name}");
    let expected_bytes = request_bytes(&client, &checksum_url, MAX_CHECKSUM_BYTES)
        .await
        .context("unable to download release checksum")?;
    let checksum = String::from_utf8(expected_bytes).context("non-UTF-8 checksum file")?;
    let expected = checksum_digest(&checksum, &name)?;

    // Stage under a random name; only publish the final filename after hash validation.
    let target = PathBuf::from("/tmp").join(&name);
    let temporary = PathBuf::from("/tmp").join(format!(".{name}.{}.part", Uuid::new_v4()));
    let result: Result<()> = async {
        let mut file = tokio::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)
            .await
            .context("unable to create temporary IPK file")?;
        let mut response = client
            .get(format!("{base}{name}"))
            .send()
            .await?
            .error_for_status()?;
        if let Some(size) = response.content_length() {
            ensure!(size <= MAX_IPK_BYTES, "IPK exceeds 64 MiB limit");
        }
        let mut digest = Sha256::new();
        let mut downloaded = 0u64;
        while let Some(chunk) = response.chunk().await? {
            downloaded += chunk.len() as u64;
            ensure!(downloaded <= MAX_IPK_BYTES, "IPK exceeds 64 MiB limit");
            digest.update(&chunk);
            file.write_all(&chunk).await?;
        }
        ensure!(downloaded > 0, "downloaded IPK is empty");
        file.flush().await?;
        file.sync_all().await?;
        drop(file);
        ensure!(
            format!("{:x}", digest.finalize()) == expected,
            "SHA-256 mismatch: refusing to install the downloaded IPK"
        );
        tokio::fs::rename(&temporary, &target).await?;
        Ok(())
    }
    .await;
    if result.is_err() {
        let _ = tokio::fs::remove_file(&temporary).await;
    }
    result?;
    println!(
        "Verified {} and saved it to {}",
        release.tag_name,
        target.display()
    );

    prepare_backup(config, config_path, no_backup).await?;

    let command = format!("{OPKG} install {}", target.display());
    if download_only || !opkg_available || unsafe { libc::geteuid() } != 0 {
        println!("To install, run as root: {command}");
        return Ok(());
    }

    // The prerm hook stops all processes named maestro. Replace this CLI
    // process with opkg so it cannot kill the process performing the upgrade.
    println!("Installing {} through Entware...", release.tag_name);
    println!("If installation fails, the verified IPK remains in /tmp. Retry: {command}");
    std::io::stdout().flush()?;
    let error = ProcessCommand::new(OPKG).arg("install").arg(&target).exec();
    bail!("unable to launch opkg ({error}). Run manually: {command}")
}

async fn prepare_backup(config: &AppConfig, config_path: &Path, no_backup: bool) -> Result<()> {
    if !no_backup {
        backup::run(config, config_path, None).await.context(
            "pre-upgrade backup failed; no installation was attempted (use --no-backup to skip)",
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn upgrade_backs_up_by_default_and_skip_bypasses_backup_failures() {
        let temp = tempfile::tempdir().unwrap();
        let directory = temp.path().join("config");
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("maestro.toml");
        let mut config = AppConfig::default();
        config.apply_test_mode(&path).unwrap();
        config.test_mode = false;
        config.platform = Platform::Linux;
        // Missing configuration must block upgrading unless explicitly skipped.
        let error = prepare_backup(&config, &path, false).await.unwrap_err();
        assert!(error.to_string().contains("no installation was attempted"));
        prepare_backup(&config, &path, true).await.unwrap();
        assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 0);

        std::fs::write(&path, "configuration").unwrap();
        prepare_backup(&config, &path, true).await.unwrap();
        assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 1);
        prepare_backup(&config, &path, false).await.unwrap();
        assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 2);
    }

    #[test]
    fn stable_tags_and_version_ordering() {
        assert_eq!(stable_version("v0.10.2"), Some([0, 10, 2]));
        assert!(stable_version("v0.10.12") > stable_version("v0.10.2"));
        for invalid in ["v0.10.2-rc.1", "0.10.2", "v1.02.3", "v0.10", "v1.2.3/evil"] {
            assert_eq!(stable_version(invalid), None, "{invalid}");
        }
        assert_eq!(
            ipk_name("v0.10.2").unwrap(),
            "maestro_0.10.2-1_aarch64-3.10.ipk"
        );
    }

    #[test]
    fn checksum_validation() {
        let hex = "a".repeat(64);
        let name = "maestro_0.10.2-1_aarch64-3.10.ipk";
        assert_eq!(
            checksum_digest(&format!("{hex}  {name}\n"), name).unwrap(),
            hex
        );
        assert!(checksum_digest(&format!("{hex}  other.ipk\n"), name).is_err());
        assert!(checksum_digest("bad  other.ipk\n", name).is_err());
        assert!(checksum_digest(&format!("{hex}  {name}\nextra\n"), name).is_err());
    }

    #[test]
    fn only_live_router_can_upgrade() {
        assert!(require_router(Platform::Asuswrt, false).is_ok());
        assert!(require_router(Platform::Asuswrt, true).is_err());
        assert!(require_router(Platform::Linux, false).is_err());
    }
}
