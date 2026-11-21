//! Router-only, command-line Entware NGINX upgrades from GitHub Releases.
//! No HTTP route exposes this operation.

use std::{
    collections::HashMap,
    ffi::CString,
    fs,
    io::Read,
    os::{
        fd::AsRawFd,
        unix::{
            ffi::OsStrExt,
            fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, symlink},
        },
    },
    path::{Path, PathBuf},
    process::{Command as ProcessCommand, Output},
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail, ensure};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::{io::AsyncWriteExt, process::Command as AsyncCommand, time::timeout};
use uuid::Uuid;

use crate::{
    backup,
    config::{AppConfig, Platform},
};

pub const RELEASES_API: &str = "https://api.github.com/repos/vm75/router-hub/releases?per_page=100";
const MAX_RELEASE_PAGES: usize = 10;
const OPKG_TIMEOUT: Duration = Duration::from_secs(300);
const RELOAD_TIMEOUT: Duration = Duration::from_secs(20);
const MIN_FREE_HEADROOM_BYTES: u64 = 16 * 1024 * 1024;
const MODULES_DIR: &str = "/opt/lib/nginx/modules";
const MODULE_CONFIG_DIR: &str = "/opt/etc/nginx/module.d";
const MODULE_FILES: [&str; 4] = [
    "ngx_http_brotli_filter_module.so",
    "ngx_http_brotli_static_module.so",
    "ngx_stream_module.so",
    "ngx_http_headers_more_filter_module.so",
];
pub const TAG_API_BASE: &str = "https://api.github.com/repos/vm75/router-hub/releases/tags";
pub const RELEASE_BASE: &str = "https://github.com/vm75/router-hub/releases/download";
pub const ARCH: &str = "aarch64-3.10";
pub const OPKG: &str = "/opt/bin/opkg";
pub const MAX_IPK_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_CHECKSUM_BYTES: u64 = 64 * 1024;

pub const REQUIRED_PACKAGES: [&str; 4] = [
    "nginx-ssl",
    "nginx-mod-brotli",
    "nginx-mod-stream",
    "nginx-mod-headers-more",
];

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Default,
    clap::ValueEnum,
    serde::Serialize,
    serde::Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum NginxChannel {
    #[default]
    Stable,
    Mainline,
}

impl std::fmt::Display for NginxChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Stable => write!(f, "stable"),
            Self::Mainline => write!(f, "mainline"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct UpgradeNginxOptions {
    pub channel: NginxChannel,
    pub tag: Option<String>,
    pub version: Option<String>,
    pub download_only: bool,
    pub no_backup: bool,
    pub force: bool,
    pub check: bool,
    pub allow_downgrade: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Release {
    pub tag_name: String,
    #[serde(default)]
    pub draft: bool,
    #[serde(default)]
    pub prerelease: bool,
    #[serde(default)]
    pub assets: Vec<Asset>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Asset {
    pub name: String,
    #[serde(default)]
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NginxTagInfo {
    pub tag: String,
    pub version: [u64; 3],
    pub version_str: String,
    pub run_id: Option<u64>,
    pub attempt: Option<u64>,
    pub channel: NginxChannel,
}

impl Ord for NginxTagInfo {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.version
            .cmp(&other.version)
            .then_with(|| self.run_id.cmp(&other.run_id))
            .then_with(|| self.attempt.cmp(&other.attempt))
    }
}

impl PartialOrd for NginxTagInfo {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

pub fn require_router(platform: Platform, test_mode: bool) -> Result<()> {
    ensure!(
        platform == Platform::Asuswrt && !test_mode,
        "upgrade-nginx is available only on a live Asuswrt-Merlin router, not Linux or test mode"
    );
    Ok(())
}

pub fn parse_version_numbers(version_str: &str) -> Option<[u64; 3]> {
    let mut parts = version_str.split('.');
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

pub fn channel_for_version(version: [u64; 3]) -> NginxChannel {
    if version[1] % 2 == 0 {
        NginxChannel::Stable
    } else {
        NginxChannel::Mainline
    }
}

pub fn parse_nginx_tag(tag: &str) -> Option<NginxTagInfo> {
    let remainder = tag.strip_prefix("nginx-v")?;
    let mut parts = remainder.split('-');
    let version_part = parts.next()?;
    let version = parse_version_numbers(version_part)?;
    let channel = channel_for_version(version);

    // Refuse unknown suffixes and path characters; the tag becomes part of a
    // staging directory and release URL, so its format must be unambiguous.
    let (run_id, attempt) = match (parts.next(), parts.next(), parts.next()) {
        (None, None, None) => (None, None),
        (Some(run), Some(attempt), None) => {
            let run = run.strip_prefix("run")?;
            let attempt = attempt.strip_prefix('a')?;
            if run.is_empty() || attempt.is_empty() {
                return None;
            }
            (Some(run.parse().ok()?), Some(attempt.parse().ok()?))
        }
        _ => return None,
    };

    Some(NginxTagInfo {
        tag: tag.to_string(),
        version,
        version_str: version_part.to_string(),
        run_id,
        attempt,
        channel,
    })
}

pub fn parse_installed_nginx_version(output: &str) -> Option<[u64; 3]> {
    for line in output.lines() {
        let lower = line.to_ascii_lowercase();
        if let Some(pos) = lower.find("nginx/") {
            let ver_part = &line[pos + "nginx/".len()..];
            let token = ver_part
                .split(|c: char| c.is_whitespace() || c == '(' || c == '/' || c == '-')
                .next()?;
            if let Some(numbers) = parse_version_numbers(token) {
                return Some(numbers);
            }
        }
    }
    None
}

pub fn parse_checksums(content: &str) -> Result<HashMap<String, String>> {
    let mut map = HashMap::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split_whitespace();
        let digest = parts.next().context("missing digest in checksum line")?;
        let file = parts.next().context("missing filename in checksum line")?;
        ensure!(
            parts.next().is_none(),
            "unexpected extra fields in checksum line: {line}"
        );
        ensure!(
            digest.len() == 64 && digest.bytes().all(|c| c.is_ascii_hexdigit()),
            "invalid SHA-256 digest: {digest}"
        );
        let filename = file.trim_start_matches('*');
        map.insert(filename.to_string(), digest.to_ascii_lowercase());
    }
    Ok(map)
}

pub fn find_package_asset<'a>(
    assets: &'a [Asset],
    pkg_name: &str,
    version_str: &str,
    arch: &str,
) -> Result<&'a Asset> {
    let prefix = format!("{pkg_name}_{version_str}-");
    let suffix = format!("_{arch}.ipk");
    let matches: Vec<&'a Asset> = assets
        .iter()
        .filter(|a| a.name.starts_with(&prefix) && a.name.ends_with(&suffix))
        .collect();
    ensure!(
        !matches.is_empty(),
        "missing required asset for {pkg_name} (version {version_str}, arch {arch})"
    );
    ensure!(
        matches.len() == 1,
        "multiple matching assets found for {pkg_name}: {:?}",
        matches.iter().map(|a| &a.name).collect::<Vec<_>>()
    );
    Ok(matches[0])
}

pub fn find_required_assets<'a>(
    assets: &'a [Asset],
    version_str: &str,
    arch: &str,
) -> Result<Vec<&'a Asset>> {
    let mut result = Vec::new();
    for pkg in REQUIRED_PACKAGES {
        result.push(find_package_asset(assets, pkg, version_str, arch)?);
    }
    Ok(result)
}

pub fn select_release_from_list<'a>(
    releases: &'a [Release],
    target_version: Option<&str>,
    channel: NginxChannel,
) -> Result<(&'a Release, NginxTagInfo)> {
    let mut candidates = Vec::new();
    for release in releases {
        if release.draft || release.prerelease {
            continue;
        }
        let Some(info) = parse_nginx_tag(&release.tag_name) else {
            continue;
        };
        if let Some(ver) = target_version {
            let req_ver =
                parse_version_numbers(ver).context("invalid --version argument: expected X.Y.Z")?;
            if info.version != req_ver {
                continue;
            }
        } else if info.channel != channel {
            continue;
        }
        candidates.push((release, info));
    }

    if candidates.is_empty() {
        if let Some(ver) = target_version {
            bail!("no NGINX release found matching version {ver}");
        } else {
            bail!("no {channel} NGINX releases found on GitHub");
        }
    }

    candidates.sort_by(|a, b| a.1.cmp(&b.1));
    Ok(candidates.pop().unwrap())
}

pub fn check_opkg_architecture() -> Result<bool> {
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

pub fn get_installed_nginx_version(nginx_bin: &Path) -> Option<[u64; 3]> {
    if !nginx_bin.is_file() {
        return None;
    }
    let output = ProcessCommand::new(nginx_bin).arg("-v").output().ok()?;
    let text = if !output.stderr.is_empty() {
        String::from_utf8_lossy(&output.stderr)
    } else {
        String::from_utf8_lossy(&output.stdout)
    };
    parse_installed_nginx_version(&text)
}

pub fn test_nginx_config(
    nginx_bin: &Path,
    config_path: &Path,
    prefix_path: Option<&Path>,
) -> Result<()> {
    if !nginx_bin.is_file() {
        return Ok(());
    }
    let mut cmd = ProcessCommand::new(nginx_bin);
    if let Some(prefix) = prefix_path {
        cmd.arg("-p").arg(prefix);
    }
    cmd.arg("-t").arg("-c").arg(config_path);
    let output = cmd
        .output()
        .context("failed to invoke nginx configuration test")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        bail!("nginx configuration test failed:\n{}{}", stdout, stderr);
    }
    Ok(())
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

async fn download_and_verify_asset(
    client: &reqwest::Client,
    base_url: &str,
    asset_name: &str,
    expected_checksum: &str,
    dest_path: &Path,
    max_bytes: u64,
) -> Result<()> {
    let url = format!("{base_url}/{asset_name}");
    let mut response = client.get(&url).send().await?.error_for_status()?;
    if let Some(length) = response.content_length() {
        ensure!(
            length <= max_bytes,
            "asset {asset_name} size ({length} bytes) exceeds limit ({max_bytes} bytes)"
        );
    }
    let mut file = tokio::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(dest_path)
        .await
        .context(format!("unable to create temporary file for {asset_name}"))?;
    let mut hasher = Sha256::new();
    let mut downloaded = 0u64;
    while let Some(chunk) = response.chunk().await? {
        downloaded += chunk.len() as u64;
        ensure!(
            downloaded <= max_bytes,
            "asset {asset_name} exceeded limit ({max_bytes} bytes)"
        );
        hasher.update(&chunk);
        file.write_all(&chunk).await?;
    }
    ensure!(downloaded > 0, "downloaded asset {asset_name} is empty");
    file.flush().await?;
    file.sync_all().await?;
    drop(file);
    let actual_checksum = format!("{:x}", hasher.finalize());
    ensure!(
        actual_checksum == expected_checksum,
        "checksum mismatch for {asset_name}: expected {expected_checksum}, got {actual_checksum}"
    );
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpgradeDisposition {
    Current,
    Newer,
    Rebuild,
    Downgrade,
}

pub fn disposition(
    installed: Option<[u64; 3]>,
    requested: [u64; 3],
    installed_files_match: bool,
) -> UpgradeDisposition {
    if installed_files_match {
        return UpgradeDisposition::Current;
    }
    match installed {
        Some(current) if requested < current => UpgradeDisposition::Downgrade,
        Some(current) if requested == current => UpgradeDisposition::Rebuild,
        _ => UpgradeDisposition::Newer,
    }
}

fn sha256_file(path: &Path) -> Result<Option<String>> {
    let mut file = match fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).with_context(|| format!("reading {}", path.display())),
    };
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 32 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(Some(format!("{:x}", hasher.finalize())))
}

pub fn installed_matches_release(
    nginx_bin: &Path,
    checksum_map: &HashMap<String, String>,
    modules_dir: &Path,
) -> Result<bool> {
    let binary_and_modules = std::iter::once((nginx_bin.to_path_buf(), "nginx".to_string())).chain(
        MODULE_FILES
            .iter()
            .map(|name| (modules_dir.join(name), (*name).to_string())),
    );
    for (path, name) in binary_and_modules {
        let expected = checksum_map
            .get(&name)
            .with_context(|| format!("release checksum missing for {name}"))?;
        if sha256_file(&path)?.as_deref() != Some(expected.as_str()) {
            return Ok(false);
        }
    }
    Ok(true)
}

async fn list_nginx_releases(client: &reqwest::Client) -> Result<Vec<Release>> {
    let mut releases = Vec::new();
    for page in 1..=MAX_RELEASE_PAGES {
        let page_releases: Vec<Release> = client
            .get(format!("{RELEASES_API}&page={page}"))
            .send()
            .await?
            .error_for_status()
            .context("unable to query GitHub releases (check internet access and rate limits)")?
            .json()
            .await
            .context("unable to decode GitHub releases")?;
        let count = page_releases.len();
        releases.extend(page_releases);
        if count < 100 {
            return Ok(releases);
        }
    }
    bail!(
        "GitHub release discovery exceeded {MAX_RELEASE_PAGES} pages; specify --tag to select an exact release"
    )
}

fn validate_asset_name(name: &str) -> Result<()> {
    ensure!(
        !name.is_empty()
            && name
                .bytes()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, b'.' | b'-' | b'_'))
            && !name.contains(".."),
        "unsafe release asset filename: {name}"
    );
    Ok(())
}

fn available_bytes(path: &Path) -> Result<u64> {
    let path_c = CString::new(path.as_os_str().as_bytes())?;
    let mut data = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    let rc = unsafe { libc::statvfs(path_c.as_ptr(), data.as_mut_ptr()) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error()).context("cannot inspect free /tmp space");
    }
    let data = unsafe { data.assume_init() };
    Ok(data.f_bavail.saturating_mul(data.f_frsize))
}

fn ensure_free_space(path: &Path, required: u64) -> Result<()> {
    let free = available_bytes(path)?;
    ensure!(
        free >= required.saturating_add(MIN_FREE_HEADROOM_BYTES),
        "insufficient free space in {}: {} MiB available; {} MiB needed plus 16 MiB headroom",
        path.display(),
        free / 1_048_576,
        required / 1_048_576
    );
    Ok(())
}

/// flock prevents stale lockfiles from blocking retries after a crash.
struct UpgradeLock(fs::File);

impl Drop for UpgradeLock {
    fn drop(&mut self) {
        let _ = unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
    }
}

impl UpgradeLock {
    fn acquire() -> Result<Self> {
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open("/tmp/.maestro-nginx-upgrade.lock")
            .context("unable to open NGINX upgrade lock")?;
        ensure!(
            unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
            "another NGINX upgrade is already running"
        );
        Ok(Self(file))
    }
}

fn create_private_directory(path: &Path) -> Result<()> {
    fs::DirBuilder::new()
        .mode(0o700)
        .create(path)
        .with_context(|| format!("unable to create {}", path.display()))
}

fn copy_node(source: &Path, destination: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(source)?;
    if metadata.file_type().is_symlink() {
        symlink(fs::read_link(source)?, destination)?;
    } else if metadata.is_dir() {
        fs::create_dir(destination)?;
        for entry in fs::read_dir(source)? {
            let entry = entry?;
            copy_node(&entry.path(), &destination.join(entry.file_name()))?;
        }
        fs::set_permissions(destination, metadata.permissions())?;
    } else if metadata.is_file() {
        fs::copy(source, destination)?;
        fs::set_permissions(destination, metadata.permissions())?;
    } else {
        bail!("cannot snapshot special file: {}", source.display());
    }
    Ok(())
}

fn remove_node(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() => fs::remove_dir_all(path)?,
        Ok(_) => fs::remove_file(path)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

struct RollbackSnapshot {
    directory: PathBuf,
    original_paths: Vec<(PathBuf, bool)>,
}

impl RollbackSnapshot {
    fn capture(paths: &[PathBuf], temp_root: &Path) -> Result<Self> {
        let directory = temp_root.join(format!(".nginx-rollback-{}", Uuid::new_v4()));
        create_private_directory(&directory)?;
        let mut original_paths = Vec::new();
        for original in paths {
            ensure!(original.is_absolute(), "rollback path must be absolute");
            let relative = original.strip_prefix("/")?;
            let saved_path = directory.join(relative);
            let exists = match fs::symlink_metadata(original) {
                Ok(_) => true,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
                Err(error) => return Err(error.into()),
            };
            if exists {
                fs::create_dir_all(saved_path.parent().context("missing snapshot parent")?)?;
                copy_node(original, &saved_path)
                    .with_context(|| format!("cannot snapshot {}", original.display()))?;
            }
            original_paths.push((original.clone(), exists));
        }
        Ok(Self {
            directory,
            original_paths,
        })
    }

    fn restore(&self) -> Result<()> {
        for (original, existed) in &self.original_paths {
            remove_node(original)?;
            if *existed {
                fs::create_dir_all(original.parent().context("missing restore parent")?)?;
                let saved_path = self.directory.join(original.strip_prefix("/")?);
                copy_node(&saved_path, original)
                    .with_context(|| format!("cannot restore {}", original.display()))?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NginxMasterIdentity {
    pid: i32,
    start_ticks: u64,
    exe_device: u64,
    exe_inode: u64,
}

/// Field 22 of /proc/<pid>/stat is the process start time in clock ticks.
/// Parse after the closing parenthesis: the comm field may contain spaces.
fn parse_proc_start_ticks(stat: &str) -> Option<u64> {
    let (_, fields) = stat.rsplit_once(") ")?;
    let mut fields = fields.split_whitespace();
    let state = fields.next()?;
    if matches!(state, "Z" | "X" | "x") {
        return None;
    }
    fields
        .nth(18)?
        .parse::<u64>()
        .ok()
        .filter(|ticks| *ticks > 0)
}

fn is_nginx_master_title(cmdline: &[u8]) -> bool {
    let title = cmdline.split(|byte| *byte == 0).next().unwrap_or(&[]);
    title == b"nginx: master process" || title.starts_with(b"nginx: master process ")
}

/// Read the identity from procfs, independently of the PID file. Comparing
/// start ticks and executable inode prevents a reused PID from passing a
/// second check, even if another NGINX master later receives the same PID.
fn nginx_master_identity_at(
    proc_root: &Path,
    pid: i32,
    nginx_binary: &Path,
) -> Result<NginxMasterIdentity> {
    ensure!(pid > 1, "invalid NGINX master PID {pid}");
    let process = proc_root.join(pid.to_string());
    let comm = fs::read_to_string(process.join("comm"))
        .with_context(|| format!("cannot inspect process {pid} name"))?;
    ensure!(comm.trim() == "nginx", "PID {pid} is not an NGINX process");

    let cmdline = fs::read(process.join("cmdline"))
        .with_context(|| format!("cannot inspect process {pid} command line"))?;
    ensure!(
        is_nginx_master_title(&cmdline),
        "PID {pid} is not an NGINX master process"
    );

    let stat = fs::read_to_string(process.join("stat"))
        .with_context(|| format!("cannot inspect process {pid} start time"))?;
    let start_ticks = parse_proc_start_ticks(&stat)
        .with_context(|| format!("PID {pid} has invalid or exited process state"))?;

    // The old executable may be unlinked by opkg and appear with a
    // " (deleted)" suffix. Its path must still match this configured NGINX.
    let running_exe = fs::read_link(process.join("exe"))
        .with_context(|| format!("cannot inspect process {pid} executable"))?;
    let running_exe = running_exe.to_string_lossy();
    let running_exe = running_exe
        .strip_suffix(" (deleted)")
        .unwrap_or(&running_exe);
    let expected_exe = fs::canonicalize(nginx_binary)
        .with_context(|| format!("cannot resolve {}", nginx_binary.display()))?;
    ensure!(
        Path::new(running_exe) == expected_exe.as_path(),
        "PID {pid} executable is not the configured NGINX binary ({})",
        nginx_binary.display()
    );
    let executable = fs::metadata(process.join("exe"))
        .with_context(|| format!("cannot stat process {pid} executable"))?;
    Ok(NginxMasterIdentity {
        pid,
        start_ticks,
        exe_device: executable.dev(),
        exe_inode: executable.ino(),
    })
}

fn nginx_master_identity(pid: i32, nginx_binary: &Path) -> Result<NginxMasterIdentity> {
    nginx_master_identity_at(Path::new("/proc"), pid, nginx_binary)
}

/// nginx -t creates an empty PID file when stopped. Accept that only when
/// procfs confirms no NGINX process exists; malformed nonempty files still fail.
/// Never use an unverified PID to signal a process.
fn nginx_master_from_pid_file_at(
    pid_path: &Path,
    nginx_binary: &Path,
    proc_root: &Path,
) -> Result<Option<NginxMasterIdentity>> {
    let contents = match fs::read_to_string(pid_path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("cannot read NGINX PID file"),
    };
    if contents.trim().is_empty() {
        for entry in
            fs::read_dir(proc_root).context("cannot inspect processes for empty NGINX PID file")?
        {
            let entry = entry.context("cannot inspect process directory")?;
            if entry.file_name().to_string_lossy().parse::<u32>().is_err() {
                continue;
            }
            let comm = match fs::read_to_string(entry.path().join("comm")) {
                Ok(comm) => comm,
                // Processes can exit during enumeration.
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error).context("cannot inspect process name"),
            };
            ensure!(
                comm.trim() != "nginx",
                "NGINX PID file is empty but an NGINX process exists; refusing to assume it is stopped"
            );
        }
        return Ok(None);
    }
    let pid = contents
        .trim()
        .parse::<i32>()
        .context("invalid NGINX PID file contents")?;
    Ok(Some(nginx_master_identity_at(
        proc_root,
        pid,
        nginx_binary,
    )?))
}

fn nginx_master_from_pid_file(
    pid_path: &Path,
    nginx_binary: &Path,
) -> Result<Option<NginxMasterIdentity>> {
    nginx_master_from_pid_file_at(pid_path, nginx_binary, Path::new("/proc"))
}

fn signal_nginx_master(
    expected: NginxMasterIdentity,
    nginx_binary: &Path,
    signal: i32,
) -> Result<()> {
    let current = nginx_master_identity(expected.pid, nginx_binary)
        .context("NGINX master identity could not be revalidated before signal")?;
    ensure!(
        current == expected,
        "NGINX master PID {} changed identity; refusing to signal a reused PID",
        expected.pid
    );
    // There is no pidfd_send_signal on older Asuswrt kernels. The procfs
    // identity check immediately precedes kill to minimize the remaining race.
    ensure!(
        unsafe { libc::kill(expected.pid, signal) } == 0,
        "cannot signal verified NGINX master {}: {}",
        expected.pid,
        std::io::Error::last_os_error()
    );
    Ok(())
}

fn process_uses_binary(pid: i32, binary: &Path) -> Result<bool> {
    let executable = fs::metadata(format!("/proc/{pid}/exe"))?;
    let installed = fs::metadata(binary)?;
    Ok(executable.dev() == installed.dev() && executable.ino() == installed.ino())
}

async fn wait_for_new_master(
    config: &AppConfig,
    old_master: NginxMasterIdentity,
) -> Result<NginxMasterIdentity> {
    for _ in 0..100 {
        // A partial PID file during master startup is transient; never signal
        // it. Only a fully verified new master can advance this operation.
        if let Ok(Some(candidate)) =
            nginx_master_from_pid_file(&config.nginx.pid_path, &config.commands.nginx)
        {
            if candidate.pid != old_master.pid
                && process_uses_binary(candidate.pid, &config.commands.nginx).unwrap_or(false)
            {
                tokio::time::sleep(Duration::from_secs(1)).await;
                ensure!(
                    nginx_master_identity(candidate.pid, &config.commands.nginx)? == candidate,
                    "new NGINX master identity changed during verification"
                );
                return Ok(candidate);
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    bail!("NGINX did not publish a verified new master PID after SIGUSR2 (20s timeout)")
}

async fn bounded_command(
    mut command: AsyncCommand,
    duration: Duration,
    description: &str,
) -> Result<Output> {
    command.kill_on_drop(true);
    timeout(duration, command.output())
        .await
        .with_context(|| {
            format!(
                "{description} timed out after {} seconds",
                duration.as_secs()
            )
        })?
        .with_context(|| format!("unable to execute {description}"))
}

async fn reload_nginx(config: &AppConfig) -> Result<()> {
    let expected = nginx_master_from_pid_file(&config.nginx.pid_path, &config.commands.nginx)?
        .context("no verified NGINX master is running for reload")?;
    let mut command = AsyncCommand::new(&config.commands.nginx);
    if let Some(prefix) = &config.nginx.prefix_path {
        command.arg("-p").arg(prefix);
    }
    command
        .arg("-s")
        .arg("reload")
        .arg("-c")
        .arg(&config.nginx.config_path);
    let output = bounded_command(command, RELOAD_TIMEOUT, "nginx reload").await?;
    ensure!(
        output.status.success(),
        "nginx reload failed: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    ensure!(
        nginx_master_from_pid_file(&config.nginx.pid_path, &config.commands.nginx)?
            == Some(expected),
        "NGINX master identity changed after reload"
    );
    Ok(())
}

async fn recover_failure(
    config: &AppConfig,
    snapshot: &RollbackSnapshot,
    failure: anyhow::Error,
    was_running: bool,
) -> anyhow::Error {
    eprintln!("NGINX upgrade failed: {failure:#}");
    eprintln!("Restoring previous binary, module files and module load directives...");
    if let Err(restore_error) = snapshot.restore() {
        eprintln!("WARNING: automatic file rollback failed: {restore_error:#}");
        eprintln!("Manual recovery snapshot: {}", snapshot.directory.display());
        return failure.context(format!("rollback also failed: {restore_error:#}"));
    }
    if let Err(test_error) = test_nginx_config(
        &config.commands.nginx,
        &config.nginx.config_path,
        config.nginx.prefix_path.as_deref(),
    ) {
        eprintln!("WARNING: restored NGINX did not pass configuration test: {test_error:#}");
        return failure.context(format!(
            "restored NGINX failed syntax validation: {test_error:#}"
        ));
    }
    if was_running {
        // reload_nginx refuses to target a stale, reused or non-master PID.
        if let Err(reload_error) = reload_nginx(config).await {
            eprintln!("WARNING: restored NGINX could not be reloaded: {reload_error:#}");
            return failure.context(format!("restored NGINX reload failed: {reload_error:#}"));
        }
    }
    eprintln!(
        "Previous NGINX files restored; opkg package records may still describe the new version."
    );
    eprintln!(
        "Keep the recovery files at {} until the system is repaired.",
        snapshot.directory.display()
    );
    failure
}

pub async fn run(
    config: &AppConfig,
    config_path: &Path,
    options: UpgradeNginxOptions,
) -> Result<()> {
    ensure!(
        options.tag.is_none() || options.version.is_none(),
        "--tag and --version are mutually exclusive"
    );
    let _lock = if options.check {
        None
    } else {
        Some(UpgradeLock::acquire()?)
    };
    let opkg_available = check_opkg_architecture()?;
    let client = reqwest::Client::builder()
        .user_agent(concat!("maestro/", env!("CARGO_PKG_VERSION")))
        .timeout(Duration::from_secs(120))
        .build()?;

    let (release, tag_info) = if let Some(tag) = &options.tag {
        ensure!(parse_nginx_tag(tag).is_some(), "invalid NGINX release tag");
        let url = format!("{TAG_API_BASE}/{tag}");
        let rel: Release = client
            .get(&url)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await
            .context("unable to deserialize GitHub release")?;
        ensure!(
            rel.tag_name == *tag,
            "release tag does not match requested tag"
        );
        ensure!(
            !rel.draft && !rel.prerelease,
            "release is draft or prerelease"
        );
        let info = parse_nginx_tag(&rel.tag_name).context("invalid NGINX release tag")?;
        (rel, info)
    } else {
        let releases = list_nginx_releases(&client).await?;
        let (selected, info) =
            select_release_from_list(&releases, options.version.as_deref(), options.channel)?;
        (selected.clone(), info)
    };

    let matched_assets = find_required_assets(&release.assets, &tag_info.version_str, ARCH)?;
    ensure!(
        release.assets.iter().any(|a| a.name == "SHA256SUMS"),
        "release {} lacks SHA256SUMS",
        tag_info.tag
    );
    let mut expected_size = 0u64;
    for asset in &matched_assets {
        validate_asset_name(&asset.name)?;
        ensure!(
            asset.size > 0 && asset.size <= MAX_IPK_BYTES,
            "invalid or oversized release asset {}",
            asset.name
        );
        expected_size = expected_size.saturating_add(asset.size);
    }

    let base_url = format!("{RELEASE_BASE}/{}", tag_info.tag);
    let checksum_bytes = request_bytes(
        &client,
        &format!("{base_url}/SHA256SUMS"),
        MAX_CHECKSUM_BYTES,
    )
    .await
    .context("unable to download release checksums")?;
    let checksum_map = parse_checksums(&String::from_utf8(checksum_bytes)?)?;
    for asset in &matched_assets {
        ensure!(
            checksum_map.contains_key(&asset.name),
            "SHA256SUMS lacks checksum for required asset {}",
            asset.name
        );
    }

    let installed = get_installed_nginx_version(&config.commands.nginx);
    let installed_files_match = installed_matches_release(
        &config.commands.nginx,
        &checksum_map,
        Path::new(MODULES_DIR),
    )?;
    let action = disposition(installed, tag_info.version, installed_files_match);

    if options.check {
        println!(
            "Installed NGINX: {}",
            installed.map_or_else(
                || "not detected".to_string(),
                |v| format!("{}.{}.{}", v[0], v[1], v[2])
            )
        );
        match action {
            UpgradeDisposition::Current => println!(
                "Installed binary and modules match release {}.",
                tag_info.tag
            ),
            UpgradeDisposition::Downgrade => println!(
                "Selected release {} is older; installation requires --allow-downgrade.",
                tag_info.tag
            ),
            UpgradeDisposition::Rebuild => println!(
                "Different NGINX build available at the same version: {}.",
                tag_info.tag
            ),
            UpgradeDisposition::Newer => println!(
                "NGINX release available: {} ({}).",
                tag_info.tag, tag_info.channel
            ),
        }
        return Ok(());
    }
    if action == UpgradeDisposition::Current && !options.force && !options.download_only {
        println!(
            "NGINX binary and modules already match {}. Use --force to reinstall.",
            tag_info.tag
        );
        return Ok(());
    }
    if action == UpgradeDisposition::Downgrade && !options.allow_downgrade && !options.download_only
    {
        bail!(
            "selected NGINX {} is older than installed version; use --allow-downgrade to proceed",
            tag_info.version_str
        );
    }

    // Verify configuration syntax before staging, backing up or modifying packages.
    test_nginx_config(
        &config.commands.nginx,
        &config.nginx.config_path,
        config.nginx.prefix_path.as_deref(),
    )
    .context("existing NGINX configuration test failed")?;

    ensure_free_space(Path::new("/tmp"), expected_size)?;
    let staging_dir = PathBuf::from("/tmp").join(format!(".nginx-upgrade-{}", Uuid::new_v4()));
    create_private_directory(&staging_dir)?;
    let download_result: Result<()> = async {
        for asset in &matched_assets {
            download_and_verify_asset(
                &client,
                &base_url,
                &asset.name,
                &checksum_map[&asset.name],
                &staging_dir.join(&asset.name),
                MAX_IPK_BYTES,
            )
            .await?;
        }
        Ok(())
    }
    .await;
    if let Err(error) = download_result {
        let _ = fs::remove_dir_all(&staging_dir);
        return Err(error);
    }

    // Use a unique verified directory: never erase a previous staged bundle.
    let final_dir =
        PathBuf::from("/tmp").join(format!("nginx-{}-{}", tag_info.tag, Uuid::new_v4()));
    fs::rename(&staging_dir, &final_dir).context("unable to publish verified NGINX packages")?;
    println!(
        "Verified NGINX {} ({}) packages: {}",
        tag_info.version_str,
        tag_info.channel,
        final_dir.display()
    );

    let package_paths: Vec<PathBuf> = matched_assets
        .iter()
        .map(|asset| final_dir.join(&asset.name))
        .collect();
    let reinstall = options.force || action == UpgradeDisposition::Rebuild;
    let mut opkg_options = Vec::new();
    if reinstall {
        opkg_options.push("--force-reinstall");
    }
    if action == UpgradeDisposition::Downgrade {
        opkg_options.push("--force-downgrade");
    }
    let manual_cmd = format!(
        "{OPKG} {}install {}",
        if opkg_options.is_empty() {
            String::new()
        } else {
            format!("{} ", opkg_options.join(" "))
        },
        package_paths
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(" ")
    );

    // Download-only still makes a backup, like maestro upgrade.
    if !options.no_backup {
        backup::run(config, config_path, None)
            .await
            .context("pre-upgrade backup failed; no packages were installed")?;
    }
    if options.download_only || !opkg_available || unsafe { libc::geteuid() } != 0 {
        println!("To install as root: {manual_cmd}");
        return Ok(());
    }

    ensure_free_space(Path::new("/tmp"), 0)?;
    let snapshot_paths = vec![
        config.commands.nginx.clone(),
        PathBuf::from(MODULES_DIR),
        PathBuf::from(MODULE_CONFIG_DIR),
        config.services.init_dir.join("S80nginx"),
    ];
    let snapshot = RollbackSnapshot::capture(&snapshot_paths, Path::new("/tmp"))?;
    println!(
        "Previous NGINX executable/modules preserved at {}",
        snapshot.directory.display()
    );
    println!("If opkg fails, inspect the snapshot; package-manager metadata is not rolled back.");
    println!("Installing NGINX via Entware. Manual retry command: {manual_cmd}");
    let old_master = nginx_master_from_pid_file(&config.nginx.pid_path, &config.commands.nginx)
        .context("NGINX PID file does not identify the configured master; refusing to install")?;
    let was_running = old_master.is_some();

    let mut opkg_cmd = AsyncCommand::new(OPKG);
    opkg_cmd
        .args(&opkg_options)
        .arg("install")
        .args(&package_paths);
    let opkg_out = match bounded_command(opkg_cmd, OPKG_TIMEOUT, "opkg install").await {
        Ok(result) => result,
        // A timed-out opkg process may leave package hooks running. Never
        // restore files underneath an installer whose state is uncertain.
        Err(error) => {
            return Err(error.context(format!(
                "opkg did not complete; do not overwrite modules until all package processes have exited; recovery snapshot: {}",
                snapshot.directory.display()
            )));
        }
    };
    if !opkg_out.status.success() {
        let error = anyhow!(
            "opkg install failed ({}):\nstdout: {}\nstderr: {}\nRetry: {}",
            opkg_out.status,
            String::from_utf8_lossy(&opkg_out.stdout),
            String::from_utf8_lossy(&opkg_out.stderr),
            manual_cmd
        );
        return Err(recover_failure(config, &snapshot, error, was_running).await);
    }
    if let Err(error) = test_nginx_config(
        &config.commands.nginx,
        &config.nginx.config_path,
        config.nginx.prefix_path.as_deref(),
    ) {
        return Err(recover_failure(config, &snapshot, error, was_running).await);
    }

    match installed_matches_release(
        &config.commands.nginx,
        &checksum_map,
        Path::new(MODULES_DIR),
    ) {
        Ok(true) => {}
        Ok(false) => {
            return Err(recover_failure(
                config,
                &snapshot,
                anyhow!(
                    "installed NGINX executable/modules do not match verified release checksums"
                ),
                was_running,
            )
            .await);
        }
        Err(error) => return Err(recover_failure(config, &snapshot, error, was_running).await),
    }

    // HUP/reload only reconfigures the OLD master binary. NGINX's supported
    // live binary upgrade is SIGUSR2: the old master launches the replacement
    // master using inherited sockets; SIGQUIT retires old workers gracefully.
    if let Some(old_master) = old_master {
        // Validate the exact same master seen before opkg. If the PID was
        // reused, do not send a signal to its new owner.
        if let Err(error) = signal_nginx_master(old_master, &config.commands.nginx, libc::SIGUSR2) {
            return Err(recover_failure(config, &snapshot, error, was_running).await);
        }
        // Once USR2 succeeds, do not automatically restore modules: a new
        // master may have started, and changing on-disk modules underneath it
        // risks loading the wrong ABI. Preserve the snapshot for diagnosis.
        let new_master = wait_for_new_master(config, old_master).await.with_context(|| {
            format!(
                "live NGINX binary activation incomplete; inspect error logs and PID files;                  previous binary/modules are at {} (no automatic rollback after SIGUSR2)",
                snapshot.directory.display()
            )
        })?;
        // The old PID may now be in nginx.pid.oldbin, not nginx.pid.
        // Only retire it if its original process identity still matches.
        signal_nginx_master(old_master, &config.commands.nginx, libc::SIGQUIT).with_context(|| {
            format!(
                "new NGINX master PID {} is running, but previous PID {} could not be safely retired; inspect and retire manually",
                new_master.pid, old_master.pid
            )
        })?;
        ensure!(
            nginx_master_identity(new_master.pid, &config.commands.nginx)? == new_master,
            "new NGINX master identity changed after retiring the old master"
        );
        println!(
            "New NGINX master PID {} verified; old master PID {} retiring gracefully.",
            new_master.pid, old_master.pid
        );
    } else {
        println!(
            "NGINX was not running before the upgrade; packages installed, service left stopped."
        );
    }
    println!(
        "Successfully installed NGINX {} ({}). Recovery files: {}",
        tag_info.version_str,
        tag_info.channel,
        snapshot.directory.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_version_numbers_valid() {
        assert_eq!(parse_version_numbers("1.30.7"), Some([1, 30, 7]));
        assert_eq!(parse_version_numbers("1.28.0"), Some([1, 28, 0]));
        assert_eq!(parse_version_numbers("0.1.0"), Some([0, 1, 0]));
        assert_eq!(parse_version_numbers("2.0.0"), Some([2, 0, 0]));
    }

    #[test]
    fn parse_version_numbers_invalid() {
        for invalid in [
            "1.30", "1.30.7.1", "1.03.7", "1.30.07", "1.30.a", "", "v1.30.7",
        ] {
            assert_eq!(parse_version_numbers(invalid), None, "tested: {invalid}");
        }
    }

    #[test]
    fn channel_detection() {
        assert_eq!(channel_for_version([1, 30, 7]), NginxChannel::Stable);
        assert_eq!(channel_for_version([1, 28, 0]), NginxChannel::Stable);
        assert_eq!(channel_for_version([1, 26, 2]), NginxChannel::Stable);
        assert_eq!(channel_for_version([1, 29, 1]), NginxChannel::Mainline);
        assert_eq!(channel_for_version([1, 31, 0]), NginxChannel::Mainline);
        assert_eq!(channel_for_version([1, 27, 4]), NginxChannel::Mainline);
    }

    #[test]
    fn parse_nginx_tag_formats() {
        let tag1 = "nginx-v1.30.7-run44684227015-a1";
        let info1 = parse_nginx_tag(tag1).unwrap();
        assert_eq!(info1.tag, tag1);
        assert_eq!(info1.version, [1, 30, 7]);
        assert_eq!(info1.version_str, "1.30.7");
        assert_eq!(info1.run_id, Some(44684227015));
        assert_eq!(info1.attempt, Some(1));
        assert_eq!(info1.channel, NginxChannel::Stable);

        let tag2 = "nginx-v1.31.0";
        let info2 = parse_nginx_tag(tag2).unwrap();
        assert_eq!(info2.version, [1, 31, 0]);
        assert_eq!(info2.run_id, None);
        assert_eq!(info2.attempt, None);
        assert_eq!(info2.channel, NginxChannel::Mainline);

        assert!(parse_nginx_tag("v0.10.3").is_none());
        assert!(parse_nginx_tag("nginx-1.30.7").is_none());
        assert!(parse_nginx_tag("nginx-v1.30").is_none());
        for invalid in [
            "nginx-v1.30.7/../../oops",
            "nginx-v1.30.7-run12-a1/escape",
            "nginx-v1.30.7-unknown",
            "nginx-v1.30.7-run12",
            "nginx-v1.30.7-run12-a1-extra",
            "nginx-v1.30.7-runx-a2",
        ] {
            assert!(parse_nginx_tag(invalid).is_none(), "{invalid}");
        }
    }

    #[test]
    fn nginx_tag_ordering() {
        let tag_old = parse_nginx_tag("nginx-v1.30.6-run10-a1").unwrap();
        let tag_mid1 = parse_nginx_tag("nginx-v1.30.7-run10-a1").unwrap();
        let tag_mid2 = parse_nginx_tag("nginx-v1.30.7-run20-a1").unwrap();
        let tag_mid3 = parse_nginx_tag("nginx-v1.30.7-run20-a2").unwrap();
        let tag_new = parse_nginx_tag("nginx-v1.31.0-run5-a1").unwrap();

        assert!(tag_old < tag_mid1);
        assert!(tag_mid1 < tag_mid2);
        assert!(tag_mid2 < tag_mid3);
        assert!(tag_mid3 < tag_new);
    }

    #[test]
    fn parse_installed_nginx_version_formats() {
        let out1 = "nginx version: nginx/1.30.6\n";
        assert_eq!(parse_installed_nginx_version(out1), Some([1, 30, 6]));

        let out2 = "nginx version: nginx/1.28.0 (Ubuntu)\nbuilt with OpenSSL\n";
        assert_eq!(parse_installed_nginx_version(out2), Some([1, 28, 0]));

        let out3 = "NGINX version: nginx/1.31.0-entware\n";
        assert_eq!(parse_installed_nginx_version(out3), Some([1, 31, 0]));

        let out4 = "command not found: nginx\n";
        assert_eq!(parse_installed_nginx_version(out4), None);
    }

    #[test]
    fn parse_checksums_valid_and_invalid() {
        let text = r#"
84b939dcee71b639bca56219cd94fd6ac9b9669cb876eb5b3ff3aed9e26a53e8  nginx
53bbf44415b63873531cb5cef447573ca7adc4745b578838b7f312ce4b2e1bce *nginx-ssl_1.30.7-99_aarch64-3.10.ipk
# Comment
ad87cc6f9b5b693e0c4bc2e6feda0915dce461e4a780d0d2e207730df826c50f  nginx-mod-brotli_1.30.7-99_aarch64-3.10.ipk
"#;
        let map = parse_checksums(text).unwrap();
        assert_eq!(map.len(), 3);
        assert_eq!(
            map.get("nginx-ssl_1.30.7-99_aarch64-3.10.ipk"),
            Some(&"53bbf44415b63873531cb5cef447573ca7adc4745b578838b7f312ce4b2e1bce".to_string())
        );
        assert_eq!(
            map.get("nginx-mod-brotli_1.30.7-99_aarch64-3.10.ipk"),
            Some(&"ad87cc6f9b5b693e0c4bc2e6feda0915dce461e4a780d0d2e207730df826c50f".to_string())
        );

        assert!(parse_checksums("invalid_hash file.ipk").is_err());
        assert!(
            parse_checksums(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa file extra"
            )
            .is_err()
        );
    }

    #[test]
    fn asset_resolution_all_packages() {
        let assets = vec![
            Asset {
                name: "SHA256SUMS".into(),
                size: 1024,
            },
            Asset {
                name: "nginx-ssl_1.30.7-99_aarch64-3.10.ipk".into(),
                size: 1024,
            },
            Asset {
                name: "nginx-mod-brotli_1.30.7-99_aarch64-3.10.ipk".into(),
                size: 1024,
            },
            Asset {
                name: "nginx-mod-stream_1.30.7-99_aarch64-3.10.ipk".into(),
                size: 1024,
            },
            Asset {
                name: "nginx-mod-headers-more_1.30.7-99_aarch64-3.10.ipk".into(),
                size: 1024,
            },
        ];

        let matched = find_required_assets(&assets, "1.30.7", "aarch64-3.10").unwrap();
        assert_eq!(matched.len(), 4);

        // Missing package should fail
        let missing = vec![Asset {
            name: "nginx-ssl_1.30.7-99_aarch64-3.10.ipk".into(),
            size: 1024,
        }];
        assert!(find_required_assets(&missing, "1.30.7", "aarch64-3.10").is_err());
    }

    #[test]
    fn select_release_filters_by_channel_and_version() {
        let rel1 = Release {
            tag_name: "nginx-v1.30.6-run1-a1".into(),
            draft: false,
            prerelease: false,
            assets: vec![],
        };
        let rel2 = Release {
            tag_name: "nginx-v1.30.7-run2-a1".into(),
            draft: false,
            prerelease: false,
            assets: vec![],
        };
        let rel3 = Release {
            tag_name: "nginx-v1.31.0-run3-a1".into(),
            draft: false,
            prerelease: false,
            assets: vec![],
        };
        let rel_other = Release {
            tag_name: "v0.10.3".into(),
            draft: false,
            prerelease: false,
            assets: vec![],
        };

        let releases = vec![rel1, rel2, rel3, rel_other];

        // Stable selection picks 1.30.7
        let (sel_stable, info_stable) =
            select_release_from_list(&releases, None, NginxChannel::Stable).unwrap();
        assert_eq!(sel_stable.tag_name, "nginx-v1.30.7-run2-a1");
        assert_eq!(info_stable.version, [1, 30, 7]);

        // Mainline selection picks 1.31.0
        let (sel_mainline, info_mainline) =
            select_release_from_list(&releases, None, NginxChannel::Mainline).unwrap();
        assert_eq!(sel_mainline.tag_name, "nginx-v1.31.0-run3-a1");
        assert_eq!(info_mainline.version, [1, 31, 0]);

        // Specific version selection
        let (sel_ver, info_ver) =
            select_release_from_list(&releases, Some("1.30.6"), NginxChannel::Mainline).unwrap();
        assert_eq!(sel_ver.tag_name, "nginx-v1.30.6-run1-a1");
        assert_eq!(info_ver.version, [1, 30, 6]);

        // Non-existent version
        assert!(select_release_from_list(&releases, Some("1.32.0"), NginxChannel::Stable).is_err());
    }

    #[test]
    fn upgrade_decision_handles_channel_switches_and_rebuilds() {
        assert_eq!(
            disposition(Some([1, 31, 8]), [1, 30, 7], false),
            UpgradeDisposition::Downgrade
        );
        assert_eq!(
            disposition(Some([1, 30, 6]), [1, 31, 8], false),
            UpgradeDisposition::Newer
        );
        assert_eq!(
            disposition(Some([1, 30, 7]), [1, 30, 7], false),
            UpgradeDisposition::Rebuild
        );
        assert_eq!(
            disposition(Some([1, 30, 7]), [1, 30, 7], true),
            UpgradeDisposition::Current
        );
        assert_eq!(
            disposition(None, [1, 30, 7], false),
            UpgradeDisposition::Newer
        );
    }

    #[test]
    fn release_identity_requires_binary_and_all_modules() {
        let dir = tempfile::tempdir().unwrap();
        let binary = dir.path().join("nginx");
        let modules = dir.path().join("modules");
        fs::create_dir(&modules).unwrap();
        fs::write(&binary, "nginx executable").unwrap();
        let mut checksums = HashMap::new();
        checksums.insert("nginx".to_string(), sha256_file(&binary).unwrap().unwrap());
        for name in MODULE_FILES {
            let path = modules.join(name);
            fs::write(&path, format!("module {name}")).unwrap();
            checksums.insert(name.to_string(), sha256_file(&path).unwrap().unwrap());
        }
        assert!(installed_matches_release(&binary, &checksums, &modules).unwrap());

        fs::write(modules.join(MODULE_FILES[1]), "different release").unwrap();
        assert!(!installed_matches_release(&binary, &checksums, &modules).unwrap());
        fs::remove_file(&binary).unwrap();
        assert!(!installed_matches_release(&binary, &checksums, &modules).unwrap());
    }

    #[test]
    fn rollback_snapshot_restores_binary_modules_and_missing_paths() {
        let dir = tempfile::tempdir().unwrap();
        let executable = dir.path().join("nginx");
        let modules = dir.path().join("modules");
        let module_link = dir.path().join("module-link");
        let absent = dir.path().join("formerly-absent");
        fs::write(&executable, "old binary").unwrap();
        fs::create_dir(&modules).unwrap();
        fs::write(modules.join("module.so"), "old module").unwrap();
        symlink("modules/module.so", &module_link).unwrap();
        let snapshot = RollbackSnapshot::capture(
            &[
                executable.clone(),
                modules.clone(),
                module_link.clone(),
                absent.clone(),
            ],
            dir.path(),
        )
        .unwrap();

        fs::write(&executable, "new binary").unwrap();
        fs::write(modules.join("module.so"), "new module").unwrap();
        fs::write(modules.join("new.so"), "new extra module").unwrap();
        fs::remove_file(&module_link).unwrap();
        fs::write(&absent, "new file").unwrap();
        snapshot.restore().unwrap();

        assert_eq!(fs::read_to_string(&executable).unwrap(), "old binary");
        assert_eq!(
            fs::read_to_string(modules.join("module.so")).unwrap(),
            "old module"
        );
        assert!(!modules.join("new.so").exists());
        assert_eq!(
            fs::read_link(module_link).unwrap(),
            PathBuf::from("modules/module.so")
        );
        assert!(!absent.exists());
    }

    #[test]
    fn refuses_unsafe_release_filenames() {
        for valid in ["nginx-ssl_1.30.7-99_aarch64-3.10.ipk", "SHA256SUMS"] {
            assert!(validate_asset_name(valid).is_ok());
        }
        for invalid in ["../nginx", "foo/bar.ipk", "evil ipk", "foo\\bar"] {
            assert!(validate_asset_name(invalid).is_err(), "{invalid}");
        }
    }

    #[tokio::test]
    async fn command_execution_reports_nonzero_and_timeout() {
        let mut failed = AsyncCommand::new("sh");
        failed.arg("-c").arg("exit 17");
        let output = bounded_command(failed, Duration::from_secs(2), "test command")
            .await
            .unwrap();
        assert_eq!(output.status.code(), Some(17));

        let mut stuck = AsyncCommand::new("sh");
        stuck.arg("-c").arg("sleep 2");
        assert!(
            bounded_command(stuck, Duration::from_millis(50), "test timeout")
                .await
                .is_err()
        );
    }

    fn fake_stat(pid: i32, start: u64, state: &str) -> String {
        let mut fields = vec!["0".to_string(); 19];
        fields[18] = start.to_string();
        format!(
            "{pid} (nginx master with spaces) {state} {}\n",
            fields.join(" ")
        )
    }

    fn create_fake_master(proc_root: &Path, pid: i32, binary: &Path, start: u64) {
        let process = proc_root.join(pid.to_string());
        fs::create_dir_all(&process).unwrap();
        fs::write(process.join("comm"), "nginx\n").unwrap();
        fs::write(
            process.join("cmdline"),
            b"nginx: master process /opt/sbin/nginx\0",
        )
        .unwrap();
        fs::write(process.join("stat"), fake_stat(pid, start, "S")).unwrap();
        symlink(binary, process.join("exe")).unwrap();
    }

    #[test]
    fn empty_pid_file_requires_no_nginx_processes() {
        let dir = tempfile::tempdir().unwrap();
        let binary = dir.path().join("nginx");
        let proc_root = dir.path().join("proc");
        let pid_file = dir.path().join("nginx.pid");
        fs::create_dir(&proc_root).unwrap();
        fs::write(&binary, "nginx executable").unwrap();
        for contents in ["", " \n"] {
            fs::write(&pid_file, contents).unwrap();
            assert!(
                nginx_master_from_pid_file_at(&pid_file, &binary, &proc_root)
                    .unwrap()
                    .is_none()
            );
        }
        create_fake_master(&proc_root, 43210, &binary, 12345);
        assert!(nginx_master_from_pid_file_at(&pid_file, &binary, &proc_root).is_err());
        fs::write(proc_root.join("43210/comm"), "httpd\n").unwrap();
        assert!(
            nginx_master_from_pid_file_at(&pid_file, &binary, &proc_root)
                .unwrap()
                .is_none()
        );
        fs::remove_dir_all(&proc_root).unwrap();
        assert!(nginx_master_from_pid_file_at(&pid_file, &binary, &proc_root).is_err());
    }

    #[test]
    fn parse_master_identity_rejects_stale_or_reused_pids() {
        let dir = tempfile::tempdir().unwrap();
        let binary = dir.path().join("nginx");
        let other_binary = dir.path().join("unrelated");
        fs::write(&binary, "nginx executable").unwrap();
        fs::write(&other_binary, "unrelated executable").unwrap();
        let proc_root = dir.path().join("proc");
        let pid_file = dir.path().join("nginx.pid");
        let pid = 43210;

        assert!(
            nginx_master_from_pid_file_at(&pid_file, &binary, &proc_root)
                .unwrap()
                .is_none()
        );
        fs::write(&pid_file, "garbage").unwrap();
        assert!(nginx_master_from_pid_file_at(&pid_file, &binary, &proc_root).is_err());

        fs::write(&pid_file, pid.to_string()).unwrap();
        assert!(nginx_master_from_pid_file_at(&pid_file, &binary, &proc_root).is_err());

        create_fake_master(&proc_root, pid, &binary, 12345);
        let process = proc_root.join(pid.to_string());
        let original = nginx_master_from_pid_file_at(&pid_file, &binary, &proc_root)
            .unwrap()
            .unwrap();
        assert_eq!(original.pid, pid);
        assert_eq!(original.start_ticks, 12345);
        assert!(original.exe_inode > 0);

        // PID reuse is detected even if the new process runs the same binary.
        fs::write(process.join("stat"), fake_stat(pid, 12346, "S")).unwrap();
        let reused = nginx_master_identity_at(&proc_root, pid, &binary).unwrap();
        assert_ne!(reused, original);

        fs::write(process.join("stat"), fake_stat(pid, 12345, "S")).unwrap();
        fs::write(process.join("cmdline"), b"nginx: worker process\0").unwrap();
        assert!(nginx_master_identity_at(&proc_root, pid, &binary).is_err());

        fs::write(process.join("cmdline"), b"nginx: master process nginx\0").unwrap();
        fs::write(process.join("comm"), "bash\n").unwrap();
        assert!(nginx_master_identity_at(&proc_root, pid, &binary).is_err());

        fs::write(process.join("comm"), "nginx\n").unwrap();
        fs::remove_file(process.join("exe")).unwrap();
        symlink(&other_binary, process.join("exe")).unwrap();
        assert!(nginx_master_identity_at(&proc_root, pid, &binary).is_err());

        fs::remove_file(process.join("exe")).unwrap();
        symlink(&binary, process.join("exe")).unwrap();
        fs::write(process.join("stat"), fake_stat(pid, 12345, "Z")).unwrap();
        assert!(nginx_master_identity_at(&proc_root, pid, &binary).is_err());
    }

    #[test]
    fn parse_master_title_and_stat_require_valid_fields() {
        assert!(is_nginx_master_title(
            b"nginx: master process /opt/sbin/nginx\0"
        ));
        assert!(is_nginx_master_title(b"nginx: master process\0"));
        for invalid in [
            &b"nginx: worker process\0"[..],
            &b"/opt/sbin/nginx -s reload\0"[..],
            &b"nginx: master process-wrapper\0"[..],
            &b""[..],
        ] {
            assert!(!is_nginx_master_title(invalid));
        }
        assert_eq!(
            parse_proc_start_ticks(&fake_stat(123, 4567, "S")),
            Some(4567)
        );
        assert_eq!(parse_proc_start_ticks(&fake_stat(123, 4567, "Z")), None);
        assert_eq!(parse_proc_start_ticks("123 (nginx) S 0"), None);
        assert_eq!(parse_proc_start_ticks("not a proc stat"), None);
    }

    #[test]
    fn require_router_guard() {
        assert!(require_router(Platform::Asuswrt, false).is_ok());
        assert!(require_router(Platform::Asuswrt, true).is_err());
        assert!(require_router(Platform::Linux, false).is_err());
    }
}
