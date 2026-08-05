use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use anyhow::{Context, Result, bail};
use chrono::{DateTime, NaiveDateTime, Utc};
use tokio::{fs, sync::Mutex, time::sleep};
use tracing::{info, warn};
use uuid::Uuid;

use crate::{
    command::CommandRunner,
    config::AppConfig,
    firewall::FirewallManager,
    models::{
        CertificateMethod, CertificateSpec, CertificateStatus, CommandResult, DehydratedLockStatus,
        DehydratedUpdate,
    },
    storage::Stores,
};

const DEHYDRATED_DOWNLOAD_URL: &str =
    "https://raw.githubusercontent.com/dehydrated-io/dehydrated/master/dehydrated";
const MAX_DEHYDRATED_DOWNLOAD_BYTES: u64 = 2 * 1024 * 1024;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<AppConfig>,
    pub stores: Stores,
    pub runner: CommandRunner,
    pub firewall: FirewallManager,
    pub filtering_timer: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
    pub filtering_paused_until: Arc<Mutex<Option<DateTime<Utc>>>>,
    dehydrated_update_lock: Arc<Mutex<()>>,
}

impl AppState {
    pub fn new(config: AppConfig, stores: Stores, firewall: FirewallManager) -> Self {
        let test_mode = config.test_mode;
        Self {
            config: Arc::new(config),
            stores,
            runner: CommandRunner::new(test_mode),
            firewall,
            filtering_timer: Arc::new(Mutex::new(None)),
            filtering_paused_until: Arc::new(Mutex::new(None)),
            dehydrated_update_lock: Arc::new(Mutex::new(())),
        }
    }

    pub fn start_certificate_renewal_loop(&self) {
        let state = self.clone();
        tokio::spawn(async move {
            loop {
                if let Err(error) = state.renew_due_certificates().await {
                    warn!(%error, "certificate renewal pass failed");
                }
                sleep(Duration::from_secs(
                    state.config.certificates.renew_interval_hours.max(1) * 3600,
                ))
                .await;
            }
        });
    }

    pub async fn certificate_status(&self, spec: &CertificateSpec) -> CertificateStatus {
        let dehydrated_root = self
            .config
            .certificates
            .certs_dir
            .join("certs")
            .join(&spec.name);
        let deployed_root = self.config.nginx.root_dir.join("certs").join(&spec.name);
        let certificate_root = if deployed_root.join("cert.pem").exists()
            || deployed_root.join("fullchain.pem").exists()
        {
            deployed_root
        } else {
            dehydrated_root
        };
        let fullchain_path = certificate_root.join("fullchain.pem");
        let cert_path = fullchain_path.with_file_name("cert.pem");
        let expires_at = match self.read_certificate_expiry(&cert_path).await {
            Ok(Some(expiry)) => Some(expiry),
            _ => self
                .read_certificate_expiry(&fullchain_path)
                .await
                .ok()
                .flatten(),
        };
        let days_remaining = expires_at
            .as_ref()
            .map(|expiry| expiry.signed_duration_since(Utc::now()).num_days());
        CertificateStatus {
            spec: spec.clone(),
            exists: fullchain_path.exists(),
            fullchain_path,
            expires_at,
            days_remaining,
            renewal_due: days_remaining
                .map(|days| days <= self.config.certificates.renew_before_days)
                .unwrap_or(true),
        }
    }

    pub async fn dehydrated_lock_status(&self) -> Result<DehydratedLockStatus> {
        let path = self.dehydrated_lock_path();
        let locked = match fs::symlink_metadata(&path).await {
            Ok(_) => true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => {
                return Err(error).with_context(|| format!("failed to inspect {}", path.display()));
            }
        };
        Ok(DehydratedLockStatus { locked, path })
    }

    pub async fn clear_dehydrated_lock(&self) -> Result<DehydratedLockStatus> {
        let path = self.dehydrated_lock_path();
        match fs::remove_file(&path).await {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| format!("failed to clear {}", path.display()));
            }
        }
        self.dehydrated_lock_status().await
    }

    async fn read_certificate_expiry(&self, path: &Path) -> Result<Option<DateTime<Utc>>> {
        if !path.exists() {
            return Ok(None);
        }
        let result = self
            .runner
            .run(
                &self.config.commands.openssl,
                vec![
                    "x509".to_string(),
                    "-enddate".to_string(),
                    "-noout".to_string(),
                    "-in".to_string(),
                    path.to_string_lossy().to_string(),
                ],
                Duration::from_secs(10),
            )
            .await?;
        if !result.success {
            bail!("openssl failed: {}", result.stderr);
        }
        if result.simulated {
            return Ok(Some(Utc::now() + chrono::Duration::days(45)));
        }
        Ok(Some(parse_certificate_expiry(&result.stdout)?))
    }

    pub async fn issue_certificate(&self, id: Uuid, renew: bool) -> Result<CommandResult> {
        let spec = self
            .stores
            .certificates
            .read()
            .await
            .iter()
            .find(|spec| spec.id == id)
            .cloned()
            .context("certificate not found")?;

        if self.dehydrated_lock_status().await?.locked {
            bail!(
                "dehydrated lock file is present; clear it before issuing or renewing certificates"
            );
        }

        self.write_dehydrated_files(&spec).await?;

        let mut args = vec![
            "--cron".to_string(),
            "--accept-terms".to_string(),
            "--config".to_string(),
            self.certificate_config_path(&spec)
                .to_string_lossy()
                .to_string(),
        ];
        if renew {
            args.push("--force".to_string());
        }

        self.runner
            .run(
                &self.config.commands.dehydrated,
                args,
                Duration::from_secs(self.config.certificates.command_timeout_seconds),
            )
            .await
    }

    pub async fn update_dehydrated(&self) -> Result<DehydratedUpdate> {
        let _update = self.dehydrated_update_lock.lock().await;
        let path = self.config.commands.dehydrated.clone();
        if self.config.test_mode {
            return Ok(DehydratedUpdate {
                path,
                source: DEHYDRATED_DOWNLOAD_URL.into(),
                bytes: 0,
                simulated: true,
            });
        }

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(
                self.config.certificates.command_timeout_seconds,
            ))
            .user_agent("router-hub/dehydrated-updater")
            .build()
            .context("failed to create GitHub download client")?;
        let response = client
            .get(DEHYDRATED_DOWNLOAD_URL)
            .send()
            .await
            .context("failed to download dehydrated from GitHub")?
            .error_for_status()
            .context("GitHub did not return dehydrated")?;
        if response
            .content_length()
            .is_some_and(|length| length > MAX_DEHYDRATED_DOWNLOAD_BYTES)
        {
            bail!("GitHub dehydrated download is unexpectedly large");
        }
        let body = response
            .bytes()
            .await
            .context("failed to read dehydrated download")?;
        if body.len() as u64 > MAX_DEHYDRATED_DOWNLOAD_BYTES {
            bail!("GitHub dehydrated download is unexpectedly large");
        }
        let text = String::from_utf8(body.to_vec())
            .context("GitHub dehydrated download was not UTF-8 text")?;
        if !text.starts_with("#!") || !text.contains("dehydrated") {
            bail!("GitHub response does not look like the dehydrated script");
        }

        write_atomic(&path, text.as_bytes(), 0o700).await?;
        Ok(DehydratedUpdate {
            path,
            source: DEHYDRATED_DOWNLOAD_URL.into(),
            bytes: text.len(),
            simulated: false,
        })
    }

    async fn write_dehydrated_files(&self, spec: &CertificateSpec) -> Result<()> {
        let config_path = self.certificate_config_path(spec);
        let domains_path = self.certificate_domains_path(spec);
        let config = render_dehydrated_config(&self.config, spec)?;
        let domains = render_dehydrated_domains(spec)?;

        fs::create_dir_all(&self.config.certificates.certs_dir).await?;
        fs::create_dir_all(self.config.certificates.certs_dir.join("certs")).await?;
        if matches!(spec.method, CertificateMethod::Http) {
            fs::create_dir_all(self.config.certificates.certs_dir.join("acme-challenge")).await?;
        }
        write_atomic(&domains_path, domains.as_bytes(), 0o600).await?;
        write_atomic(&config_path, config.as_bytes(), 0o600).await?;
        Ok(())
    }

    fn certificate_config_path(&self, spec: &CertificateSpec) -> PathBuf {
        self.config
            .certificates
            .certs_dir
            .join(format!("{}.cfg", spec.name))
    }

    fn certificate_domains_path(&self, spec: &CertificateSpec) -> PathBuf {
        self.config
            .certificates
            .certs_dir
            .join(format!("{}.txt", spec.name))
    }

    async fn renew_due_certificates(&self) -> Result<()> {
        if self.dehydrated_lock_status().await?.locked {
            warn!("skipping certificate renewal because the dehydrated lock file is present");
            return Ok(());
        }
        let specs = self.stores.certificates.read().await.clone();
        for spec in specs.into_iter().filter(|spec| spec.auto_renew) {
            let status = self.certificate_status(&spec).await;
            if status.renewal_due {
                info!(certificate = %spec.name, "certificate is due for renewal");
                match self.issue_certificate(spec.id, status.exists).await {
                    Ok(result) if !result.success => {
                        warn!(certificate = %spec.name, stderr = %result.stderr, "certificate renewal failed");
                    }
                    Ok(_) => {}
                    Err(error) => {
                        warn!(certificate = %spec.name, %error, "certificate renewal failed");
                    }
                }
            }
        }
        Ok(())
    }

    fn dehydrated_lock_path(&self) -> PathBuf {
        self.config.certificates.certs_dir.join("lock")
    }
}

fn parse_certificate_expiry(output: &str) -> Result<DateTime<Utc>> {
    let value = output
        .lines()
        .map(str::trim)
        .find_map(|line| line.strip_prefix("notAfter="))
        .context("openssl did not return a notAfter value")?;
    let naive = NaiveDateTime::parse_from_str(value, "%b %e %H:%M:%S %Y GMT")
        .with_context(|| format!("unable to parse certificate expiry: {value}"))?;
    Ok(DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc))
}

fn render_dehydrated_config(config: &AppConfig, spec: &CertificateSpec) -> Result<String> {
    validate_certificate_name(&spec.name)?;
    let domains_path = config
        .certificates
        .certs_dir
        .join(format!("{}.txt", spec.name));
    let challenge_type = match spec.method {
        CertificateMethod::Http => "http-01",
        CertificateMethod::Dns => "dns-01",
    };
    let ca = if spec.staging {
        "letsencrypt-test"
    } else {
        "letsencrypt"
    };
    let mut lines = vec![
        format!("CA={}", shell_quote(ca)),
        "AUTO_CLEANUP='yes'".to_string(),
        format!(
            "DOMAINS_TXT={}",
            shell_quote(&domains_path.to_string_lossy())
        ),
        format!("CHALLENGETYPE={}", shell_quote(challenge_type)),
    ];
    match spec.method {
        CertificateMethod::Http => {
            let wellknown = config.certificates.certs_dir.join("acme-challenge");
            lines.push(format!(
                "WELLKNOWN={}",
                shell_quote(&wellknown.to_string_lossy())
            ));
        }
        CertificateMethod::Dns => {
            let hook = spec.hook.clone().unwrap_or_else(|| {
                config
                    .commands
                    .dehydrated
                    .parent()
                    .unwrap_or(&config.paths.data_dir)
                    .join("dehydrated-dns01-hook.sh")
            });
            if hook.as_os_str().is_empty() || hook.to_string_lossy().contains(['\n', '\r']) {
                bail!("DNS certificates require a valid dehydrated hook");
            }
            lines.push(format!("HOOK={}", shell_quote(&hook.to_string_lossy())));
        }
    }
    if let Some(hook) = &spec.hook {
        if hook.as_os_str().is_empty() || hook.to_string_lossy().contains(['\n', '\r']) {
            bail!("certificate hook cannot be empty or contain newlines");
        }
        if matches!(&spec.method, CertificateMethod::Http) {
            lines.push(format!("HOOK={}", shell_quote(&hook.to_string_lossy())));
        }
    }
    for (name, value) in &spec.hook_env {
        validate_hook_env_name(name)?;
        if value.contains(['\n', '\r']) {
            bail!("hook environment values cannot contain newlines");
        }
        lines.push(format!("export {name}={}", shell_quote(value)));
    }
    Ok(format!("{}\n", lines.join("\n")))
}

fn render_dehydrated_domains(spec: &CertificateSpec) -> Result<String> {
    validate_certificate_name(&spec.name)?;
    if spec.domains.is_empty() {
        bail!("at least one domain is required");
    }
    let mut output = String::from("\n");
    for domain in &spec.domains {
        validate_domain(domain)?;
        let marker = domain.strip_prefix("*.").unwrap_or(domain);
        output.push_str(&format!(
            "# {marker}-start\n{domain} > {}\n# {marker}-end\n",
            spec.name
        ));
    }
    Ok(output)
}

fn validate_certificate_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.starts_with('.')
        || name.ends_with('.')
        || name.len() > 128
        || !name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "-_.".contains(character))
    {
        bail!("certificate name contains invalid characters");
    }
    Ok(())
}

fn validate_domain(domain: &str) -> Result<()> {
    let hostname = domain.strip_prefix("*.").unwrap_or(domain);
    let wildcard_count = domain.matches('*').count();
    let wildcard_allowed = if domain.starts_with("*.") { 1 } else { 0 };
    if hostname.is_empty()
        || hostname.len() > 253
        || wildcard_count > wildcard_allowed
        || domain.chars().any(|character| {
            character.is_whitespace()
                || matches!(character, '#' | '>' | '\\' | '\'' | '"' | '/' | ':')
        })
        || !hostname
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || ".-_".contains(character))
    {
        bail!("domain contains invalid characters");
    }
    Ok(())
}

fn validate_hook_env_name(name: &str) -> Result<()> {
    if name.is_empty()
        || !name.chars().enumerate().all(|(index, character)| {
            if index == 0 {
                character.is_ascii_alphabetic() || character == '_'
            } else {
                character.is_ascii_alphanumeric() || character == '_'
            }
        })
    {
        bail!("hook environment names must be shell variable names");
    }
    Ok(())
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

async fn write_atomic(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let parent = path
        .parent()
        .context("cannot write a file without a parent directory")?;
    fs::create_dir_all(parent).await?;
    let filename = path
        .file_name()
        .context("cannot write a file without a filename")?
        .to_string_lossy();
    let temp = parent.join(format!(".{filename}.tmp-{}", Uuid::new_v4().simple()));
    fs::write(&temp, bytes)
        .await
        .with_context(|| format!("failed to write {}", temp.display()))?;
    #[cfg(unix)]
    fs::set_permissions(&temp, std::fs::Permissions::from_mode(mode)).await?;
    fs::rename(&temp, path)
        .await
        .with_context(|| format!("failed to replace {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    #[test]
    fn renders_reference_style_dns_files() {
        let mut config = AppConfig::default();
        config.certificates.certs_dir = "/tmp/router-hub/certs".into();
        let mut hook_env = BTreeMap::new();
        hook_env.insert("DUCKDNS_TOKEN".into(), "token-value".into());
        let spec = CertificateSpec {
            id: Uuid::new_v4(),
            name: "example_duckdns_org".into(),
            domains: vec!["*.example.duckdns.org".into()],
            method: CertificateMethod::Dns,
            hook: Some("/tmp/router-hub/dehydrated-duckdns-hook.sh".into()),
            hook_env,
            staging: false,
            auto_renew: true,
            updated_at: Utc::now(),
        };

        assert_eq!(
            render_dehydrated_config(&config, &spec).unwrap(),
            "CA='letsencrypt'\nAUTO_CLEANUP='yes'\nDOMAINS_TXT='/tmp/router-hub/certs/example_duckdns_org.txt'\nCHALLENGETYPE='dns-01'\nHOOK='/tmp/router-hub/dehydrated-duckdns-hook.sh'\nexport DUCKDNS_TOKEN='token-value'\n"
        );
        assert_eq!(
            render_dehydrated_domains(&spec).unwrap(),
            "\n# example.duckdns.org-start\n*.example.duckdns.org > example_duckdns_org\n# example.duckdns.org-end\n"
        );
    }

    #[test]
    fn shell_quotes_hook_values() {
        assert_eq!(shell_quote("a'b"), "'a'\\''b'");
    }

    #[test]
    fn parses_openssl_expiry_output() {
        let expiry = parse_certificate_expiry("notAfter=Sep  3 18:58:29 2026 GMT\n").unwrap();
        assert_eq!(expiry.to_rfc3339(), "2026-09-03T18:58:29+00:00");
    }
}
