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
use tracing::warn;
use uuid::Uuid;

use crate::{
    command::CommandRunner,
    config::AppConfig,
    firewall::FirewallManager,
    models::{
        CertificateMethod, CertificateOperation, CertificateSpec, CertificateStatus, CommandResult,
        DehydratedActivity, DehydratedLockStatus, DehydratedUpdate,
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
    pub nginx_lock: Arc<Mutex<()>>,
    pub http_access_lock: Arc<Mutex<()>>,
    certificate_shutdown: tokio::sync::watch::Sender<bool>,
    pub firewall: FirewallManager,
    pub filtering_timer: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
    pub filtering_paused_until: Arc<Mutex<Option<DateTime<Utc>>>>,
    dehydrated_update_lock: Arc<Mutex<()>>,
    certificate_operation_lock: Arc<Mutex<()>>,
    certificate_operation: Arc<Mutex<Option<CertificateOperation>>>,
}

impl AppState {
    pub(crate) fn certificates_stopping(&self) -> bool {
        *self.certificate_shutdown.borrow()
    }
    pub async fn stop_certificates(&self) -> Result<()> {
        self.certificate_shutdown.send_replace(true);
        let _guard = self.certificate_operation_lock.lock().await;
        crate::certificate_http::close(self).await
    }
    pub fn certificate_busy(&self) -> bool {
        self.certificate_operation_lock.try_lock().is_err()
    }
    pub async fn close_http_access(&self) -> Result<()> {
        let _guard = self
            .certificate_operation_lock
            .try_lock()
            .context("a certificate batch is running; wait for its cleanup")?;
        crate::certificate_http::close(self).await
    }
    pub fn new(config: AppConfig, stores: Stores, firewall: FirewallManager) -> Self {
        let test_mode = config.test_mode;
        Self {
            config: Arc::new(config),
            stores,
            runner: CommandRunner::new(test_mode),
            nginx_lock: Arc::new(Mutex::new(())),
            http_access_lock: Arc::new(Mutex::new(())),
            certificate_shutdown: tokio::sync::watch::channel(false).0,
            firewall,
            filtering_timer: Arc::new(Mutex::new(None)),
            filtering_paused_until: Arc::new(Mutex::new(None)),
            dehydrated_update_lock: Arc::new(Mutex::new(())),
            certificate_operation_lock: Arc::new(Mutex::new(())),
            certificate_operation: Arc::new(Mutex::new(None)),
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

        let mut operation = self.certificate_operation.lock().await.clone();
        let managed_running = operation
            .as_ref()
            .is_some_and(|op| op.status == DehydratedActivity::Running);
        let external_running = self.dehydrated_process_running();
        let running = managed_running || external_running;
        if external_running && !managed_running {
            // Do not attribute another Dehydrated process to our last operation.
            operation = None;
        }
        let status = if running {
            DehydratedActivity::Running
        } else if locked
            && operation
                .as_ref()
                .is_some_and(|op| op.status == DehydratedActivity::Failed)
        {
            DehydratedActivity::Failed
        } else if locked {
            // The owner is unknown; only offer manual clearing after checking processes.
            DehydratedActivity::Locked
        } else {
            operation
                .as_ref()
                .map_or(DehydratedActivity::Idle, |op| op.status)
        };
        Ok(DehydratedLockStatus {
            locked,
            path,
            status,
            operation,
        })
    }

    pub async fn clear_dehydrated_lock(&self) -> Result<DehydratedLockStatus> {
        // Serialize with issue/renew so a concurrent request cannot remove its lock.
        let _guard = self
            .certificate_operation_lock
            .try_lock()
            .context("cannot clear lock while a certificate operation is running")?;
        if self.dehydrated_lock_status().await?.status == DehydratedActivity::Running {
            bail!("cannot clear lock while dehydrated or a certificate hook is running");
        }
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

    fn dehydrated_process_running(&self) -> bool {
        // Detect operations started outside this process (for example, after a
        // Maestro restart), including active shell-based DNS hooks.
        #[cfg(target_os = "linux")]
        {
            let executable = self.config.commands.dehydrated.to_string_lossy();
            let Ok(entries) = std::fs::read_dir("/proc") else {
                // A lock cannot safely be cleared if process state is unknown.
                return true;
            };
            for entry in entries.flatten() {
                if !entry
                    .file_name()
                    .to_string_lossy()
                    .bytes()
                    .all(|b| b.is_ascii_digit())
                {
                    continue;
                }
                let Ok(cmdline) = std::fs::read(entry.path().join("cmdline")) else {
                    continue;
                };
                if cmdline.split(|b| *b == 0).any(|arg| {
                    let arg = String::from_utf8_lossy(arg);
                    arg == executable
                        || (arg.starts_with('/')
                            && arg.contains("dehydrated")
                            && arg.contains("hook")
                            && arg.ends_with(".sh"))
                }) {
                    return true;
                }
            }
        }
        false
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
        self.certificate_batch(vec![(spec, renew)]).await?.remove(0)
    }

    /// An owned worker outlives an HTTP client disconnect and always reaches
    /// cleanup. Scheduled and manual work share one session/operation guard.
    async fn certificate_batch(
        &self,
        jobs: Vec<(CertificateSpec, bool)>,
    ) -> Result<Vec<Result<CommandResult>>> {
        let guard = self
            .certificate_operation_lock
            .clone()
            .try_lock_owned()
            .context("another certificate operation is already running")?;
        let state = self.clone();
        tokio::spawn(async move {
            let _guard = guard;
            let lock = state.dehydrated_lock_status().await?;
            if lock.locked || lock.status == DehydratedActivity::Running {
                bail!("dehydrated is running or a lock is present; no HTTP window was opened");
            }
            let mut results: Vec<Option<Result<CommandResult>>> = (0..jobs.len()).map(|_| None).collect();
            // DNS operations never open a window, even in a mixed batch.
            for (index, (spec, renew)) in jobs.iter().enumerate().filter(|(_, (spec, _))| matches!(spec.method, CertificateMethod::Dns)) {
                results[index] = Some(state.issue_certificate_locked(spec, *renew, None).await);
            }
            let http: Vec<_> = jobs.iter().filter(|(spec, _)| matches!(spec.method, CertificateMethod::Http)).map(|(spec, _)| spec.clone()).collect();
            if !http.is_empty() {
                match crate::certificate_http::begin(&state, &http).await {
                    Err(error) => {
                        for (index, (spec, _)) in jobs.iter().enumerate() {
                            if matches!(spec.method, CertificateMethod::Http) {
                                results[index] = Some(Err(anyhow::anyhow!("{error:#}")));
                            }
                        }
                    }
                    Ok(session) => {
                        for (index, (spec, renew)) in jobs.iter().enumerate().filter(|(_, (spec, _))| matches!(spec.method, CertificateMethod::Http)) {
                            results[index] = Some(state.issue_certificate_locked(spec, *renew, session.as_ref().map(|s| s.expires_at)).await);
                        }
                        if session.is_some() {
                            if let Err(cleanup) = crate::certificate_http::close(&state).await {
                                for (index, (spec, _)) in jobs.iter().enumerate() {
                                    if matches!(spec.method, CertificateMethod::Http) {
                                        let original = results[index].take().unwrap();
                                        results[index] = Some(Err(anyhow::anyhow!("certificate result: {}; HTTP cleanup failed: {cleanup:#}", match original {
                                            Ok(output) => format!("success={}, stderr={}", output.success, output.stderr),
                                            Err(error) => format!("{error:#}"),
                                        })));
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Ok(results.into_iter().map(|result| result.expect("each job completed")).collect())
        }).await.context("certificate worker failed")?
    }

    async fn issue_certificate_locked(
        &self,
        spec: &CertificateSpec,
        renew: bool,
        deadline: Option<DateTime<Utc>>,
    ) -> Result<CommandResult> {
        if *self.certificate_shutdown.borrow() {
            bail!("certificate service is shutting down");
        }
        let lock_status = self.dehydrated_lock_status().await?;
        if lock_status.locked || lock_status.status == DehydratedActivity::Running {
            bail!("dehydrated is running or a lock is present; cannot issue or renew");
        }

        let action = if renew { "renew" } else { "issue" };
        let mut operation = CertificateOperation {
            certificate: spec.name.clone(),
            action: action.to_owned(),
            status: DehydratedActivity::Running,
            started_at: Utc::now(),
            finished_at: None,
            error: None,
        };
        *self.certificate_operation.lock().await = Some(operation.clone());

        let result = match self.run_certificate_operation(spec, renew, deadline).await {
            Ok(output) if output.success => self.deploy_certificate(spec).await.map(|()| output),
            result => result,
        };
        let failure = match &result {
            Ok(output) if output.success => None,
            Ok(output) => Some(if output.stderr.is_empty() {
                format!("dehydrated exited unsuccessfully (code {:?})", output.code)
            } else {
                output.stderr.clone()
            }),
            Err(error) => Some(format!("{error:#}")),
        };

        // The process-group runner kills the hook subprocesses on timeout before
        // returning, so cleanup cannot race a still-running managed hook.
        let cleanup_failure = match fs::remove_file(self.dehydrated_lock_path()).await {
            Ok(()) => None,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => {
                warn!(%error, "failed to clear dehydrated lock");
                Some(format!("failed to clear dehydrated lock: {error}"))
            }
        };

        operation.finished_at = Some(Utc::now());
        operation.error = failure.or(cleanup_failure);
        operation.status = if operation.error.is_some() {
            DehydratedActivity::Failed
        } else {
            DehydratedActivity::Completed
        };
        *self.certificate_operation.lock().await = Some(operation);
        result
    }

    /// Standard dehydrated output is deployed as a validated nginx transaction.
    /// Custom hooks that deploy elsewhere retain their existing behavior.
    async fn deploy_certificate(&self, spec: &CertificateSpec) -> Result<()> {
        validate_certificate_name(&spec.name)?;
        let source = self
            .config
            .certificates
            .certs_dir
            .join("certs")
            .join(&spec.name);
        if !source.join("fullchain.pem").exists() {
            return Ok(());
        }
        let certificate = self
            .runner
            .run(
                &self.config.commands.openssl,
                vec![
                    "x509".into(),
                    "-in".into(),
                    source.join("fullchain.pem").to_string_lossy().into_owned(),
                    "-pubkey".into(),
                    "-noout".into(),
                ],
                Duration::from_secs(10),
            )
            .await?;
        let key = self
            .runner
            .run(
                &self.config.commands.openssl,
                vec![
                    "pkey".into(),
                    "-in".into(),
                    source.join("privkey.pem").to_string_lossy().into_owned(),
                    "-pubout".into(),
                ],
                Duration::from_secs(10),
            )
            .await?;
        if !certificate.success || !key.success || certificate.stdout.trim() != key.stdout.trim() {
            bail!("renewed certificate is invalid or does not match its private key");
        }
        let _lock = self.nginx_lock.lock().await;
        let target = self.config.nginx.root_dir.join("certs").join(&spec.name);
        let mut files = std::collections::BTreeMap::new();
        for name in ["privkey.pem", "fullchain.pem", "cert.pem", "chain.pem"] {
            let path = source.join(name);
            if matches!(name, "cert.pem" | "chain.pem") && !path.exists() {
                continue;
            }
            files.insert(
                target.join(name),
                fs::read_to_string(&path).await.with_context(|| {
                    format!("unable to read renewed certificate {}", path.display())
                })?,
            );
        }
        let mut transaction = crate::nginx_render::FileTransaction::apply(&self.config, files)?;
        let result = async {
            let test = crate::api::nginx::nginx_test(self).await?;
            if !test.success {
                bail!(
                    "renewed certificate failed nginx validation: {}",
                    test.stderr
                );
            }
            if crate::api::nginx::is_running(self).await {
                let reload = crate::api::nginx::nginx_reload(self).await?;
                if !reload.success {
                    bail!(
                        "nginx reload after certificate deployment failed: {}",
                        reload.stderr
                    );
                }
            }
            Ok(())
        }
        .await;
        if let Err(error) = result {
            transaction.rollback()?;
            if crate::api::nginx::is_running(self).await {
                let _ = crate::api::nginx::nginx_reload(self).await;
            }
            return Err(error);
        }
        transaction.commit();
        Ok(())
    }

    async fn run_certificate_operation(
        &self,
        spec: &CertificateSpec,
        renew: bool,
        deadline: Option<DateTime<Utc>>,
    ) -> Result<CommandResult> {
        self.write_dehydrated_files(spec).await?;
        let mut args = vec![
            "--cron".to_string(),
            "--accept-terms".to_string(),
            "--config".to_string(),
            self.certificate_config_path(spec)
                .to_string_lossy()
                .to_string(),
        ];
        if renew {
            args.push("--force".to_string());
        }
        let mut timeout = Duration::from_secs(self.config.certificates.command_timeout_seconds);
        if let Some(deadline) = deadline {
            let remaining = (deadline - Utc::now())
                .to_std()
                .context("HTTP validation batch window has expired")?;
            if remaining.is_zero() {
                bail!("HTTP validation batch window has expired");
            }
            timeout = timeout.min(remaining);
        }
        let mut shutdown = self.certificate_shutdown.subscribe();
        if *shutdown.borrow() {
            bail!("certificate service is shutting down");
        }
        tokio::select! {
            result = self.runner.run_process_group(&self.config.commands.dehydrated, args, timeout) => result,
            _ = shutdown.changed() => bail!("certificate operation cancelled for shutdown"),
        }
    }

    pub async fn update_dehydrated(&self) -> Result<DehydratedUpdate> {
        let _update = self.dehydrated_update_lock.lock().await;
        download_latest_dehydrated(&self.config).await
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
        let mut jobs = Vec::new();
        for spec in specs.into_iter().filter(|spec| spec.auto_renew) {
            let status = self.certificate_status(&spec).await;
            if status.renewal_due {
                jobs.push((spec, status.exists));
            }
        }
        if jobs.is_empty() {
            return Ok(());
        }
        let names = jobs
            .iter()
            .map(|(spec, _)| spec.name.clone())
            .collect::<Vec<_>>();
        for (name, result) in names.into_iter().zip(self.certificate_batch(jobs).await?) {
            match result {
                Ok(output) if !output.success => {
                    warn!(certificate=%name, stderr=%output.stderr, "certificate renewal failed")
                }
                Err(error) => warn!(certificate=%name, %error, "certificate renewal failed"),
                _ => {}
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
            let hook = spec
                .hook
                .clone()
                .unwrap_or_else(|| config.certificates.dns01_hook.clone());
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
    let mut domains = Vec::with_capacity(spec.domains.len());
    for domain in &spec.domains {
        validate_domain(domain)?;
        domains.push(domain.as_str());
    }
    let marker = spec.domains[0]
        .strip_prefix("*.")
        .unwrap_or(&spec.domains[0]);
    Ok(format!(
        "\n# {marker}-start\n{} > {}\n# {marker}-end\n",
        domains.join(" "),
        spec.name
    ))
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

pub(crate) fn validate_domain(domain: &str) -> Result<()> {
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

pub async fn download_latest_dehydrated(config: &AppConfig) -> Result<DehydratedUpdate> {
    let path = config.commands.dehydrated.clone();
    if config.test_mode {
        return Ok(DehydratedUpdate {
            path,
            source: DEHYDRATED_DOWNLOAD_URL.into(),
            bytes: 0,
            simulated: true,
        });
    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(
            config.certificates.command_timeout_seconds,
        ))
        .user_agent("maestro/dehydrated-updater")
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
    fn renders_multiple_domains_as_one_certificate_entry() {
        let spec = CertificateSpec {
            id: Uuid::new_v4(),
            name: "example_com".into(),
            domains: vec!["*.example.com".into(), "example.com".into()],
            method: CertificateMethod::Dns,
            hook: None,
            hook_env: BTreeMap::new(),
            staging: false,
            auto_renew: true,
            updated_at: Utc::now(),
        };

        assert_eq!(
            render_dehydrated_domains(&spec).unwrap(),
            "\n# example.com-start\n*.example.com example.com > example_com\n# example.com-end\n"
        );
    }

    #[test]
    fn renders_default_dns_hook_from_config() {
        let mut config = AppConfig::default();
        config.certificates.certs_dir = "/tmp/router-hub/certs".into();
        config.certificates.dns01_hook =
            "/opt/var/lib/router-hub/dehydrated/dehydrated-dns01-hook.sh".into();
        let spec = CertificateSpec {
            id: Uuid::new_v4(),
            name: "example_default_hook".into(),
            domains: vec!["example.com".into()],
            method: CertificateMethod::Dns,
            hook: None,
            hook_env: BTreeMap::new(),
            staging: false,
            auto_renew: true,
            updated_at: Utc::now(),
        };

        let rendered = render_dehydrated_config(&config, &spec).unwrap();
        assert!(
            rendered
                .contains("HOOK='/opt/var/lib/router-hub/dehydrated/dehydrated-dns01-hook.sh'\n")
        );

        // User override in config
        config.certificates.dns01_hook = "/custom/path/hook.sh".into();
        let rendered2 = render_dehydrated_config(&config, &spec).unwrap();
        assert!(rendered2.contains("HOOK='/custom/path/hook.sh'\n"));
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
