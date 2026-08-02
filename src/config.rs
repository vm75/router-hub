use std::{
    fs,
    net::IpAddr,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use axum::http::HeaderValue;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AppConfig {
    pub test_mode: bool,
    pub server: ServerConfig,
    pub paths: PathsConfig,
    pub commands: CommandsConfig,
    pub asus_ui: AsusUiConfig,
    pub services: ServicesConfig,
    pub nginx: NginxConfig,
    pub certificates: CertificatesConfig,
    pub firewall: FirewallRuntimeConfig,
    pub adguard: AdGuardConfig,
}

#[allow(clippy::derivable_impls)]
impl Default for AppConfig {
    fn default() -> Self {
        Self {
            test_mode: false,
            server: ServerConfig::default(),
            paths: PathsConfig::default(),
            commands: CommandsConfig::default(),
            asus_ui: AsusUiConfig::default(),
            services: ServicesConfig::default(),
            nginx: NginxConfig::default(),
            certificates: CertificatesConfig::default(),
            firewall: FirewallRuntimeConfig::default(),
            adguard: AdGuardConfig::default(),
        }
    }
}

impl AppConfig {
    pub fn load(path: &Path) -> Result<Self> {
        if path.exists() {
            let raw = fs::read_to_string(path)
                .with_context(|| format!("failed to read {}", path.display()))?;
            toml::from_str(&raw).with_context(|| format!("failed to parse {}", path.display()))
        } else {
            let mut config = Self::default();
            if path.to_string_lossy().contains("test") || !Path::new("/opt").exists() {
                config.apply_test_mode(path)?;
            }
            Ok(config)
        }
    }

    pub fn apply_test_mode(&mut self, config_path: &Path) -> Result<()> {
        let root = config_path
            .parent()
            .and_then(Path::parent)
            .unwrap_or_else(|| Path::new("."))
            .canonicalize()
            .unwrap_or_else(|_| PathBuf::from("."));
        self.test_mode = true;
        self.server.bind = "127.0.0.1".into();
        self.server.port = 3030;
        self.server.auth_token = "router-hub-test-token".into();
        self.server.allowed_origins = vec!["*".into()];
        self.paths.data_dir = root.join("data");
        self.paths.runtime_dir = root.join("test-fixtures/runtime");
        self.paths.hosts_add = root.join("test-fixtures/hosts.add");
        self.services.init_dir = root.join("test-fixtures/init.d");
        self.services.log_dirs = vec![root.join("test-fixtures/logs")];
        self.nginx.root_dir = root.join("test-fixtures/nginx");
        self.nginx.config_path = root.join("test-fixtures/nginx/nginx.conf");
        self.nginx.pid_path = root.join("test-fixtures/nginx/nginx.pid");
        self.nginx.domains_available_dir = root.join("test-fixtures/nginx/domains-available");
        self.nginx.domains_enabled_dir = root.join("test-fixtures/nginx/domains-enabled");
        self.nginx.templates_dir = root.join("test-fixtures/nginx/templates");
        self.nginx.subdomain_upstream_map_path =
            root.join("test-fixtures/nginx/conf.d/03_subdomain_upstream_map.conf");
        self.nginx.subfolder_upstream_map_path =
            root.join("test-fixtures/nginx/conf.d/04_subfolder_upstream_map.conf");
        self.nginx.http_forwarder_path =
            root.join("test-fixtures/nginx/conf.d/05-http-to-https.conf");
        self.nginx.log_dir = root.join("test-fixtures/logs/nginx");
        self.firewall.log_dirs = vec![root.join("test-fixtures/logs/nginx")];
        self.commands.dehydrated = root.join("test-fixtures/dehydrated/dehydrated");
        self.certificates.certs_dir = root.join("test-fixtures/dehydrated/certs");
        self.asus_ui.enabled = false;
        self.asus_ui.rendered_page = root.join("test-fixtures/router-hub.asp");
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        if self.server.port == 0 {
            bail!("server.port must be greater than zero");
        }
        if !self.test_mode {
            let token = self.server.auth_token.trim();
            if token.len() < 24 || token.contains("CHANGE-ME") || token.contains("REPLACE-WITH") {
                bail!(
                    "server.auth_token must be a non-placeholder value with at least 24 characters outside test mode"
                );
            }
        }
        let _: IpAddr = self
            .server
            .bind
            .parse()
            .context("server.bind must be an IP address")?;
        if self.server.max_request_bytes == 0 {
            bail!("server.max_request_bytes must be greater than zero");
        }
        if self.nginx.log_read_bytes == 0 {
            bail!("nginx.log_read_bytes must be greater than zero");
        }
        if self.certificates.certs_dir.as_os_str().is_empty() {
            bail!("certificates.certs_dir must not be empty");
        }
        if self.certificates.renew_interval_hours == 0
            || self.certificates.command_timeout_seconds == 0
        {
            bail!("certificate renewal interval and command timeout must be greater than zero");
        }
        for (field, value) in [
            ("firewall.set_name_v4", &self.firewall.set_name_v4),
            ("firewall.set_name_v6", &self.firewall.set_name_v6),
        ] {
            if value.is_empty()
                || !value
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric() || "_-".contains(character))
            {
                bail!("{field} contains invalid characters");
            }
        }
        if self.firewall.subnet_prefix_v4 > 32 {
            bail!("firewall.subnet_prefix_v4 must be <= 32");
        }
        if self.firewall.subnet_prefix_v6 > 128 {
            bail!("firewall.subnet_prefix_v6 must be <= 128");
        }
        if self.firewall.max_tracked_ips == 0
            || self.firewall.max_tracked_subnets == 0
            || self.firewall.max_reputation_entries == 0
            || self.firewall.max_active_bans == 0
            || self.firewall.max_status_entries == 0
        {
            bail!("firewall tracking and status capacities must be greater than zero");
        }
        if self.firewall.persist_interval_seconds == 0
            || self.firewall.command_timeout_seconds == 0
            || self.firewall.max_read_bytes_per_file_poll == 0
            || self.firewall.max_lines_per_file_poll == 0
            || self.firewall.max_line_bytes == 0
        {
            bail!("firewall persistence, command, and log limits must be greater than zero");
        }
        let durations = [
            self.firewall.score_retention_days,
            self.firewall.reputation_retention_days,
            self.firewall.subnet_promotion_window_days,
            self.firewall.subnet_ban_days,
            self.firewall.first_ban_days,
            self.firewall.second_ban_days,
            self.firewall.third_ban_days,
            self.firewall.max_ban_days,
        ];
        if durations
            .iter()
            .any(|days| *days == 0 || days.checked_mul(SECONDS_PER_DAY).is_none())
        {
            bail!("firewall retention and ban durations must be valid, non-zero day values");
        }
        if self.firewall.first_ban_days > self.firewall.second_ban_days
            || self.firewall.second_ban_days > self.firewall.third_ban_days
            || self.firewall.third_ban_days > self.firewall.max_ban_days
        {
            bail!("firewall ban durations must be monotonically increasing");
        }
        if self.firewall.log_dirs.is_empty() {
            bail!("firewall.log_dirs must contain at least one allowed root");
        }
        Ok(())
    }

    pub fn ensure_directories(&self) -> Result<()> {
        for path in [
            &self.paths.data_dir,
            &self.paths.runtime_dir,
            &self.certificates.certs_dir,
            &self.certificates.certs_dir.join("certs"),
            &self.certificates.certs_dir.join("acme-challenge"),
            &self.nginx.root_dir,
            &self.nginx.domains_available_dir,
            &self.nginx.domains_enabled_dir,
            &self.nginx.templates_dir.join("domain"),
            &self.nginx.templates_dir.join("subdomain"),
            &self.nginx.templates_dir.join("subfolder"),
            self.nginx
                .subdomain_upstream_map_path
                .parent()
                .unwrap_or(&self.nginx.root_dir),
            self.nginx
                .subfolder_upstream_map_path
                .parent()
                .unwrap_or(&self.nginx.root_dir),
            self.nginx
                .http_forwarder_path
                .parent()
                .unwrap_or(&self.nginx.root_dir),
            &self.nginx.log_dir,
        ] {
            fs::create_dir_all(path)
                .with_context(|| format!("failed to create {}", path.display()))?;
        }
        if let Some(parent) = self.asus_ui.rendered_page.parent() {
            fs::create_dir_all(parent)?;
        }
        Ok(())
    }
}

pub(crate) const SECONDS_PER_DAY: u64 = 86_400;

pub(crate) fn days_to_seconds(days: u64) -> Result<u64> {
    days.checked_mul(SECONDS_PER_DAY)
        .context("duration in days exceeds the supported range")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    pub bind: String,
    pub port: u16,
    pub auth_token: String,
    pub allowed_origins: Vec<String>,
    pub max_request_bytes: usize,
    pub daemonize: bool,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind: "0.0.0.0".into(),
            port: 3030,
            auth_token: "CHANGE-ME-TO-A-LONG-RANDOM-TOKEN".into(),
            allowed_origins: vec!["http://router.asus.com".into(), "http://192.168.1.1".into()],
            max_request_bytes: 1024 * 1024,
            daemonize: true,
        }
    }
}

impl ServerConfig {
    pub fn allowed_origin_values(&self) -> Result<Vec<HeaderValue>> {
        self.allowed_origins
            .iter()
            .map(|value| {
                HeaderValue::from_str(value)
                    .with_context(|| format!("invalid allowed origin: {value}"))
            })
            .collect()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PathsConfig {
    pub data_dir: PathBuf,
    pub runtime_dir: PathBuf,
    pub log_file: PathBuf,
    pub hosts_add: PathBuf,
}

impl Default for PathsConfig {
    fn default() -> Self {
        Self {
            data_dir: "/opt/var/lib/router-hub".into(),
            runtime_dir: "/opt/var/run/router-hub".into(),
            log_file: "/opt/var/log/router-hub.log".into(),
            hosts_add: "/jffs/configs/hosts.add".into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CommandsConfig {
    pub mount: PathBuf,
    pub umount: PathBuf,
    pub nginx: PathBuf,
    pub service: PathBuf,
    pub ipset: PathBuf,
    pub iptables: PathBuf,
    pub ip6tables: PathBuf,
    pub dehydrated: PathBuf,
    pub openssl: PathBuf,
    pub logread: PathBuf,
    pub nvram: PathBuf,
    pub ip: PathBuf,
    pub ping: PathBuf,
}

impl Default for CommandsConfig {
    fn default() -> Self {
        Self {
            mount: "/bin/mount".into(),
            umount: "/bin/umount".into(),
            nginx: "/opt/sbin/nginx".into(),
            service: "/sbin/service".into(),
            ipset: "/opt/sbin/ipset".into(),
            iptables: "/usr/sbin/iptables".into(),
            ip6tables: "/usr/sbin/ip6tables".into(),
            dehydrated: "/opt/var/lib/router-hub/dehydrated/dehydrated".into(),
            openssl: "/usr/sbin/openssl".into(),
            logread: "/opt/sbin/logread".into(),
            nvram: "/bin/nvram".into(),
            ip: "/opt/sbin/ip".into(),
            ping: "/bin/ping".into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AsusUiConfig {
    pub enabled: bool,
    pub rendered_page: PathBuf,
    pub menu_tree: PathBuf,
    pub menu_index: String,
    pub api_base_url: String,
}

impl Default for AsusUiConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            rendered_page: "/tmp/var/wwwext/user20.asp".into(),
            menu_tree: "/www/require/modules/menuTree.js".into(),
            menu_index: "menu_Alexa_IFTTT".into(),
            api_base_url: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ServicesConfig {
    pub init_dir: PathBuf,
    pub log_dirs: Vec<PathBuf>,
    pub status_timeout_seconds: u64,
    pub action_timeout_seconds: u64,
    pub log_tail_lines: usize,
}

impl Default for ServicesConfig {
    fn default() -> Self {
        Self {
            init_dir: "/opt/etc/init.d".into(),
            log_dirs: vec!["/opt/var/log".into(), "/tmp".into()],
            status_timeout_seconds: 5,
            action_timeout_seconds: 30,
            log_tail_lines: 300,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct NginxConfig {
    pub root_dir: PathBuf,
    pub config_path: PathBuf,
    pub pid_path: PathBuf,
    pub domains_available_dir: PathBuf,
    pub domains_enabled_dir: PathBuf,
    pub templates_dir: PathBuf,
    /// Nginx `map $host $subdomain_upstream` include managed by site changes.
    pub subdomain_upstream_map_path: PathBuf,
    /// Nginx subfolder URI/upstream maps managed by site changes.
    pub subfolder_upstream_map_path: PathBuf,
    /// HTTP-to-HTTPS server block generated for enabled domains and subdomains.
    pub http_forwarder_path: PathBuf,
    pub log_dir: PathBuf,
    pub log_read_bytes: usize,
    pub reload_timeout_seconds: u64,
}

impl Default for NginxConfig {
    fn default() -> Self {
        Self {
            root_dir: "/opt/etc/nginx".into(),
            config_path: "/opt/etc/nginx/nginx.conf".into(),
            pid_path: "/opt/var/run/nginx.pid".into(),
            domains_available_dir: "/opt/etc/nginx/domains-available".into(),
            domains_enabled_dir: "/opt/etc/nginx/domains-enabled".into(),
            templates_dir: "/opt/etc/nginx/templates".into(),
            subdomain_upstream_map_path: "/opt/etc/nginx/conf.d/03_subdomain_upstream_map.conf"
                .into(),
            subfolder_upstream_map_path: "/opt/etc/nginx/conf.d/04_subfolder_upstream_map.conf"
                .into(),
            http_forwarder_path: "/opt/etc/nginx/conf.d/05-http-to-https.conf".into(),
            log_dir: "/opt/var/log/nginx".into(),
            log_read_bytes: 512 * 1024,
            reload_timeout_seconds: 15,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CertificatesConfig {
    /// Directory containing one `<name>.cfg` and `<name>.txt` per certificate.
    /// Dehydrated places generated material below its `certs/` child.
    pub certs_dir: PathBuf,
    pub renew_interval_hours: u64,
    pub renew_before_days: i64,
    pub command_timeout_seconds: u64,
}

impl Default for CertificatesConfig {
    fn default() -> Self {
        Self {
            certs_dir: "/opt/var/lib/router-hub/dehydrated/certs".into(),
            renew_interval_hours: 12,
            renew_before_days: 30,
            command_timeout_seconds: 300,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct FirewallRuntimeConfig {
    pub poll_interval_ms: u64,
    pub cleanup_interval_seconds: u64,
    pub set_name_v4: String,
    pub set_name_v6: String,
    pub subnet_prefix_v4: u8,
    pub subnet_prefix_v6: u8,
    pub ip_failures: u64,
    pub subnet_failures: u64,
    pub promote_after_banned_ips: usize,
    pub regex_dfa_cache_bytes: usize,
    pub regex_size_limit_bytes: usize,
    pub reverify_interval_seconds: u64,
    pub protect_input: bool,
    pub protect_forward: bool,
    pub score_retention_days: u64,
    pub reputation_retention_days: u64,
    pub subnet_promotion_window_days: u64,
    pub subnet_ban_days: u64,
    pub first_ban_days: u64,
    pub second_ban_days: u64,
    pub third_ban_days: u64,
    pub max_ban_days: u64,
    pub max_tracked_ips: usize,
    pub max_tracked_subnets: usize,
    pub max_reputation_entries: usize,
    pub max_active_bans: usize,
    pub max_status_entries: usize,
    pub persist_interval_seconds: u64,
    pub command_timeout_seconds: u64,
    pub log_dirs: Vec<PathBuf>,
    pub max_read_bytes_per_file_poll: usize,
    pub max_lines_per_file_poll: usize,
    pub max_line_bytes: usize,
}

impl Default for FirewallRuntimeConfig {
    fn default() -> Self {
        Self {
            poll_interval_ms: 1000,
            cleanup_interval_seconds: 60,
            set_name_v4: "router_hub_bans4".into(),
            set_name_v6: "router_hub_bans6".into(),
            subnet_prefix_v4: 24,
            subnet_prefix_v6: 64,
            ip_failures: 4,
            subnet_failures: 8,
            promote_after_banned_ips: 2,
            regex_dfa_cache_bytes: 2 * 1024 * 1024,
            regex_size_limit_bytes: 1024 * 1024,
            reverify_interval_seconds: 60,
            protect_input: true,
            protect_forward: true,
            score_retention_days: 3,
            reputation_retention_days: 90,
            subnet_promotion_window_days: 3,
            subnet_ban_days: 7,
            first_ban_days: 1,
            second_ban_days: 7,
            third_ban_days: 30,
            max_ban_days: 90,
            max_tracked_ips: 10_000,
            max_tracked_subnets: 2_048,
            max_reputation_entries: 4_096,
            max_active_bans: 8_192,
            max_status_entries: 100,
            persist_interval_seconds: 30,
            command_timeout_seconds: 5,
            log_dirs: vec!["/opt/var/log/nginx".into()],
            max_read_bytes_per_file_poll: 262_144,
            max_lines_per_file_poll: 1_000,
            max_line_bytes: 16_384,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AdGuardConfig {
    pub enabled: bool,
    pub api_endpoint: String,
    pub username: String,
    pub password: String,
    pub lan_ip: String,
}

impl Default for AdGuardConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            api_endpoint: "".into(),
            username: "".into(),
            password: "".into(),
            lan_ip: "192.168.1.1".into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = AppConfig::default();
        assert!(!config.test_mode);
        assert_eq!(config.server.bind, "0.0.0.0");
        assert_eq!(config.server.port, 3030);
        assert_eq!(config.firewall.subnet_prefix_v4, 24);
        assert_eq!(config.firewall.subnet_prefix_v6, 64);
    }

    #[test]
    fn test_apply_test_mode() {
        let mut config = AppConfig::default();
        let dummy_path = Path::new("/some/dir/config.toml");
        config.apply_test_mode(dummy_path).unwrap();

        assert!(config.test_mode);
        assert_eq!(config.server.bind, "127.0.0.1");
        assert_eq!(config.server.port, 3030);
        assert_eq!(config.server.auth_token, "router-hub-test-token");
        assert!(!config.asus_ui.enabled);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_production_token() {
        let mut config = AppConfig {
            test_mode: false,
            ..Default::default()
        };
        config.server.auth_token = "CHANGE-ME-SHORT".into();
        assert!(config.validate().is_err());

        config.server.auth_token = "12345678901234567890123".into(); // 23 chars
        assert!(config.validate().is_err());

        config.server.auth_token = "123456789012345678901234".into(); // 24 chars
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_invalid_ip() {
        let mut config = AppConfig {
            test_mode: true,
            ..Default::default()
        };

        config.server.bind = "invalid-ip".into();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_nginx_log_limit() {
        let mut config = AppConfig {
            test_mode: true,
            ..Default::default()
        };
        config.nginx.log_read_bytes = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_invalid_firewall_set_name() {
        let mut config = AppConfig {
            test_mode: true,
            ..Default::default()
        };
        config.firewall.set_name_v4 = "bad set name!".into();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_invalid_prefixes() {
        let mut config = AppConfig {
            test_mode: true,
            ..Default::default()
        };

        config.firewall.subnet_prefix_v4 = 33;
        assert!(config.validate().is_err());

        config.firewall.subnet_prefix_v4 = 24;
        config.firewall.subnet_prefix_v6 = 129;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_allowed_origin_values() {
        let mut config = AppConfig::default();
        config.server.allowed_origins = vec!["http://example.com".into()];
        let values = config.server.allowed_origin_values().unwrap();
        assert_eq!(values.len(), 1);

        config.server.allowed_origins = vec!["invalid\nheader".into()];
        assert!(config.server.allowed_origin_values().is_err());
    }
}
