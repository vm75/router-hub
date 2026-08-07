use std::{collections::BTreeMap, net::IpAddr, path::PathBuf};

use chrono::{DateTime, Utc};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::ban_attack::{EngineHealth, Snapshot};

fn utc_now() -> DateTime<Utc> {
    Utc::now()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NginxObjectKind {
    Domain,
    Subdomain,
    Subfolder,
}

impl NginxObjectKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Domain => "domain",
            Self::Subdomain => "subdomain",
            Self::Subfolder => "subfolder",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NginxObject {
    pub kind: NginxObjectKind,
    pub domain: String,
    pub name: String,
    pub display_name: String,
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    pub enabled: bool,
    pub running: bool,
    #[serde(default)]
    pub state: String,
    pub modified: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NginxTemplateEntry {
    pub kind: NginxObjectKind,
    pub name: String,
    pub size: u64,
    pub modified: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NginxLogEntry {
    pub path: String,
    pub size: u64,
    pub modified: Option<DateTime<Utc>>,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CertificateMethod {
    Http,
    Dns,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateSpec {
    #[serde(default = "Uuid::new_v4")]
    pub id: Uuid,
    pub name: String,
    pub domains: Vec<String>,
    pub method: CertificateMethod,
    #[serde(default)]
    pub hook: Option<PathBuf>,
    #[serde(default)]
    pub hook_env: BTreeMap<String, String>,
    #[serde(default)]
    pub staging: bool,
    #[serde(default = "default_true")]
    pub auto_renew: bool,
    #[serde(default = "utc_now")]
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateStatus {
    pub spec: CertificateSpec,
    pub fullchain_path: PathBuf,
    pub exists: bool,
    pub expires_at: Option<DateTime<Utc>>,
    pub days_remaining: Option<i64>,
    pub renewal_due: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DehydratedLockStatus {
    pub locked: bool,
    pub path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DehydratedUpdate {
    pub path: PathBuf,
    pub source: String,
    pub bytes: usize,
    pub simulated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WolMachine {
    #[serde(default = "Uuid::new_v4")]
    pub id: Uuid,
    pub name: String,
    pub mac: String,
    #[serde(default = "default_broadcast")]
    pub broadcast: IpAddr,
    #[serde(default = "default_wol_port")]
    pub port: u16,
    #[serde(default)]
    pub notes: String,
    #[serde(default = "utc_now")]
    pub updated_at: DateTime<Utc>,
}

fn default_broadcast() -> IpAddr {
    "255.255.255.255".parse().expect("valid broadcast")
}
fn default_wol_port() -> u16 {
    9
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BanRule {
    #[serde(default = "Uuid::new_v4")]
    pub id: Uuid,
    pub name: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub log_paths: Vec<PathBuf>,
    #[serde(alias = "regex")]
    pub pattern: String,
    #[serde(default = "default_attempts")]
    pub attempts: usize,
    #[serde(default = "default_ip_group")]
    pub ip_group: String,
    #[serde(default)]
    pub group_values: BTreeMap<String, Vec<String>>,
    #[serde(default = "default_weight")]
    pub weight: u64,
    #[serde(default = "utc_now")]
    pub updated_at: DateTime<Utc>,
}

fn default_attempts() -> usize {
    5
}
fn default_ip_group() -> String {
    "ip".into()
}
fn default_weight() -> u64 {
    1
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FirewallTuning {
    pub ip_failures: u64,
    pub subnet_failures: u64,
    pub promote_after_banned_ips: usize,
    pub reputation_repromote_after_offenses: u32,
    pub score_retention_days: u64,
    pub reputation_retention_days: u64,
    pub subnet_promotion_window_days: u64,
    pub subnet_ban_days: u64,
    pub first_ban_days: u64,
    pub second_ban_days: u64,
    pub third_ban_days: u64,
    pub max_ban_days: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FirewallPolicy {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub observe_only: bool,
    #[serde(default)]
    pub rules: Vec<BanRule>,
    #[serde(default)]
    pub allowlist: Vec<IpNet>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tuning: Option<FirewallTuning>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BanRecord {
    pub network: IpNet,
    pub reason: String,
    pub rule_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    #[serde(default)]
    pub hit_count: usize,
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub offense_count: u32,
    #[serde(default)]
    pub triggering_rule: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInfo {
    pub name: String,
    pub enabled: bool,
    pub path: PathBuf,
    pub running: bool,
    pub status_code: Option<i32>,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandResult {
    pub success: bool,
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub simulated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dashboard {
    pub version: String,
    pub test_mode: bool,
    pub services_total: usize,
    pub services_running: usize,
    pub nginx_running: bool,
    pub nginx_objects: usize,
    pub certificates: usize,
    pub certificates_due: usize,
    pub wol_machines: usize,
    pub active_bans: usize,
    pub active_ip_bans: usize,
    pub active_subnet_bans: usize,
    pub firewall_enabled: bool,
    pub firewall_health: EngineHealth,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeInfo {
    pub version: String,
    pub api_base_url: String,
    pub token_hint: String,
    pub test_mode: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NginxFileEntry {
    pub path: String,
    pub size: u64,
    pub modified: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallStatus {
    pub policy: FirewallPolicy,
    pub snapshot: Snapshot,
    #[serde(default)]
    pub bans: Vec<BanRecord>,
    pub health: EngineHealth,
    pub settings: FirewallSettings,
    pub tuning: FirewallTuning,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallSettings {
    pub global_threshold: u64,
    pub score_retention_seconds: u64,
    pub escalation_seconds: [u64; 4],
    pub subnet_promotion_window_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiMessage {
    pub message: String,
}

impl ApiMessage {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}
