use std::{collections::BTreeMap, path::PathBuf};

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::ban_attack::Error;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default = "default_poll_interval_ms")]
    pub poll_interval_ms: u64,

    #[serde(default = "default_dfa_cache_bytes")]
    pub regex_dfa_cache_bytes: usize,

    #[serde(default = "default_regex_size_limit_bytes")]
    pub regex_size_limit_bytes: usize,

    #[serde(default)]
    pub test_mode: bool,

    #[serde(default)]
    pub persistence_file: Option<PathBuf>,

    #[serde(default = "default_persist_interval_seconds")]
    pub persist_interval_seconds: u64,

    #[serde(default = "default_cleanup_interval_seconds")]
    pub cleanup_interval_seconds: u64,

    #[serde(default = "default_max_status_entries")]
    pub max_status_entries: usize,

    #[serde(default = "default_command_queue_capacity")]
    pub command_queue_capacity: usize,

    #[serde(default = "default_command_timeout_seconds")]
    pub command_timeout_seconds: u64,

    #[serde(default = "default_log_dirs")]
    pub log_dirs: Vec<PathBuf>,

    #[serde(default = "default_max_read_bytes_per_file_poll")]
    pub max_read_bytes_per_file_poll: usize,

    #[serde(default = "default_max_lines_per_file_poll")]
    pub max_lines_per_file_poll: usize,

    #[serde(default = "default_max_line_bytes")]
    pub max_line_bytes: usize,

    #[serde(default)]
    pub firewall: FirewallConfig,

    #[serde(default)]
    pub aggregation: AggregationConfig,

    #[serde(default)]
    pub ipset: IpSetConfig,

    #[serde(default)]
    pub exceptions: Vec<IpNet>,

    pub files: Vec<FileConfig>,
}

impl Config {
    #[allow(dead_code)]
    pub fn from_toml(input: &str) -> Result<Self, Error> {
        toml::from_str(input).map_err(|error| Error::Config(error.to_string()))
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FirewallConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,

    #[serde(default)]
    pub observe_only: bool,

    #[serde(default = "default_iptables_command")]
    pub iptables_command: PathBuf,

    #[serde(default = "default_ip6tables_command")]
    pub ip6tables_command: PathBuf,

    #[serde(default = "default_true")]
    pub protect_input: bool,

    #[serde(default = "default_true")]
    pub protect_forward: bool,

    #[serde(default = "default_reverify_interval_seconds")]
    pub reverify_interval_seconds: u64,

    #[serde(default = "default_command_timeout_seconds")]
    pub command_timeout_seconds: u64,
}

impl Default for FirewallConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            observe_only: false,
            iptables_command: default_iptables_command(),
            ip6tables_command: default_ip6tables_command(),
            protect_input: true,
            protect_forward: true,
            reverify_interval_seconds: default_reverify_interval_seconds(),
            command_timeout_seconds: default_command_timeout_seconds(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AggregationConfig {
    #[serde(default = "default_ip_failures")]
    pub ip_failures: u64,

    #[serde(default = "default_subnet_failures")]
    pub subnet_failures: u64,

    #[serde(default = "default_promote_after_banned_ips")]
    pub promote_after_banned_ips: usize,

    #[serde(default = "default_ipv4_prefix")]
    pub ipv4_prefix: u8,

    #[serde(default = "default_ipv6_prefix")]
    pub ipv6_prefix: u8,

    #[serde(default = "default_score_retention_seconds")]
    pub score_retention_seconds: u64,

    #[serde(default = "default_reputation_retention_seconds")]
    pub reputation_retention_seconds: u64,

    #[serde(default = "default_subnet_promotion_window_seconds")]
    pub subnet_promotion_window_seconds: u64,

    #[serde(default = "default_subnet_ban_seconds")]
    pub subnet_ban_seconds: u64,

    #[serde(default = "default_first_ban_seconds")]
    pub first_ban_seconds: u64,

    #[serde(default = "default_second_ban_seconds")]
    pub second_ban_seconds: u64,

    #[serde(default = "default_third_ban_seconds")]
    pub third_ban_seconds: u64,

    #[serde(default = "default_max_ban_seconds")]
    pub max_ban_seconds: u64,

    #[serde(default = "default_max_tracked_ips")]
    pub max_tracked_ips: usize,

    #[serde(default = "default_max_tracked_subnets")]
    pub max_tracked_subnets: usize,

    #[serde(default = "default_max_reputation_entries")]
    pub max_reputation_entries: usize,

    #[serde(default = "default_max_active_bans")]
    pub max_active_bans: usize,
}

impl Default for AggregationConfig {
    fn default() -> Self {
        Self {
            ip_failures: default_ip_failures(),
            subnet_failures: default_subnet_failures(),
            promote_after_banned_ips: default_promote_after_banned_ips(),
            ipv4_prefix: default_ipv4_prefix(),
            ipv6_prefix: default_ipv6_prefix(),
            score_retention_seconds: default_score_retention_seconds(),
            reputation_retention_seconds: default_reputation_retention_seconds(),
            subnet_promotion_window_seconds: default_subnet_promotion_window_seconds(),
            subnet_ban_seconds: default_subnet_ban_seconds(),
            first_ban_seconds: default_first_ban_seconds(),
            second_ban_seconds: default_second_ban_seconds(),
            third_ban_seconds: default_third_ban_seconds(),
            max_ban_seconds: default_max_ban_seconds(),
            max_tracked_ips: default_max_tracked_ips(),
            max_tracked_subnets: default_max_tracked_subnets(),
            max_reputation_entries: default_max_reputation_entries(),
            max_active_bans: default_max_active_bans(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IpSetConfig {
    #[serde(default = "default_ipset_command")]
    pub command: PathBuf,

    #[serde(default = "default_v4_set")]
    pub v4_set: String,

    #[serde(default = "default_v6_set")]
    pub v6_set: String,

    #[serde(default = "default_max_entries")]
    pub max_entries: usize,
}

impl Default for IpSetConfig {
    fn default() -> Self {
        Self {
            command: default_ipset_command(),
            v4_set: default_v4_set(),
            v6_set: default_v6_set(),
            max_entries: default_max_entries(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FileConfig {
    pub path: PathBuf,

    #[serde(default)]
    pub start_at: StartAt,

    pub rules: Vec<RuleConfig>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum StartAt {
    Beginning,
    #[default]
    End,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuleConfig {
    pub name: String,
    pub regex: String,

    #[serde(default = "default_ip_group")]
    pub ip_group: String,

    #[serde(default)]
    pub group_values: BTreeMap<String, Vec<String>>,

    #[serde(default = "default_weight")]
    pub weight: u64,
}

fn default_poll_interval_ms() -> u64 {
    250
}

fn default_persist_interval_seconds() -> u64 {
    30
}
fn default_cleanup_interval_seconds() -> u64 {
    60
}
fn default_max_status_entries() -> usize {
    100
}
fn default_command_queue_capacity() -> usize {
    128
}
fn default_command_timeout_seconds() -> u64 {
    5
}
fn default_log_dirs() -> Vec<PathBuf> {
    vec![PathBuf::from("/opt/var/log/nginx")]
}
fn default_max_read_bytes_per_file_poll() -> usize {
    262_144
}
fn default_max_lines_per_file_poll() -> usize {
    1_000
}
fn default_max_line_bytes() -> usize {
    16_384
}

fn default_dfa_cache_bytes() -> usize {
    2 * 1024 * 1024
}

fn default_regex_size_limit_bytes() -> usize {
    1024 * 1024
}

fn default_true() -> bool {
    true
}

fn default_iptables_command() -> PathBuf {
    PathBuf::from("/usr/sbin/iptables")
}

fn default_ip6tables_command() -> PathBuf {
    PathBuf::from("/usr/sbin/ip6tables")
}

fn default_ip_failures() -> u64 {
    4
}

fn default_subnet_failures() -> u64 {
    8
}

fn default_promote_after_banned_ips() -> usize {
    2
}

fn default_ipv4_prefix() -> u8 {
    24
}

fn default_ipv6_prefix() -> u8 {
    64
}

fn default_score_retention_seconds() -> u64 {
    259_200
}
fn default_reputation_retention_seconds() -> u64 {
    7_776_000
}
fn default_subnet_promotion_window_seconds() -> u64 {
    259_200
}
fn default_subnet_ban_seconds() -> u64 {
    604_800
}
fn default_first_ban_seconds() -> u64 {
    86_400
}
fn default_second_ban_seconds() -> u64 {
    604_800
}
fn default_third_ban_seconds() -> u64 {
    2_592_000
}
fn default_max_ban_seconds() -> u64 {
    7_776_000
}
fn default_max_tracked_ips() -> usize {
    10_000
}
fn default_max_tracked_subnets() -> usize {
    2_048
}
fn default_max_reputation_entries() -> usize {
    4_096
}
fn default_max_active_bans() -> usize {
    8_192
}

fn default_ipset_command() -> PathBuf {
    PathBuf::from("/usr/sbin/ipset")
}

fn default_v4_set() -> String {
    "ban_attack_v4".to_owned()
}

fn default_v6_set() -> String {
    "ban_attack_v6".to_owned()
}

fn default_max_entries() -> usize {
    65_536
}

fn default_ip_group() -> String {
    "ip".to_owned()
}

fn default_weight() -> u64 {
    1
}

fn default_reverify_interval_seconds() -> u64 {
    60
}
