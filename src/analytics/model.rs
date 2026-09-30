use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AnalyticsSettings {
    pub enabled: bool,
    pub sample_interval_seconds: u64,
    pub kernel_verify_interval_seconds: u64,
    pub rollup_interval_minutes: u64,
    pub hourly_retention_days: u64,
    pub daily_retention_days: u64,
    pub detect_issues: bool,
    pub collect_kernel_counters: bool,
    pub collect_event_samples: bool,
    pub max_samples_per_hour: usize,
    pub max_sample_path_bytes: usize,
    pub max_summary_bytes: usize,
    pub ai: AiSettings,
}

impl Default for AnalyticsSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            sample_interval_seconds: 300,
            kernel_verify_interval_seconds: 7200,
            rollup_interval_minutes: 60,
            hourly_retention_days: 14,
            daily_retention_days: 90,
            detect_issues: true,
            collect_kernel_counters: true,
            collect_event_samples: true,
            max_samples_per_hour: 32,
            max_sample_path_bytes: 256,
            max_summary_bytes: 65_536,
            ai: AiSettings::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AiSettings {
    pub enabled: bool,
    pub automatic: bool,
    pub endpoint: String,
    pub api_key: String,
    pub model: String,
    pub interval_hours: u64,
    pub privacy_mode: String,
    pub max_payload_bytes: usize,
    pub max_samples: usize,
    pub max_output_tokens: u32,
    pub timeout_seconds: u64,
    pub additional_headers: BTreeMap<String, String>,
}

impl Default for AiSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            automatic: false,
            endpoint: String::new(),
            api_key: String::new(),
            model: String::new(),
            interval_hours: 24,
            privacy_mode: "strict".to_owned(),
            max_payload_bytes: 32_768,
            max_samples: 50,
            max_output_tokens: 1200,
            timeout_seconds: 30,
            additional_headers: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct AnalyticsSettingsView {
    pub enabled: bool,
    pub sample_interval_seconds: u64,
    pub kernel_verify_interval_seconds: u64,
    pub rollup_interval_minutes: u64,
    pub hourly_retention_days: u64,
    pub daily_retention_days: u64,
    pub detect_issues: bool,
    pub collect_kernel_counters: bool,
    pub collect_event_samples: bool,
    pub max_samples_per_hour: usize,
    pub max_sample_path_bytes: usize,
    pub max_summary_bytes: usize,
    pub ai: AiSettingsView,
}

impl From<&AnalyticsSettings> for AnalyticsSettingsView {
    fn from(settings: &AnalyticsSettings) -> Self {
        Self {
            enabled: settings.enabled,
            sample_interval_seconds: settings.sample_interval_seconds,
            kernel_verify_interval_seconds: settings.kernel_verify_interval_seconds,
            rollup_interval_minutes: settings.rollup_interval_minutes,
            hourly_retention_days: settings.hourly_retention_days,
            daily_retention_days: settings.daily_retention_days,
            detect_issues: settings.detect_issues,
            collect_kernel_counters: settings.collect_kernel_counters,
            collect_event_samples: settings.collect_event_samples,
            max_samples_per_hour: settings.max_samples_per_hour,
            max_sample_path_bytes: settings.max_sample_path_bytes,
            max_summary_bytes: settings.max_summary_bytes,
            ai: AiSettingsView::from(&settings.ai),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct AiSettingsView {
    pub enabled: bool,
    pub automatic: bool,
    pub endpoint: String,
    pub api_key_configured: bool,
    pub model: String,
    pub interval_hours: u64,
    pub privacy_mode: String,
    pub max_payload_bytes: usize,
    pub max_samples: usize,
    pub max_output_tokens: u32,
    pub timeout_seconds: u64,
    pub additional_headers: BTreeMap<String, String>,
}

impl From<&AiSettings> for AiSettingsView {
    fn from(settings: &AiSettings) -> Self {
        Self {
            enabled: settings.enabled,
            automatic: settings.automatic,
            endpoint: settings.endpoint.clone(),
            api_key_configured: !settings.api_key.is_empty(),
            model: settings.model.clone(),
            interval_hours: settings.interval_hours,
            privacy_mode: settings.privacy_mode.clone(),
            max_payload_bytes: settings.max_payload_bytes,
            max_samples: settings.max_samples,
            max_output_tokens: settings.max_output_tokens,
            timeout_seconds: settings.timeout_seconds,
            additional_headers: settings.additional_headers.clone(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct AnalyticsSettingsUpdate {
    pub enabled: bool,
    pub sample_interval_seconds: u64,
    pub kernel_verify_interval_seconds: u64,
    pub rollup_interval_minutes: u64,
    pub hourly_retention_days: u64,
    pub daily_retention_days: u64,
    pub detect_issues: bool,
    pub collect_kernel_counters: bool,
    pub collect_event_samples: bool,
    pub max_samples_per_hour: usize,
    pub max_sample_path_bytes: usize,
    pub max_summary_bytes: usize,
    pub ai: AiSettingsUpdate,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AiSettingsUpdate {
    pub enabled: bool,
    pub automatic: bool,
    pub endpoint: String,
    #[serde(default)]
    pub api_key: Option<String>,
    #[serde(default)]
    pub clear_api_key: bool,
    pub model: String,
    pub interval_hours: u64,
    pub privacy_mode: String,
    pub max_payload_bytes: usize,
    pub max_samples: usize,
    pub max_output_tokens: u32,
    pub timeout_seconds: u64,
    #[serde(default)]
    pub additional_headers: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RuleActivity {
    pub name: String,
    pub matches: u64,
    pub ban_transitions: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SanitizedSample {
    pub source: String,
    pub rule: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AnalyticsFinding {
    pub severity: String,
    pub category: String,
    pub title: String,
    #[serde(default)]
    pub evidence: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recommendation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f32>,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyticsRollup {
    pub period_start: DateTime<Utc>,
    pub period_end: DateTime<Utc>,
    pub input_packets_blocked: u64,
    pub input_bytes_blocked: u64,
    pub forward_packets_blocked: u64,
    pub forward_bytes_blocked: u64,
    pub new_ip_bans: u64,
    pub new_subnet_bans: u64,
    pub expired_bans: u64,
    pub subnet_promotions: u64,
    pub active_ip_bans: usize,
    pub active_subnet_bans: usize,
    pub repeat_offender_bans: usize,
    pub engine_errors: u64,
    pub command_timeouts: u64,
    pub dropped_lines: u64,
    pub evictions: u64,
    pub kernel_state_consistent: Option<bool>,
    pub rule_activity: Vec<RuleActivity>,
    pub findings: Vec<AnalyticsFinding>,
    pub analytics_event_drops: u64,
    pub samples: Vec<SanitizedSample>,
}

impl AnalyticsRollup {
    pub fn empty(period_start: DateTime<Utc>, period_end: DateTime<Utc>) -> Self {
        Self {
            period_start,
            period_end,
            input_packets_blocked: 0,
            input_bytes_blocked: 0,
            forward_packets_blocked: 0,
            forward_bytes_blocked: 0,
            new_ip_bans: 0,
            new_subnet_bans: 0,
            expired_bans: 0,
            subnet_promotions: 0,
            active_ip_bans: 0,
            active_subnet_bans: 0,
            repeat_offender_bans: 0,
            engine_errors: 0,
            command_timeouts: 0,
            dropped_lines: 0,
            evictions: 0,
            kernel_state_consistent: None,
            rule_activity: Vec::new(),
            findings: Vec::new(),
            analytics_event_drops: 0,
            samples: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiFinding {
    pub severity: String,
    pub category: String,
    pub title: String,
    #[serde(default)]
    pub evidence: Vec<String>,
    pub recommendation: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiAnalysis {
    pub summary: String,
    #[serde(default)]
    pub findings: Vec<AiFinding>,
    #[serde(default)]
    pub policy_suggestions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiAnalysisRecord {
    pub created_at: DateTime<Utc>,
    pub model: String,
    pub analysis: AiAnalysis,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyticsHistory {
    #[serde(default = "history_schema_version")]
    pub schema_version: u32,
    #[serde(default)]
    pub hourly: Vec<AnalyticsRollup>,
    #[serde(default)]
    pub daily: Vec<AnalyticsRollup>,
    #[serde(default)]
    pub ai: Vec<AiAnalysisRecord>,
}

impl Default for AnalyticsHistory {
    fn default() -> Self {
        Self {
            schema_version: history_schema_version(),
            hourly: Vec::new(),
            daily: Vec::new(),
            ai: Vec::new(),
        }
    }
}

fn history_schema_version() -> u32 {
    1
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AnalyticsOverhead {
    pub processing_micros: u64,
    pub estimated_memory_bytes: usize,
    pub disk_bytes_written: u64,
    pub external_commands: u64,
    pub ai_requests_attempted: u64,
    pub ai_requests_succeeded: u64,
    pub ai_requests_failed: u64,
    pub ai_bytes_sent: u64,
    pub ai_bytes_received: u64,
    pub samples_dropped: u64,
    pub last_rollup_micros: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct AnalyticsStatus {
    pub enabled: bool,
    pub ai_enabled: bool,
    pub queue_capacity: usize,
    pub current_period_start: DateTime<Utc>,
    pub last_rollup_at: Option<DateTime<Utc>>,
    pub last_kernel_verify_at: Option<DateTime<Utc>>,
    pub last_ai_analysis_at: Option<DateTime<Utc>>,
    pub last_24h: AnalyticsRollup,
    pub findings: Vec<AnalyticsFinding>,
    pub overhead: AnalyticsOverhead,
}

#[derive(Debug, Clone, Serialize)]
pub struct AiPreview {
    pub privacy_mode: String,
    pub bytes: usize,
    pub payload: serde_json::Value,
}
