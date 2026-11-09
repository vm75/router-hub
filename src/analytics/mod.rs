mod ai;
pub mod model;
mod privacy;

use std::{
    collections::{BTreeMap, HashSet},
    fs::OpenOptions,
    io::Write,
    net::IpAddr,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Datelike, TimeZone, Utc};
use parking_lot::Mutex as ParkingMutex;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex, Notify, RwLock, mpsc};
use tracing::warn;
use uuid::Uuid;

use crate::{
    ban_attack::{BanTarget, EngineEvent, EngineState},
    command::CommandRunner,
    config::AppConfig,
    firewall::FirewallManager,
    models::FirewallStatus,
};

use self::{
    model::{
        AiAnalysisRecord, AiPreview, AnalyticsFinding, AnalyticsHistory, AnalyticsOverhead,
        AnalyticsRollup, AnalyticsSettings, AnalyticsSettingsUpdate, AnalyticsSettingsView,
        AnalyticsStatus, RuleActivity, SanitizedSample,
    },
    privacy::{
        hex_decode_32, hex_encode, parse_request_line, pseudonymize_ip, sanitize_method,
        sanitize_path, sanitize_rule_name, sanitize_status,
    },
};

pub const EVENT_QUEUE_CAPACITY: usize = 128;
const HISTORY_SCHEMA_VERSION: u32 = 1;
const HISTORY_MEMORY_BUDGET_BYTES: usize = 768 * 1024;
const MAX_FINDINGS_PER_ROLLUP: usize = 32;
const MAX_AI_RECORDS: usize = 30;

static GLOBAL: OnceLock<Arc<AnalyticsManager>> = OnceLock::new();
static INGRESS: OnceLock<AnalyticsIngress> = OnceLock::new();

#[derive(Clone)]
struct AnalyticsIngress {
    enabled: Arc<AtomicBool>,
    collect_samples: Arc<AtomicBool>,
    dropped: Arc<AtomicU64>,
    sender: mpsc::Sender<InternalEvent>,
}

#[derive(Debug)]
enum InternalEvent {
    Match {
        rule: String,
        ip: IpAddr,
        method: Option<String>,
        path: Option<String>,
        status: Option<String>,
    },
    Banned {
        subnet: bool,
    },
    Promoted,
    Unbanned,
}

#[derive(Clone)]
struct Accumulator {
    period_start: DateTime<Utc>,
    input_packets_blocked: u64,
    input_bytes_blocked: u64,
    forward_packets_blocked: u64,
    forward_bytes_blocked: u64,
    new_ip_bans: u64,
    new_subnet_bans: u64,
    expired_bans: u64,
    subnet_promotions: u64,
    active_ip_bans: usize,
    active_subnet_bans: usize,
    repeat_offender_bans: usize,
    engine_errors: u64,
    command_timeouts: u64,
    dropped_lines: u64,
    evictions: u64,
    kernel_state_consistent: Option<bool>,
    rules: BTreeMap<String, (u64, u64)>,
    findings: Vec<AnalyticsFinding>,
    samples: Vec<SanitizedSample>,
}

impl Accumulator {
    fn new(now: DateTime<Utc>) -> Self {
        Self {
            period_start: now,
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
            rules: BTreeMap::new(),
            findings: Vec::new(),
            samples: Vec::new(),
        }
    }

    fn to_rollup(&self, end: DateTime<Utc>, event_drops: u64) -> AnalyticsRollup {
        AnalyticsRollup {
            period_start: self.period_start,
            period_end: end,
            input_packets_blocked: self.input_packets_blocked,
            input_bytes_blocked: self.input_bytes_blocked,
            forward_packets_blocked: self.forward_packets_blocked,
            forward_bytes_blocked: self.forward_bytes_blocked,
            new_ip_bans: self.new_ip_bans,
            new_subnet_bans: self.new_subnet_bans,
            expired_bans: self.expired_bans,
            subnet_promotions: self.subnet_promotions,
            active_ip_bans: self.active_ip_bans,
            active_subnet_bans: self.active_subnet_bans,
            repeat_offender_bans: self.repeat_offender_bans,
            engine_errors: self.engine_errors,
            command_timeouts: self.command_timeouts,
            dropped_lines: self.dropped_lines,
            evictions: self.evictions,
            kernel_state_consistent: self.kernel_state_consistent,
            rule_activity: self
                .rules
                .iter()
                .map(|(name, (matches, bans))| RuleActivity {
                    name: name.clone(),
                    matches: *matches,
                    ban_transitions: *bans,
                })
                .collect(),
            findings: self.findings.clone(),
            analytics_event_drops: event_drops,
            samples: self.samples.clone(),
        }
    }
}

struct StatusBaseline {
    rule_stats: BTreeMap<String, (u64, u64)>,
    error_count: u64,
    command_timeout_count: u64,
    dropped_line_count: u64,
    eviction_count: u64,
}

#[derive(Clone, Copy, Default)]
struct CounterPair {
    packets: u64,
    bytes: u64,
}

#[derive(Clone, Copy, Default)]
struct KernelCounters {
    input_v4: Option<CounterPair>,
    input_v6: Option<CounterPair>,
    forward_v4: Option<CounterPair>,
    forward_v6: Option<CounterPair>,
}

pub struct AnalyticsManager {
    config: Arc<AppConfig>,
    settings: RwLock<AnalyticsSettings>,
    accumulator: ParkingMutex<Accumulator>,
    history: RwLock<AnalyticsHistory>,
    overhead: ParkingMutex<AnalyticsOverhead>,
    baseline: Mutex<Option<StatusBaseline>>,
    last_kernel_counters: Mutex<Option<KernelCounters>>,
    enabled: Arc<AtomicBool>,
    collect_samples: Arc<AtomicBool>,
    dropped_events: Arc<AtomicU64>,
    privacy_key: [u8; 32],
    notify: Notify,
    ai_lock: Mutex<()>,
    last_rollup_at: RwLock<Option<DateTime<Utc>>>,
    last_kernel_verify_at: RwLock<Option<DateTime<Utc>>>,
    last_ai_analysis_at: RwLock<Option<DateTime<Utc>>>,
    settings_path: PathBuf,
    history_path: PathBuf,
}

impl AnalyticsManager {
    pub async fn initialize(config: AppConfig) -> Result<Arc<Self>> {
        let settings_path = config.paths.data_dir.join("analytics-settings.json");
        let history_path = config.paths.data_dir.join("analytics-history.json");
        let key_path = config.paths.data_dir.join("analytics-pseudonym.key");

        let mut settings = load_json::<AnalyticsSettings>(&settings_path).unwrap_or_else(|error| {
            warn!(%error, "unable to load analytics settings; analytics remains disabled");
            AnalyticsSettings::default()
        });
        if let Err(error) = validate_settings(&settings, config.test_mode) {
            warn!(%error, "invalid analytics settings; analytics remains disabled");
            settings = AnalyticsSettings::default();
        }
        let history = load_json::<AnalyticsHistory>(&history_path).unwrap_or_else(|error| {
            warn!(%error, "unable to load analytics history; starting with empty history");
            AnalyticsHistory::default()
        });
        let privacy_key = load_or_create_privacy_key(&key_path, &config.server.auth_token)?;
        let enabled = Arc::new(AtomicBool::new(settings.enabled));
        let collect_samples = Arc::new(AtomicBool::new(
            settings.enabled && settings.collect_event_samples,
        ));
        let dropped_events = Arc::new(AtomicU64::new(0));
        let (sender, receiver) = mpsc::channel(EVENT_QUEUE_CAPACITY);

        let manager = Arc::new(Self {
            config: Arc::new(config),
            settings: RwLock::new(settings),
            accumulator: ParkingMutex::new(Accumulator::new(Utc::now())),
            history: RwLock::new(history),
            overhead: ParkingMutex::new(AnalyticsOverhead::default()),
            baseline: Mutex::new(None),
            last_kernel_counters: Mutex::new(None),
            enabled: enabled.clone(),
            collect_samples: collect_samples.clone(),
            dropped_events: dropped_events.clone(),
            privacy_key,
            notify: Notify::new(),
            ai_lock: Mutex::new(()),
            last_rollup_at: RwLock::new(None),
            last_kernel_verify_at: RwLock::new(None),
            last_ai_analysis_at: RwLock::new(None),
            settings_path,
            history_path,
        });

        let ingress = AnalyticsIngress {
            enabled,
            collect_samples,
            dropped: dropped_events,
            sender,
        };
        let _ = INGRESS.set(ingress);
        let _ = GLOBAL.set(manager.clone());
        manager.clone().start_event_consumer(receiver);
        Ok(manager)
    }

    pub fn start(self: &Arc<Self>, firewall: FirewallManager) {
        let manager = self.clone();
        tokio::spawn(async move {
            manager.run_periodic(firewall).await;
        });
    }

    fn start_event_consumer(self: Arc<Self>, mut receiver: mpsc::Receiver<InternalEvent>) {
        tokio::spawn(async move {
            while let Some(event) = receiver.recv().await {
                let started = Instant::now();
                self.consume_event(event).await;
                self.add_processing_time(started.elapsed());
            }
        });
    }

    async fn consume_event(&self, event: InternalEvent) {
        if !self.enabled.load(Ordering::Relaxed) {
            return;
        }
        match event {
            InternalEvent::Match {
                rule,
                ip,
                method,
                path,
                status,
            } => {
                if !self.collect_samples.load(Ordering::Relaxed) {
                    return;
                }
                let settings = self.settings.read().await.clone();
                let mut accumulator = self.accumulator.lock();
                if accumulator.samples.len() >= settings.max_samples_per_hour {
                    let mut overhead = self.overhead.lock();
                    overhead.samples_dropped = overhead.samples_dropped.saturating_add(1);
                    return;
                }
                accumulator.samples.push(SanitizedSample {
                    source: pseudonymize_ip(&self.privacy_key, ip),
                    rule: sanitize_rule_name(&self.privacy_key, &rule),
                    method: sanitize_method(method.as_deref()),
                    path: sanitize_path(path.as_deref(), settings.max_sample_path_bytes),
                    status: sanitize_status(status.as_deref()),
                });
            }
            InternalEvent::Banned { subnet } => {
                let mut accumulator = self.accumulator.lock();
                if subnet {
                    accumulator.new_subnet_bans = accumulator.new_subnet_bans.saturating_add(1);
                } else {
                    accumulator.new_ip_bans = accumulator.new_ip_bans.saturating_add(1);
                }
            }
            InternalEvent::Promoted => {
                let mut accumulator = self.accumulator.lock();
                accumulator.new_subnet_bans = accumulator.new_subnet_bans.saturating_add(1);
                accumulator.subnet_promotions = accumulator.subnet_promotions.saturating_add(1);
            }
            InternalEvent::Unbanned => {
                let mut accumulator = self.accumulator.lock();
                accumulator.expired_bans = accumulator.expired_bans.saturating_add(1);
            }
        }
    }

    async fn run_periodic(self: Arc<Self>, firewall: FirewallManager) {
        let mut last_sample = Instant::now()
            .checked_sub(Duration::from_secs(24 * 3600))
            .unwrap_or_else(Instant::now);
        let mut last_kernel = Instant::now();
        let mut last_rollup = Instant::now();
        let mut last_ai = Instant::now();

        loop {
            let settings = self.settings.read().await.clone();
            if !settings.enabled {
                *self.baseline.lock().await = None;
                *self.last_kernel_counters.lock().await = None;
                self.notify.notified().await;
                continue;
            }

            let started = Instant::now();
            if last_sample.elapsed() >= Duration::from_secs(settings.sample_interval_seconds) {
                let status = firewall.status().await;
                self.sample_firewall(&status, settings.detect_issues).await;
                last_sample = Instant::now();
            }

            if settings.collect_kernel_counters
                && last_kernel.elapsed()
                    >= Duration::from_secs(settings.kernel_verify_interval_seconds)
            {
                let status = firewall.status().await;
                if let Err(error) = self.verify_kernel(&status).await {
                    self.add_finding(AnalyticsFinding {
                        severity: "critical".into(),
                        category: "enforcement".into(),
                        title: "Kernel enforcement verification failed".into(),
                        evidence: vec!["Router Hub could not verify its owned firewall/ipset state".into()],
                        recommendation: Some("Inspect Ban Shield health and run firewall reconciliation before relying on the affected enforcement path.".into()),
                        confidence: None,
                        source: "local".into(),
                    });
                    warn!(%error, "analytics kernel verification failed");
                }
                last_kernel = Instant::now();
                *self.last_kernel_verify_at.write().await = Some(Utc::now());
            }

            if last_rollup.elapsed()
                >= Duration::from_secs(settings.rollup_interval_minutes.saturating_mul(60))
            {
                if let Err(error) = self.finalize_rollup(&settings).await {
                    warn!(%error, "analytics rollup failed");
                }
                last_rollup = Instant::now();

                if settings.ai.enabled
                    && settings.ai.automatic
                    && last_ai.elapsed()
                        >= Duration::from_secs(settings.ai.interval_hours.saturating_mul(3600))
                    && self.has_notable_activity().await
                {
                    let manager = self.clone();
                    tokio::spawn(async move {
                        if let Err(error) = manager.analyze_now().await {
                            warn!(%error, "automatic analytics AI review failed");
                        }
                    });
                    last_ai = Instant::now();
                }
            }
            self.add_processing_time(started.elapsed());

            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(30)) => {},
                _ = self.notify.notified() => {},
            }
        }
    }

    async fn sample_firewall(&self, status: &FirewallStatus, detect_issues: bool) {
        let current_rules: BTreeMap<String, (u64, u64)> = status
            .snapshot
            .rule_stats
            .iter()
            .map(|(name, stats)| (name.clone(), (stats.match_count, stats.ban_count)))
            .collect();
        let current = StatusBaseline {
            rule_stats: current_rules.clone(),
            error_count: status.health.error_count,
            command_timeout_count: status.health.command_timeout_count,
            dropped_line_count: status.health.dropped_line_count,
            eviction_count: status.snapshot.eviction_count,
        };
        let mut baseline = self.baseline.lock().await;
        let previous = baseline.replace(current);

        {
            let mut accumulator = self.accumulator.lock();
            accumulator.active_ip_bans = status.snapshot.banned_ips.len();
            accumulator.active_subnet_bans = status.snapshot.banned_subnets.len();
            accumulator.repeat_offender_bans = status
                .snapshot
                .active_bans
                .iter()
                .filter(|ban| ban.offense_count >= 2)
                .count();
            accumulator.kernel_state_consistent =
                Some(status.health.set_entries == status.snapshot.active_ban_count);

            if let Some(previous) = &previous {
                accumulator.engine_errors = accumulator.engine_errors.saturating_add(
                    counter_delta(status.health.error_count, previous.error_count),
                );
                accumulator.command_timeouts =
                    accumulator.command_timeouts.saturating_add(counter_delta(
                        status.health.command_timeout_count,
                        previous.command_timeout_count,
                    ));
                accumulator.dropped_lines =
                    accumulator.dropped_lines.saturating_add(counter_delta(
                        status.health.dropped_line_count,
                        previous.dropped_line_count,
                    ));
                accumulator.evictions = accumulator.evictions.saturating_add(counter_delta(
                    status.snapshot.eviction_count,
                    previous.eviction_count,
                ));

                for (name, (matches, bans)) in &current_rules {
                    let (previous_matches, previous_bans) = previous
                        .rule_stats
                        .get(name)
                        .copied()
                        .unwrap_or((*matches, *bans));
                    let entry = accumulator.rules.entry(name.clone()).or_default();
                    entry.0 = entry
                        .0
                        .saturating_add(counter_delta(*matches, previous_matches));
                    entry.1 = entry.1.saturating_add(counter_delta(*bans, previous_bans));
                }
            }
        }

        if detect_issues {
            self.detect_local_issues(status, previous.as_ref());
        }
    }

    fn detect_local_issues(&self, status: &FirewallStatus, previous: Option<&StatusBaseline>) {
        if status.policy.enabled
            && matches!(
                status.health.state,
                EngineState::Degraded | EngineState::Stopped
            )
        {
            self.add_finding(AnalyticsFinding {
                severity: "critical".into(),
                category: "engine_health".into(),
                title: "Ban Shield engine is not healthy".into(),
                evidence: vec![format!("engine state: {:?}", status.health.state).to_lowercase()],
                recommendation: Some("Inspect Router Hub logs and reconcile the firewall before relying on Ban Shield enforcement.".into()),
                confidence: None,
                source: "local".into(),
            });
        }
        if status.health.set_capacity > 0
            && status.health.set_entries.saturating_mul(100) / status.health.set_capacity >= 80
        {
            self.add_finding(AnalyticsFinding {
                severity: "warning".into(),
                category: "performance".into(),
                title: "Ban set is approaching capacity".into(),
                evidence: vec![format!(
                    "{} of {} entries are in use",
                    status.health.set_entries, status.health.set_capacity
                )],
                recommendation: Some(
                    "Review retention and active-ban growth before increasing resource caps."
                        .into(),
                ),
                confidence: None,
                source: "local".into(),
            });
        }
        if status.health.set_entries != status.snapshot.active_ban_count {
            self.add_finding(AnalyticsFinding {
                severity: "critical".into(),
                category: "enforcement".into(),
                title: "Firewall state diverges from active ban state".into(),
                evidence: vec![
                    "The engine-reported set entry count differs from the active ban count".into(),
                ],
                recommendation: Some(
                    "Run Router Hub firewall reconciliation and verify the owned ipsets.".into(),
                ),
                confidence: None,
                source: "local".into(),
            });
        }
        if let Some(previous) = previous {
            let dropped = counter_delta(
                status.health.dropped_line_count,
                previous.dropped_line_count,
            );
            if dropped > 0 {
                self.add_finding(AnalyticsFinding {
                    severity: "warning".into(),
                    category: "coverage_gap".into(),
                    title: "Log ingestion dropped input".into(),
                    evidence: vec![format!("{dropped} log lines were dropped since the previous sample")],
                    recommendation: Some("Review log volume and bounded tailer limits before increasing resource caps.".into()),
                    confidence: None,
                    source: "local".into(),
                });
            }
            let timeouts = counter_delta(
                status.health.command_timeout_count,
                previous.command_timeout_count,
            );
            if timeouts > 0 {
                self.add_finding(AnalyticsFinding {
                    severity: "warning".into(),
                    category: "enforcement".into(),
                    title: "Firewall command timeouts increased".into(),
                    evidence: vec![format!(
                        "{timeouts} command timeouts occurred since the previous sample"
                    )],
                    recommendation: Some(
                        "Inspect router load and firewall command availability.".into(),
                    ),
                    confidence: None,
                    source: "local".into(),
                });
            }

            let mut total_bans = 0u64;
            let mut dominant: Option<(&str, u64)> = None;
            for (name, stats) in &status.snapshot.rule_stats {
                let (previous_matches, previous_bans) = previous
                    .rule_stats
                    .get(name)
                    .copied()
                    .unwrap_or((stats.match_count, stats.ban_count));
                let match_delta = counter_delta(stats.match_count, previous_matches);
                let ban_delta = counter_delta(stats.ban_count, previous_bans);
                total_bans = total_bans.saturating_add(ban_delta);
                if dominant.map(|(_, count)| ban_delta > count).unwrap_or(true) {
                    dominant = Some((name.as_str(), ban_delta));
                }
                if match_delta >= 100 && ban_delta == 0 {
                    self.add_finding(AnalyticsFinding {
                        severity: "warning".into(),
                        category: "rule_quality".into(),
                        title: "High-volume rule produced no ban transitions".into(),
                        evidence: vec![format!("rule `{}` matched {match_delta} times", sanitize_rule_name(&self.privacy_key, name))],
                        recommendation: Some("Review whether the rule is intentionally low weight or is generating noisy matches.".into()),
                        confidence: None,
                        source: "local".into(),
                    });
                }
            }
            if total_bans >= 20 {
                if let Some((name, count)) = dominant {
                    if count.saturating_mul(100) / total_bans >= 90 {
                        self.add_finding(AnalyticsFinding {
                            severity: "warning".into(),
                            category: "rule_quality".into(),
                            title: "One rule dominates ban transitions".into(),
                            evidence: vec![format!("rule `{}` caused at least 90% of recent transitions", sanitize_rule_name(&self.privacy_key, name))],
                            recommendation: Some("Confirm the dominant rule is high confidence and not matching ordinary application traffic.".into()),
                            confidence: None,
                            source: "local".into(),
                        });
                    }
                }
            }
        }
    }

    async fn verify_kernel(&self, status: &FirewallStatus) -> Result<()> {
        let counters = self.collect_kernel_counters().await?;
        let (set_v4, set_v6) = self.collect_ipset_counts().await?;
        let expected_v4 = status
            .snapshot
            .active_bans
            .iter()
            .filter(|ban| ban.network.addr().is_ipv4())
            .count()
            + status
                .policy
                .allowlist
                .iter()
                .filter(|network| network.addr().is_ipv4())
                .count();
        let expected_v6 = status
            .snapshot
            .active_bans
            .iter()
            .filter(|ban| ban.network.addr().is_ipv6())
            .count()
            + status
                .policy
                .allowlist
                .iter()
                .filter(|network| network.addr().is_ipv6())
                .count();
        let set_consistent = set_v4.map(|count| count == expected_v4).unwrap_or(true)
            && set_v6.map(|count| count == expected_v6).unwrap_or(true);
        {
            let mut accumulator = self.accumulator.lock();
            accumulator.kernel_state_consistent = Some(set_consistent);
        }
        if !set_consistent {
            self.add_finding(AnalyticsFinding {
                severity: "critical".into(),
                category: "enforcement".into(),
                title: "Kernel ipset membership diverges from Router Hub state".into(),
                evidence: vec![
                    "Owned ipset entry counts do not match active bans plus allowlist exceptions"
                        .into(),
                ],
                recommendation: Some(
                    "Run firewall reconciliation and inspect the Router Hub-owned ipsets.".into(),
                ),
                confidence: None,
                source: "local".into(),
            });
        }

        let mut previous = self.last_kernel_counters.lock().await;
        if let Some(old) = *previous {
            let input = add_counter_delta(
                pair_delta(counters.input_v4, old.input_v4),
                pair_delta(counters.input_v6, old.input_v6),
            );
            let forward = add_counter_delta(
                pair_delta(counters.forward_v4, old.forward_v4),
                pair_delta(counters.forward_v6, old.forward_v6),
            );
            let mut accumulator = self.accumulator.lock();
            accumulator.input_packets_blocked = accumulator
                .input_packets_blocked
                .saturating_add(input.packets);
            accumulator.input_bytes_blocked =
                accumulator.input_bytes_blocked.saturating_add(input.bytes);
            accumulator.forward_packets_blocked = accumulator
                .forward_packets_blocked
                .saturating_add(forward.packets);
            accumulator.forward_bytes_blocked = accumulator
                .forward_bytes_blocked
                .saturating_add(forward.bytes);
        }
        *previous = Some(counters);
        Ok(())
    }

    async fn collect_kernel_counters(&self) -> Result<KernelCounters> {
        let timeout = Duration::from_secs(self.config.firewall.command_timeout_seconds.min(10));
        let mut counters = KernelCounters::default();
        if self.config.firewall.protect_input {
            counters.input_v4 = self
                .read_chain_counter(&self.config.commands.iptables, "ROUTER_HUB_INPUT", timeout)
                .await?;
            counters.input_v6 = self
                .read_chain_counter(&self.config.commands.ip6tables, "ROUTER_HUB_INPUT", timeout)
                .await?;
        }
        if self.config.firewall.protect_forward {
            counters.forward_v4 = self
                .read_chain_counter(
                    &self.config.commands.iptables,
                    "ROUTER_HUB_FORWARD",
                    timeout,
                )
                .await?;
            counters.forward_v6 = self
                .read_chain_counter(
                    &self.config.commands.ip6tables,
                    "ROUTER_HUB_FORWARD",
                    timeout,
                )
                .await?;
        }
        Ok(counters)
    }

    async fn read_chain_counter(
        &self,
        command: &Path,
        chain: &str,
        timeout: Duration,
    ) -> Result<Option<CounterPair>> {
        {
            let mut overhead = self.overhead.lock();
            overhead.external_commands = overhead.external_commands.saturating_add(1);
        }
        let result = CommandRunner::new(self.config.test_mode)
            .run(command, ["-nvxL", chain], timeout)
            .await?;
        if result.simulated {
            return Ok(None);
        }
        if !result.success {
            bail!("unable to read owned firewall chain `{chain}`");
        }
        let mut total = CounterPair::default();
        let mut saw_drop = false;
        for line in result.stdout.lines() {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 3 || fields[2] != "DROP" {
                continue;
            }
            let Ok(packets) = fields[0].parse::<u64>() else {
                continue;
            };
            let Ok(bytes) = fields[1].parse::<u64>() else {
                continue;
            };
            total.packets = total.packets.saturating_add(packets);
            total.bytes = total.bytes.saturating_add(bytes);
            saw_drop = true;
        }
        if !saw_drop {
            bail!("owned firewall chain `{chain}` has no DROP rule");
        }
        Ok(Some(total))
    }

    async fn collect_ipset_counts(&self) -> Result<(Option<usize>, Option<usize>)> {
        let timeout = Duration::from_secs(self.config.firewall.command_timeout_seconds.min(10));
        let v4 = self
            .read_ipset_count(&self.config.firewall.set_name_v4, timeout)
            .await?;
        let v6 = self
            .read_ipset_count(&self.config.firewall.set_name_v6, timeout)
            .await?;
        Ok((v4, v6))
    }

    async fn read_ipset_count(&self, set_name: &str, timeout: Duration) -> Result<Option<usize>> {
        {
            let mut overhead = self.overhead.lock();
            overhead.external_commands = overhead.external_commands.saturating_add(1);
        }
        let result = CommandRunner::new(self.config.test_mode)
            .run(&self.config.commands.ipset, ["list", set_name], timeout)
            .await?;
        if result.simulated {
            return Ok(None);
        }
        if !result.success {
            bail!("unable to inspect Router Hub ipset `{set_name}`");
        }
        let mut members = false;
        let mut count = 0usize;
        for line in result.stdout.lines() {
            if line.trim() == "Members:" {
                members = true;
                continue;
            }
            if members && !line.trim().is_empty() {
                count = count.saturating_add(1);
            }
        }
        Ok(Some(count))
    }

    async fn finalize_rollup(&self, settings: &AnalyticsSettings) -> Result<()> {
        let started = Instant::now();
        let now = Utc::now();
        let dropped = self.dropped_events.swap(0, Ordering::Relaxed);
        let mut rollup = {
            let mut accumulator = self.accumulator.lock();
            let rollup = accumulator.to_rollup(now, dropped);
            let active_ip = accumulator.active_ip_bans;
            let active_subnet = accumulator.active_subnet_bans;
            let repeat = accumulator.repeat_offender_bans;
            let consistency = accumulator.kernel_state_consistent;
            *accumulator = Accumulator::new(now);
            accumulator.active_ip_bans = active_ip;
            accumulator.active_subnet_bans = active_subnet;
            accumulator.repeat_offender_bans = repeat;
            accumulator.kernel_state_consistent = consistency;
            rollup
        };
        bound_rollup(&mut rollup, settings.max_summary_bytes);

        let mut history = self.history.write().await;
        for previous in &mut history.hourly {
            previous.samples.clear();
        }
        history.hourly.push(rollup);
        prune_history(&mut history, settings, now);
        rebuild_daily(&mut history, now);
        while history.ai.len() > MAX_AI_RECORDS {
            history.ai.remove(0);
        }
        while serialized_len(&*history) > HISTORY_MEMORY_BUDGET_BYTES && history.hourly.len() > 24 {
            history.hourly.remove(0);
        }
        let bytes = serde_json::to_vec_pretty(&*history)?;
        write_atomic_private(&self.history_path, &bytes)?;
        let estimated = bytes
            .len()
            .saturating_add(estimate_accumulator_bytes(&self.accumulator.lock()));
        drop(history);

        {
            let mut overhead = self.overhead.lock();
            overhead.disk_bytes_written = overhead
                .disk_bytes_written
                .saturating_add(bytes.len() as u64);
            overhead.estimated_memory_bytes = estimated;
            overhead.last_rollup_micros =
                started.elapsed().as_micros().min(u64::MAX as u128) as u64;
        }
        *self.last_rollup_at.write().await = Some(now);
        Ok(())
    }

    pub async fn status(&self) -> AnalyticsStatus {
        let settings = self.settings.read().await.clone();
        let current = self
            .accumulator
            .lock()
            .to_rollup(Utc::now(), self.dropped_events.load(Ordering::Relaxed));
        let history = self.history.read().await;
        let last_24h = aggregate_since(
            &history.hourly,
            &current,
            Utc::now() - chrono::Duration::hours(24),
        );
        let findings = current.findings.clone();
        let overhead = self.overhead.lock().clone();
        AnalyticsStatus {
            enabled: settings.enabled,
            ai_enabled: settings.ai.enabled,
            queue_capacity: EVENT_QUEUE_CAPACITY,
            current_period_start: current.period_start,
            last_rollup_at: *self.last_rollup_at.read().await,
            last_kernel_verify_at: *self.last_kernel_verify_at.read().await,
            last_ai_analysis_at: *self.last_ai_analysis_at.read().await,
            last_24h,
            findings,
            overhead,
        }
    }

    pub async fn history(&self) -> AnalyticsHistory {
        self.history.read().await.clone()
    }

    pub async fn settings_view(&self) -> AnalyticsSettingsView {
        AnalyticsSettingsView::from(&*self.settings.read().await)
    }

    pub async fn update_settings(
        &self,
        update: AnalyticsSettingsUpdate,
    ) -> Result<AnalyticsSettingsView> {
        let current = self.settings.read().await.clone();
        let api_key = if update.ai.clear_api_key {
            String::new()
        } else if let Some(value) = update.ai.api_key {
            value.trim().to_owned()
        } else {
            current.ai.api_key
        };
        let candidate = AnalyticsSettings {
            enabled: update.enabled,
            sample_interval_seconds: update.sample_interval_seconds,
            kernel_verify_interval_seconds: update.kernel_verify_interval_seconds,
            rollup_interval_minutes: update.rollup_interval_minutes,
            hourly_retention_days: update.hourly_retention_days,
            daily_retention_days: update.daily_retention_days,
            detect_issues: update.detect_issues,
            collect_kernel_counters: update.collect_kernel_counters,
            collect_event_samples: update.collect_event_samples,
            max_samples_per_hour: update.max_samples_per_hour,
            max_sample_path_bytes: update.max_sample_path_bytes,
            max_summary_bytes: update.max_summary_bytes,
            ai: model::AiSettings {
                enabled: update.ai.enabled,
                automatic: update.ai.automatic,
                endpoint: update.ai.endpoint.trim().to_owned(),
                api_key,
                model: update.ai.model.trim().to_owned(),
                interval_hours: update.ai.interval_hours,
                privacy_mode: update.ai.privacy_mode.trim().to_owned(),
                max_payload_bytes: update.ai.max_payload_bytes,
                max_samples: update.ai.max_samples,
                max_output_tokens: update.ai.max_output_tokens,
                timeout_seconds: update.ai.timeout_seconds,
                additional_headers: update.ai.additional_headers,
            },
        };
        validate_settings(&candidate, self.config.test_mode)?;
        let bytes = serde_json::to_vec_pretty(&candidate)?;
        write_atomic_private(&self.settings_path, &bytes)?;
        {
            let mut overhead = self.overhead.lock();
            overhead.disk_bytes_written = overhead
                .disk_bytes_written
                .saturating_add(bytes.len() as u64);
        }
        *self.settings.write().await = candidate.clone();
        self.enabled.store(candidate.enabled, Ordering::Relaxed);
        self.collect_samples.store(
            candidate.enabled && candidate.collect_event_samples,
            Ordering::Relaxed,
        );
        self.notify.notify_waiters();
        Ok(AnalyticsSettingsView::from(&candidate))
    }

    pub async fn preview_ai_payload(&self) -> Result<AiPreview> {
        let settings = self.settings.read().await.clone();
        if !settings.enabled {
            bail!("security analytics is disabled");
        }
        let payload = self.build_ai_payload(&settings).await?;
        let request = ai::request_json(&settings.ai, &payload)?;
        let bytes =
            ai::validate_request_body(&settings.ai, &request, &self.config.server.auth_token)?;
        Ok(AiPreview {
            privacy_mode: settings.ai.privacy_mode,
            bytes: bytes.len(),
            payload: request,
        })
    }

    pub async fn analyze_now(&self) -> Result<AiAnalysisRecord> {
        let _guard = self.ai_lock.lock().await;
        let settings = self.settings.read().await.clone();
        if !settings.enabled {
            bail!("security analytics is disabled");
        }
        if !settings.ai.enabled {
            bail!("AI analysis is disabled");
        }
        let payload = self.build_ai_payload(&settings).await?;
        {
            let mut overhead = self.overhead.lock();
            overhead.ai_requests_attempted = overhead.ai_requests_attempted.saturating_add(1);
        }
        let result = match ai::analyze(
            &settings.ai,
            &payload,
            &self.config.server.auth_token,
            self.config.test_mode,
        )
        .await
        {
            Ok(result) => result,
            Err(error) => {
                let mut overhead = self.overhead.lock();
                overhead.ai_requests_failed = overhead.ai_requests_failed.saturating_add(1);
                return Err(error);
            }
        };
        let record = AiAnalysisRecord {
            created_at: Utc::now(),
            model: settings.ai.model.clone(),
            analysis: result.analysis,
        };
        {
            let mut history = self.history.write().await;
            history.ai.push(record.clone());
            while history.ai.len() > MAX_AI_RECORDS {
                history.ai.remove(0);
            }
            let bytes = serde_json::to_vec_pretty(&*history)?;
            write_atomic_private(&self.history_path, &bytes)?;
            let mut overhead = self.overhead.lock();
            overhead.disk_bytes_written = overhead
                .disk_bytes_written
                .saturating_add(bytes.len() as u64);
        }
        {
            let mut overhead = self.overhead.lock();
            overhead.ai_requests_succeeded = overhead.ai_requests_succeeded.saturating_add(1);
            overhead.ai_bytes_sent = overhead
                .ai_bytes_sent
                .saturating_add(result.request_bytes as u64);
            overhead.ai_bytes_received = overhead
                .ai_bytes_received
                .saturating_add(result.response_bytes as u64);
        }
        *self.last_ai_analysis_at.write().await = Some(record.created_at);
        Ok(record)
    }

    async fn build_ai_payload(&self, settings: &AnalyticsSettings) -> Result<Value> {
        let current = self
            .accumulator
            .lock()
            .to_rollup(Utc::now(), self.dropped_events.load(Ordering::Relaxed));
        let history = self.history.read().await;
        let summary = aggregate_since(
            &history.hourly,
            &current,
            Utc::now() - chrono::Duration::hours(24),
        );
        let rules: Vec<Value> = summary
            .rule_activity
            .iter()
            .map(|rule| {
                json!({
                    "name": sanitize_rule_name(&self.privacy_key, &rule.name),
                    "matches": rule.matches,
                    "ban_transitions": rule.ban_transitions,
                })
            })
            .collect();
        let samples: Vec<Value> = summary
            .samples
            .iter()
            .take(settings.ai.max_samples)
            .map(|sample| serde_json::to_value(sample).unwrap_or(Value::Null))
            .collect();
        let findings: Vec<Value> = summary
            .findings
            .iter()
            .map(|finding| {
                json!({
                    "severity": finding.severity,
                    "category": finding.category,
                    "title": finding.title,
                    "evidence": finding.evidence,
                    "recommendation": finding.recommendation,
                })
            })
            .collect();
        Ok(json!({
            "schema_version": 1,
            "period_hours": 24,
            "privacy": {
                "mode": "strict",
                "source_addresses": "stable local pseudonyms",
                "query_strings": "removed",
                "raw_logs": false
            },
            "protection": {
                "input_packets_dropped": summary.input_packets_blocked,
                "input_bytes_dropped": summary.input_bytes_blocked,
                "forward_packets_dropped": summary.forward_packets_blocked,
                "forward_bytes_dropped": summary.forward_bytes_blocked,
                "new_ip_bans": summary.new_ip_bans,
                "new_subnet_bans": summary.new_subnet_bans,
                "subnet_promotions": summary.subnet_promotions,
                "expired_bans": summary.expired_bans,
                "active_ip_bans": summary.active_ip_bans,
                "active_subnet_bans": summary.active_subnet_bans,
                "repeat_offender_bans": summary.repeat_offender_bans
            },
            "engine": {
                "errors_delta": summary.engine_errors,
                "command_timeouts_delta": summary.command_timeouts,
                "dropped_lines_delta": summary.dropped_lines,
                "evictions_delta": summary.evictions,
                "kernel_state_consistent": summary.kernel_state_consistent,
                "analytics_event_drops": summary.analytics_event_drops
            },
            "rules": rules,
            "local_findings": findings,
            "sanitized_samples": samples
        }))
    }

    async fn has_notable_activity(&self) -> bool {
        let status = self.status().await;
        status.last_24h.input_packets_blocked > 0
            || status.last_24h.forward_packets_blocked > 0
            || status.last_24h.new_ip_bans > 0
            || status.last_24h.new_subnet_bans > 0
            || status
                .last_24h
                .findings
                .iter()
                .any(|finding| finding.severity != "info")
    }

    fn add_finding(&self, finding: AnalyticsFinding) {
        let mut accumulator = self.accumulator.lock();
        if accumulator.findings.iter().any(|existing| {
            existing.category == finding.category && existing.title == finding.title
        }) {
            return;
        }
        if accumulator.findings.len() >= MAX_FINDINGS_PER_ROLLUP {
            accumulator.findings.remove(0);
        }
        accumulator.findings.push(finding);
    }

    fn add_processing_time(&self, elapsed: Duration) {
        let micros = elapsed.as_micros().min(u64::MAX as u128) as u64;
        let mut overhead = self.overhead.lock();
        overhead.processing_micros = overhead.processing_micros.saturating_add(micros);
    }
}

pub fn global() -> Option<&'static Arc<AnalyticsManager>> {
    GLOBAL.get()
}

pub fn record_engine_event(event: &EngineEvent) {
    let Some(ingress) = INGRESS.get() else {
        return;
    };
    if !ingress.enabled.load(Ordering::Relaxed) {
        return;
    }
    let event = match event {
        EngineEvent::Match {
            rule, ip, groups, ..
        } => {
            if !ingress.collect_samples.load(Ordering::Relaxed) {
                return;
            }
            let (request_method, request_path) = parse_request_line(
                groups
                    .get("request")
                    .or_else(|| groups.get("request_line"))
                    .map(String::as_str),
            );
            let method = groups.get("method").cloned().or(request_method);
            let path = groups
                .get("path")
                .or_else(|| groups.get("uri"))
                .cloned()
                .or(request_path);
            InternalEvent::Match {
                rule: rule.clone(),
                ip: *ip,
                method,
                path,
                status: groups.get("status").cloned(),
            }
        }
        EngineEvent::Banned { target } => InternalEvent::Banned {
            subnet: matches!(target, BanTarget::Subnet(_)),
        },
        EngineEvent::Promoted { .. } => InternalEvent::Promoted,
        EngineEvent::Unbanned { .. } => InternalEvent::Unbanned,
        _ => return,
    };
    if ingress.sender.try_send(event).is_err() {
        ingress.dropped.fetch_add(1, Ordering::Relaxed);
    }
}

fn validate_settings(settings: &AnalyticsSettings, test_mode: bool) -> Result<()> {
    if !(60..=3600).contains(&settings.sample_interval_seconds) {
        bail!("analytics sample_interval_seconds must be between 60 and 3600");
    }
    if !(3600..=86_400).contains(&settings.kernel_verify_interval_seconds) {
        bail!("analytics kernel_verify_interval_seconds must be between 3600 and 86400");
    }
    if !(60..=1440).contains(&settings.rollup_interval_minutes) {
        bail!("analytics rollup_interval_minutes must be between 60 and 1440");
    }
    if settings.hourly_retention_days == 0 || settings.hourly_retention_days > 31 {
        bail!("analytics hourly_retention_days must be between 1 and 31");
    }
    if settings.daily_retention_days == 0 || settings.daily_retention_days > 365 {
        bail!("analytics daily_retention_days must be between 1 and 365");
    }
    if settings.max_samples_per_hour > 64 {
        bail!("analytics max_samples_per_hour must not exceed 64");
    }
    if !(64..=512).contains(&settings.max_sample_path_bytes) {
        bail!("analytics max_sample_path_bytes must be between 64 and 512");
    }
    if !(4096..=65_536).contains(&settings.max_summary_bytes) {
        bail!("analytics max_summary_bytes must be between 4096 and 65536");
    }
    if settings.ai.enabled && !settings.enabled {
        bail!("analytics must be enabled before AI analysis can be enabled");
    }
    ai::validate_ai_settings(&settings.ai, test_mode)
}

fn load_json<T>(path: &Path) -> Result<T>
where
    T: serde::de::DeserializeOwned,
{
    let bytes =
        std::fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("failed to parse {}", path.display()))
}

fn load_or_create_privacy_key(path: &Path, auth_token: &str) -> Result<[u8; 32]> {
    if let Ok(value) = std::fs::read_to_string(path) {
        if let Some(key) = hex_decode_32(value.trim()) {
            return Ok(key);
        }
        warn!(path = %path.display(), "analytics pseudonym key is invalid; rotating it");
    }
    let mut hasher = Sha256::new();
    hasher.update(Uuid::new_v4().as_bytes());
    hasher.update(
        Utc::now()
            .timestamp_nanos_opt()
            .unwrap_or_default()
            .to_le_bytes(),
    );
    hasher.update(std::process::id().to_le_bytes());
    hasher.update(auth_token.as_bytes());
    let digest = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&digest);
    write_atomic_private(path, hex_encode(&key).as_bytes())?;
    Ok(key)
}

fn write_atomic_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .context("analytics persistence path has no parent")?;
    std::fs::create_dir_all(parent)?;
    let temp = parent.join(format!(
        ".{}-{}.tmp",
        path.file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("analytics"),
        Uuid::new_v4()
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp)?;
    let result = (|| -> Result<()> {
        file.write_all(bytes)?;
        file.sync_all()?;
        std::fs::rename(&temp, path)?;
        std::fs::File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result
}

fn counter_delta(current: u64, previous: u64) -> u64 {
    current.saturating_sub(previous)
}

fn pair_delta(current: Option<CounterPair>, previous: Option<CounterPair>) -> CounterPair {
    match (current, previous) {
        (Some(current), Some(previous)) => CounterPair {
            packets: counter_delta(current.packets, previous.packets),
            bytes: counter_delta(current.bytes, previous.bytes),
        },
        _ => CounterPair::default(),
    }
}

fn add_counter_delta(left: CounterPair, right: CounterPair) -> CounterPair {
    CounterPair {
        packets: left.packets.saturating_add(right.packets),
        bytes: left.bytes.saturating_add(right.bytes),
    }
}

fn bound_rollup(rollup: &mut AnalyticsRollup, max_bytes: usize) {
    while serialized_len(rollup) > max_bytes && !rollup.samples.is_empty() {
        rollup.samples.pop();
    }
    while serialized_len(rollup) > max_bytes && !rollup.findings.is_empty() {
        rollup.findings.pop();
    }
    while serialized_len(rollup) > max_bytes && !rollup.rule_activity.is_empty() {
        rollup.rule_activity.pop();
    }
}

fn prune_history(history: &mut AnalyticsHistory, settings: &AnalyticsSettings, now: DateTime<Utc>) {
    history.schema_version = HISTORY_SCHEMA_VERSION;
    let hourly_cutoff = now - chrono::Duration::days(settings.hourly_retention_days as i64);
    let daily_cutoff = now - chrono::Duration::days(settings.daily_retention_days as i64);
    history
        .hourly
        .retain(|rollup| rollup.period_end >= hourly_cutoff);
    history
        .daily
        .retain(|rollup| rollup.period_end >= daily_cutoff);
}

fn rebuild_daily(history: &mut AnalyticsHistory, now: DateTime<Utc>) {
    let date = now.date_naive();
    let mut todays: Vec<AnalyticsRollup> = history
        .hourly
        .iter()
        .filter(|rollup| rollup.period_end.date_naive() == date)
        .cloned()
        .collect();
    if todays.is_empty() {
        return;
    }
    todays.sort_by_key(|rollup| rollup.period_start);
    let start = Utc
        .with_ymd_and_hms(date.year(), date.month(), date.day(), 0, 0, 0)
        .single()
        .unwrap_or(todays[0].period_start);
    let mut day = aggregate_rollups(&todays, start, now);
    day.samples.clear();
    history
        .daily
        .retain(|rollup| rollup.period_end.date_naive() != date);
    history.daily.push(day);
    history.daily.sort_by_key(|rollup| rollup.period_start);
}

fn aggregate_since(
    hourly: &[AnalyticsRollup],
    current: &AnalyticsRollup,
    cutoff: DateTime<Utc>,
) -> AnalyticsRollup {
    let mut selected: Vec<AnalyticsRollup> = hourly
        .iter()
        .filter(|rollup| rollup.period_end >= cutoff)
        .cloned()
        .collect();
    selected.push(current.clone());
    aggregate_rollups(&selected, cutoff, Utc::now())
}

fn aggregate_rollups(
    rollups: &[AnalyticsRollup],
    start: DateTime<Utc>,
    end: DateTime<Utc>,
) -> AnalyticsRollup {
    let mut output = AnalyticsRollup::empty(start, end);
    let mut rules: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    let mut finding_keys = HashSet::new();
    for rollup in rollups {
        output.input_packets_blocked = output
            .input_packets_blocked
            .saturating_add(rollup.input_packets_blocked);
        output.input_bytes_blocked = output
            .input_bytes_blocked
            .saturating_add(rollup.input_bytes_blocked);
        output.forward_packets_blocked = output
            .forward_packets_blocked
            .saturating_add(rollup.forward_packets_blocked);
        output.forward_bytes_blocked = output
            .forward_bytes_blocked
            .saturating_add(rollup.forward_bytes_blocked);
        output.new_ip_bans = output.new_ip_bans.saturating_add(rollup.new_ip_bans);
        output.new_subnet_bans = output
            .new_subnet_bans
            .saturating_add(rollup.new_subnet_bans);
        output.expired_bans = output.expired_bans.saturating_add(rollup.expired_bans);
        output.subnet_promotions = output
            .subnet_promotions
            .saturating_add(rollup.subnet_promotions);
        output.active_ip_bans = rollup.active_ip_bans;
        output.active_subnet_bans = rollup.active_subnet_bans;
        output.repeat_offender_bans = rollup.repeat_offender_bans;
        output.engine_errors = output.engine_errors.saturating_add(rollup.engine_errors);
        output.command_timeouts = output
            .command_timeouts
            .saturating_add(rollup.command_timeouts);
        output.dropped_lines = output.dropped_lines.saturating_add(rollup.dropped_lines);
        output.evictions = output.evictions.saturating_add(rollup.evictions);
        output.analytics_event_drops = output
            .analytics_event_drops
            .saturating_add(rollup.analytics_event_drops);
        if rollup.kernel_state_consistent == Some(false) {
            output.kernel_state_consistent = Some(false);
        } else if output.kernel_state_consistent.is_none()
            && rollup.kernel_state_consistent.is_some()
        {
            output.kernel_state_consistent = Some(true);
        }
        for rule in &rollup.rule_activity {
            let entry = rules.entry(rule.name.clone()).or_default();
            entry.0 = entry.0.saturating_add(rule.matches);
            entry.1 = entry.1.saturating_add(rule.ban_transitions);
        }
        for finding in &rollup.findings {
            let key = format!("{}:{}", finding.category, finding.title);
            if finding_keys.insert(key) && output.findings.len() < MAX_FINDINGS_PER_ROLLUP {
                output.findings.push(finding.clone());
            }
        }
        if output.samples.len() < 64 {
            let remaining = 64 - output.samples.len();
            output
                .samples
                .extend(rollup.samples.iter().take(remaining).cloned());
        }
    }
    output.rule_activity = rules
        .into_iter()
        .map(|(name, (matches, ban_transitions))| RuleActivity {
            name,
            matches,
            ban_transitions,
        })
        .collect();
    output
}

fn serialized_len<T: serde::Serialize>(value: &T) -> usize {
    serde_json::to_vec(value)
        .map(|bytes| bytes.len())
        .unwrap_or(usize::MAX)
}

fn estimate_accumulator_bytes(accumulator: &Accumulator) -> usize {
    1024usize
        .saturating_add(accumulator.rules.len().saturating_mul(96))
        .saturating_add(accumulator.samples.len().saturating_mul(384))
        .saturating_add(accumulator.findings.len().saturating_mul(512))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_enforce_router_performance_gates() {
        let mut settings = AnalyticsSettings::default();
        assert!(validate_settings(&settings, false).is_ok());
        settings.rollup_interval_minutes = 5;
        assert!(validate_settings(&settings, false).is_err());
        settings.rollup_interval_minutes = 60;
        settings.max_samples_per_hour = 1000;
        assert!(validate_settings(&settings, false).is_err());
    }

    #[test]
    fn counter_resets_do_not_create_fake_traffic() {
        assert_eq!(counter_delta(100, 90), 10);
        assert_eq!(counter_delta(3, 100), 0);
    }

    #[test]
    fn rollup_aggregation_keeps_latest_active_counts() {
        let now = Utc::now();
        let mut first = AnalyticsRollup::empty(
            now - chrono::Duration::hours(2),
            now - chrono::Duration::hours(1),
        );
        first.new_ip_bans = 2;
        first.active_ip_bans = 2;
        let mut second = AnalyticsRollup::empty(now - chrono::Duration::hours(1), now);
        second.new_ip_bans = 3;
        second.active_ip_bans = 4;
        let merged = aggregate_rollups(&[first, second], now - chrono::Duration::hours(2), now);
        assert_eq!(merged.new_ip_bans, 5);
        assert_eq!(merged.active_ip_bans, 4);
    }
}
