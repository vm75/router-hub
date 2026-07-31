use std::{
    collections::BTreeMap,
    net::IpAddr,
    path::PathBuf,
    sync::{
        Arc,
        mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use ipnet::IpNet;

use chrono::Duration as ChronoDuration;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::ban_attack::{
    Config, Error,
    aggregate::{Aggregator, BanTransition, Snapshot},
    backend::{BanBackend, BanTarget, CommandIpSet},
    compiled::CompiledConfig,
    tailer::Tailer,
};

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub enum EngineEvent {
    Match {
        file: PathBuf,
        rule: String,
        ip: IpAddr,
        groups: BTreeMap<String, String>,
        ip_count: u64,
        subnet: IpNet,
        subnet_count: u64,
    },
    Banned {
        target: BanTarget,
    },
    Promoted {
        subnet: IpNet,
        removed_ips: Vec<IpAddr>,
    },
    Unbanned {
        target: BanTarget,
    },
    CountsReset {
        target: BanTarget,
    },
    ConfigUpdated,
    Error {
        file: Option<PathBuf>,
        message: String,
    },
}

#[derive(Clone)]
pub struct EngineHandle {
    commands: SyncSender<Command>,
    timeout: Duration,
}

pub struct BanEngine {
    handle: EngineHandle,
    join: Option<JoinHandle<()>>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum EngineState {
    Disabled,
    Observe,
    Running,
    Degraded,
    Stopped,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EngineHealth {
    pub state: EngineState,
    pub started_at: Option<DateTime<Utc>>,
    pub last_poll_at: Option<DateTime<Utc>>,
    pub last_match_at: Option<DateTime<Utc>>,
    pub last_reconcile_at: Option<DateTime<Utc>>,
    pub last_persist_at: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
    pub error_count: u64,
    pub command_timeout_count: u64,
    pub dropped_line_count: u64,
    pub set_capacity: usize,
    pub set_entries: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EngineStatus {
    pub snapshot: Snapshot,
    pub health: EngineHealth,
}

impl BanEngine {
    pub fn start(config: Config) -> Result<Self, Error> {
        let backend = Arc::new(CommandIpSet::new_with_options(
            config.ipset.clone(),
            config.firewall.clone(),
            config.test_mode,
        ));
        Self::start_with_backend(config, backend)
    }

    pub fn start_with_backend(config: Config, backend: Arc<dyn BanBackend>) -> Result<Self, Error> {
        let command_queue_capacity = config.command_queue_capacity;
        let command_timeout = Duration::from_secs(config.command_timeout_seconds);
        let compiled = CompiledConfig::compile(config)?;
        backend.ensure()?;

        let (command_tx, command_rx) = mpsc::sync_channel(command_queue_capacity);
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);

        let join = thread::Builder::new()
            .name("ban-attack".to_owned())
            .spawn(move || match Worker::new(compiled, backend) {
                Ok(mut worker) => {
                    worker.tailer.sync(&worker.config.files);
                    let _ = ready_tx.send(Ok(()));
                    worker.run(command_rx);
                }
                Err(error) => {
                    let _ = ready_tx.send(Err(error));
                }
            })?;

        if let Err(error) = ready_rx.recv().map_err(|_| Error::EngineStopped)? {
            let _ = join.join();
            return Err(error);
        }

        Ok(Self {
            handle: EngineHandle {
                commands: command_tx,
                timeout: command_timeout,
            },
            join: Some(join),
        })
    }

    pub fn handle(&self) -> EngineHandle {
        self.handle.clone()
    }

    #[allow(dead_code)]
    pub fn shutdown(mut self) -> Result<(), Error> {
        let (reply_tx, reply_rx) = mpsc::sync_channel(1);
        self.handle.enqueue(Command::Stop(reply_tx))?;
        reply_rx
            .recv_timeout(self.handle.timeout)
            .map_err(|error| match error {
                mpsc::RecvTimeoutError::Timeout => Error::CommandTimeout,
                mpsc::RecvTimeoutError::Disconnected => Error::EngineStopped,
            })?;
        if let Some(join) = self.join.take() {
            join.join().map_err(|_| Error::EngineStopped)?;
        }
        Ok(())
    }
}

impl Drop for BanEngine {
    fn drop(&mut self) {
        if self.join.is_none() {
            return;
        }
        let (reply_tx, _reply_rx) = mpsc::sync_channel(1);
        if self.handle.enqueue(Command::Stop(reply_tx)).is_ok() {
            if let Some(join) = self.join.take() {
                let _ = join.join();
            }
        } else {
            // Dropping the JoinHandle detaches the worker; dropping the final
            // sender immediately afterwards lets it observe disconnection.
            self.join.take();
        }
    }
}

impl EngineHandle {
    pub fn update_config(&self, config: Config) -> Result<(), Error> {
        let compiled = CompiledConfig::compile(config)?;
        self.request(|reply| Command::Update(Box::new(compiled), reply))
    }

    pub fn reset_counts(&self, target: BanTarget) -> Result<(), Error> {
        self.request(|reply| Command::ResetCounts(target, reply))
    }

    pub fn disable(&self) -> Result<(), Error> {
        self.request(Command::Disable)
    }

    pub fn reconcile(&self) -> Result<(), Error> {
        self.request(Command::Reconcile)
    }

    pub fn flush(&self) -> Result<(), Error> {
        self.request(Command::Flush)
    }

    pub fn add_ban(
        &self,
        target: BanTarget,
        seconds: u64,
        reason: String,
    ) -> Result<crate::ban_attack::ActiveBan, Error> {
        let (reply_tx, reply_rx) = mpsc::sync_channel(1);
        self.enqueue(Command::AddBan(target, seconds, reason, reply_tx))?;
        reply_rx
            .recv_timeout(self.timeout)
            .map_err(map_reply_error)?
    }

    #[allow(dead_code)]
    pub fn snapshot(&self) -> Result<Snapshot, Error> {
        Ok(self.status()?.snapshot)
    }

    pub fn status(&self) -> Result<EngineStatus, Error> {
        let (reply_tx, reply_rx) = mpsc::sync_channel(1);
        self.enqueue(Command::Status(reply_tx))?;
        reply_rx.recv_timeout(self.timeout).map_err(map_reply_error)
    }

    fn request<F>(&self, make_command: F) -> Result<(), Error>
    where
        F: FnOnce(SyncSender<Result<(), Error>>) -> Command,
    {
        let (reply_tx, reply_rx) = mpsc::sync_channel(1);
        self.enqueue(make_command(reply_tx))?;
        reply_rx
            .recv_timeout(self.timeout)
            .map_err(map_reply_error)?
    }

    fn enqueue(&self, command: Command) -> Result<(), Error> {
        self.commands
            .try_send(command)
            .map_err(|error| match error {
                TrySendError::Full(_) => Error::EngineBusy,
                TrySendError::Disconnected(_) => Error::EngineStopped,
            })
    }
}

fn map_reply_error(error: mpsc::RecvTimeoutError) -> Error {
    match error {
        mpsc::RecvTimeoutError::Timeout => Error::CommandTimeout,
        mpsc::RecvTimeoutError::Disconnected => Error::EngineStopped,
    }
}

enum Command {
    Update(Box<CompiledConfig>, SyncSender<Result<(), Error>>),
    ResetCounts(BanTarget, SyncSender<Result<(), Error>>),
    Disable(SyncSender<Result<(), Error>>),
    Reconcile(SyncSender<Result<(), Error>>),
    Flush(SyncSender<Result<(), Error>>),
    AddBan(
        BanTarget,
        u64,
        String,
        SyncSender<Result<crate::ban_attack::ActiveBan, Error>>,
    ),
    Status(SyncSender<EngineStatus>),
    Stop(SyncSender<()>),
}

struct Worker {
    config: CompiledConfig,
    aggregator: Aggregator,
    backend: Arc<dyn BanBackend>,
    tailer: Tailer,
    health: EngineHealth,
    last_reverify: Instant,
    last_poll: Instant,
    dirty: bool,
    last_persist: Instant,
    last_cleanup: Instant,
    invalid_line_count: u64,
}

impl Worker {
    fn new(config: CompiledConfig, backend: Arc<dyn BanBackend>) -> Result<Self, Error> {
        let started_at = Utc::now();
        let mut startup_errors = Vec::new();
        let mut aggregator = Aggregator::new(config.aggregation.clone());
        if let Some(ref path) = config.persistence_file {
            match load_state(path) {
                Ok(Some((state, migrated))) => {
                    if let Err(error) =
                        aggregator.restore_persistent_state(&state, backend.as_ref())
                    {
                        startup_errors.push(format!("could not restore ban state: {error}"));
                    } else if migrated {
                        if let Err(error) = save_state(path, &aggregator.persistent_state()) {
                            startup_errors
                                .push(format!("could not migrate legacy bans.json: {error}"));
                        } else {
                            let legacy = path.with_file_name("bans.json");
                            let archive = path.with_file_name("bans.json.migrated-v1");
                            if let Err(error) = std::fs::rename(&legacy, &archive) {
                                startup_errors.push(format!(
                                    "migrated state but could not archive {} as {}: {error}",
                                    legacy.display(),
                                    archive.display()
                                ));
                            }
                        }
                    }
                }
                Ok(None) => {}
                Err(error) => {
                    startup_errors.push(format!("invalid persisted ban state: {error}"));
                }
            }
        }
        backend.reconcile(
            &aggregator.targets_excluding(&config.exceptions),
            &config.exceptions,
        )?;
        let exceptions_cleared =
            match aggregator.apply_exceptions(&config.exceptions, backend.as_ref()) {
                Ok(_) => !config.exceptions.is_empty(),
                Err(error) => {
                    startup_errors.push(format!(
                        "could not clear exception-covered ban history: {error}"
                    ));
                    false
                }
            };
        if exceptions_cleared {
            if let Some(ref path) = config.persistence_file {
                if let Err(error) = save_state(path, &aggregator.persistent_state()) {
                    startup_errors.push(format!(
                        "could not persist exception-cleared ban state: {error}"
                    ));
                }
            }
        }
        let last_error = startup_errors.last().cloned();
        for error in &startup_errors {
            tracing::error!(message = %error, "ban-attack startup error");
        }
        let state = if startup_errors.is_empty() {
            if config.firewall.observe_only {
                EngineState::Observe
            } else {
                EngineState::Running
            }
        } else {
            EngineState::Degraded
        };
        let set_capacity = config.ipset.max_entries;
        let set_entries = aggregator.active_targets().len();
        Ok(Self {
            config,
            aggregator,
            backend,
            tailer: Tailer::default(),
            health: EngineHealth {
                state,
                started_at: Some(started_at),
                last_poll_at: None,
                last_match_at: None,
                last_reconcile_at: Some(started_at),
                last_persist_at: None,
                last_error,
                error_count: startup_errors.len() as u64,
                command_timeout_count: 0,
                dropped_line_count: 0,
                set_capacity,
                set_entries,
            },
            last_reverify: Instant::now(),
            last_poll: Instant::now(),
            dirty: false,
            last_persist: Instant::now(),
            last_cleanup: Instant::now(),
            invalid_line_count: 0,
        })
    }

    fn check_reverify(&mut self) {
        if self.config.firewall.enabled && self.config.firewall.reverify_interval_seconds > 0 {
            let interval = Duration::from_secs(self.config.firewall.reverify_interval_seconds);
            if self.last_reverify.elapsed() >= interval {
                if let Err(error) = self
                    .backend
                    .reconcile(&self.aggregator.active_targets(), &self.config.exceptions)
                {
                    self.emit(EngineEvent::Error {
                        file: None,
                        message: format!("periodic chain re-verification failed: {error}"),
                    });
                }
                self.health.last_reconcile_at = Some(Utc::now());
                self.last_reverify = Instant::now();
            }
        }
    }

    fn save_persistence_if_configured(&mut self, force: bool) {
        if !self.dirty || (!force && self.last_persist.elapsed() < self.config.persist_interval) {
            return;
        }
        if let Some(ref path) = self.config.persistence_file {
            if let Err(error) = save_state(path, &self.aggregator.persistent_state()) {
                self.emit(EngineEvent::Error {
                    file: None,
                    message: format!("could not persist ban state: {error}"),
                });
                return;
            }
        }
        self.dirty = false;
        self.last_persist = Instant::now();
        self.health.last_persist_at = Some(Utc::now());
    }

    fn run(&mut self, commands: Receiver<Command>) {
        loop {
            match commands.recv_timeout(self.config.poll_interval) {
                Ok(Command::Update(config, reply)) => {
                    let result = self.update(*config);
                    let _ = reply.send(result);
                }
                Ok(Command::ResetCounts(target, reply)) => {
                    self.aggregator.reset_counts(&target);
                    self.emit(EngineEvent::CountsReset { target });
                    self.dirty = true;
                    self.save_persistence_if_configured(true);
                    let _ = reply.send(Ok(()));
                }
                Ok(Command::Disable(reply)) => {
                    let result = self.backend.disable().map_err(Error::Backend);
                    let _ = reply.send(result);
                }
                Ok(Command::Reconcile(reply)) => {
                    let result = self
                        .backend
                        .reconcile(&self.aggregator.active_targets(), &self.config.exceptions)
                        .map(|_| {
                            self.health.last_reconcile_at = Some(Utc::now());
                        })
                        .map_err(Error::Backend);
                    if let Err(error) = &result {
                        self.emit(EngineEvent::Error {
                            file: None,
                            message: format!("requested reconciliation failed: {error}"),
                        });
                    }
                    let _ = reply.send(result);
                }
                Ok(Command::Flush(reply)) => {
                    self.save_persistence_if_configured(true);
                    let result = if self.dirty {
                        Err(Error::Config("ban state could not be flushed".to_owned()))
                    } else {
                        Ok(())
                    };
                    let _ = reply.send(result);
                }
                Ok(Command::AddBan(target, seconds, reason, reply)) => {
                    let result =
                        if seconds < 60 || seconds > self.config.aggregation.max_ban_seconds {
                            Err(Error::Config(format!(
                                "manual ban duration must be between 60 and {} seconds",
                                self.config.aggregation.max_ban_seconds
                            )))
                        } else {
                            self.aggregator
                                .add_manual(
                                    target.clone(),
                                    ChronoDuration::seconds(seconds as i64),
                                    reason,
                                    self.backend.as_ref(),
                                )
                                .map_err(Error::Backend)
                        };
                    if result.is_ok() {
                        self.dirty = true;
                        self.save_persistence_if_configured(true);
                        self.emit(EngineEvent::Banned { target });
                    }
                    let _ = reply.send(result);
                }
                Ok(Command::Status(reply)) => {
                    self.health.dropped_line_count = self
                        .tailer
                        .dropped_line_count()
                        .saturating_add(self.invalid_line_count);
                    self.health.set_entries = self.aggregator.active_targets().len();
                    let _ = reply.send(EngineStatus {
                        snapshot: self
                            .aggregator
                            .snapshot_limited(self.config.max_status_entries),
                        health: self.health.clone(),
                    });
                }
                Ok(Command::Stop(reply)) => {
                    self.save_persistence_if_configured(true);
                    self.health.state = EngineState::Stopped;
                    let _ = reply.send(());
                    break;
                }
                Err(RecvTimeoutError::Timeout) => self.poll(),
                Err(RecvTimeoutError::Disconnected) => {
                    self.save_persistence_if_configured(true);
                    self.health.state = EngineState::Stopped;
                    break;
                }
            }
            // recv_timeout alone allows a continuous request stream to starve
            // log ingestion forever. Keep an absolute polling deadline.
            if self.last_poll.elapsed() >= self.config.poll_interval {
                self.poll();
            }
        }
    }

    fn update(&mut self, config: CompiledConfig) -> Result<(), Error> {
        if config.ipset != self.config.ipset {
            return Err(Error::Config(
                "ipset configuration is startup-only".to_owned(),
            ));
        }
        if config.firewall != self.config.firewall {
            return Err(Error::Config(
                "firewall backend configuration is startup-only".to_owned(),
            ));
        }
        self.backend.reconcile(
            &self.aggregator.targets_excluding(&config.exceptions),
            &config.exceptions,
        )?;
        let removed = self
            .aggregator
            .apply_exceptions(&config.exceptions, self.backend.as_ref())?;
        for target in removed {
            self.emit(EngineEvent::Unbanned { target });
        }
        self.aggregator.reconfigure(config.aggregation.clone());
        self.config = config;
        self.dirty = true;
        self.save_persistence_if_configured(true);
        self.tailer.sync(&self.config.files);
        self.emit(EngineEvent::ConfigUpdated);
        Ok(())
    }

    fn poll(&mut self) {
        self.last_poll = Instant::now();
        self.health.last_poll_at = Some(Utc::now());
        self.check_reverify();
        if self.last_cleanup.elapsed() >= self.config.cleanup_interval {
            match self.aggregator.cleanup_expired(self.backend.as_ref()) {
                Ok(expired) => {
                    if !expired.is_empty() {
                        self.dirty = true;
                    }
                    for target in expired {
                        self.emit(EngineEvent::Unbanned { target });
                    }
                    self.save_persistence_if_configured(true);
                }
                Err(error) => self.emit(EngineEvent::Error {
                    file: None,
                    message: format!("ban expiry cleanup failed: {error}"),
                }),
            }
            self.last_cleanup = Instant::now();
        } else {
            self.save_persistence_if_configured(false);
        }
        for file_index in 0..self.config.files.len() {
            let (path, start_at) = {
                let file = &self.config.files[file_index];
                (file.path.clone(), file.start_at)
            };

            let lines = match self.tailer.read_lines_bounded(
                &path,
                start_at,
                self.config.max_read_bytes_per_file_poll,
                self.config.max_lines_per_file_poll,
                self.config.max_line_bytes,
            ) {
                Ok(lines) => lines,
                Err(error) => {
                    self.emit(EngineEvent::Error {
                        file: Some(path),
                        message: error.to_string(),
                    });
                    continue;
                }
            };

            for bytes in lines {
                let line = match std::str::from_utf8(&bytes) {
                    Ok(line) => line,
                    Err(error) => {
                        self.invalid_line_count = self.invalid_line_count.saturating_add(1);
                        self.emit(EngineEvent::Error {
                            file: Some(path.clone()),
                            message: format!("ignored non-UTF-8 log line: {error}"),
                        });
                        continue;
                    }
                };

                let rule_count = self.config.files[file_index].rules.len();
                for rule_index in 0..rule_count {
                    let (rule_name, weight, match_result) = {
                        let rule = &mut self.config.files[file_index].rules[rule_index];
                        (rule.name.clone(), rule.weight, rule.match_line(line))
                    };
                    let hit = match match_result {
                        Ok(Some(hit)) => hit,
                        Ok(None) => continue,
                        Err(error) => {
                            self.emit(EngineEvent::Error {
                                file: Some(path.clone()),
                                message: format!(
                                    "hybrid DFA search failed for rule `{rule_name}`: {error}"
                                ),
                            });
                            continue;
                        }
                    };
                    if self.config.is_exception(&hit.ip) {
                        continue;
                    }

                    match self
                        .aggregator
                        .record(hit.ip, weight, self.backend.as_ref())
                    {
                        Ok(result) => {
                            self.dirty = true;
                            self.emit(EngineEvent::Match {
                                file: path.clone(),
                                rule: rule_name,
                                ip: hit.ip,
                                groups: hit.groups,
                                ip_count: result.ip_count,
                                subnet: result.subnet,
                                subnet_count: result.subnet_count,
                            });
                            if !result.transitions.is_empty() {
                                self.save_persistence_if_configured(true);
                            } else {
                                self.save_persistence_if_configured(false);
                            }
                            for transition in result.transitions {
                                match transition {
                                    BanTransition::Banned(target) => {
                                        self.emit(EngineEvent::Banned { target });
                                    }
                                    BanTransition::Promoted {
                                        subnet,
                                        removed_ips,
                                    } => {
                                        self.emit(EngineEvent::Promoted {
                                            subnet,
                                            removed_ips,
                                        });
                                    }
                                }
                            }
                            for message in result.cleanup_errors {
                                self.emit(EngineEvent::Error {
                                    file: Some(path.clone()),
                                    message,
                                });
                            }
                            // Rules are ordered: one log event has one meaning.
                            break;
                        }
                        Err(error) => self.emit(EngineEvent::Error {
                            file: Some(path.clone()),
                            message: error.to_string(),
                        }),
                    }
                }
            }
        }
    }

    fn emit(&mut self, event: EngineEvent) {
        match event {
            EngineEvent::Match { .. } => {
                self.health.last_match_at = Some(Utc::now());
            }
            EngineEvent::Banned { target } => {
                tracing::info!(?target, "ban-attack target banned");
            }
            EngineEvent::Promoted {
                subnet,
                removed_ips,
            } => {
                tracing::info!(%subnet, removed_ip_count = removed_ips.len(), "ban-attack subnet promoted");
            }
            EngineEvent::Unbanned { target } => {
                tracing::info!(?target, "ban-attack target unbanned");
            }
            EngineEvent::CountsReset { target } => {
                tracing::info!(?target, "ban-attack history reset");
            }
            EngineEvent::ConfigUpdated => {
                tracing::info!("ban-attack configuration updated");
            }
            EngineEvent::Error { file, message } => {
                self.health.state = EngineState::Degraded;
                self.health.error_count = self.health.error_count.saturating_add(1);
                if message.contains("timed out") {
                    self.health.command_timeout_count =
                        self.health.command_timeout_count.saturating_add(1);
                }
                self.health.last_error = Some(message.clone());
                if let Some(file) = file {
                    tracing::error!(path = %file.display(), %message, "ban-attack error");
                } else {
                    tracing::error!(%message, "ban-attack error");
                }
            }
        }
    }
}

#[derive(Deserialize)]
struct LegacyBanRecord {
    network: IpNet,
    #[serde(default = "legacy_reason")]
    reason: String,
    #[serde(default)]
    created_at: Option<chrono::DateTime<Utc>>,
    #[serde(default)]
    expires_at: Option<chrono::DateTime<Utc>>,
    #[serde(default)]
    hit_count: u64,
}

#[derive(Deserialize)]
struct LegacyEngineState {
    #[serde(default)]
    banned_ips: Vec<IpAddr>,
    #[serde(default)]
    banned_subnets: Vec<IpNet>,
}

fn legacy_reason() -> String {
    "legacy ban".to_owned()
}

fn load_state(
    path: &std::path::Path,
) -> Result<Option<(crate::ban_attack::PersistentState, bool)>, String> {
    if path.exists() {
        let bytes = std::fs::read(path).map_err(|error| error.to_string())?;
        let state: crate::ban_attack::PersistentState =
            serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
        if state.schema_version != 1 {
            return Err(format!(
                "unsupported ban state schema version {}",
                state.schema_version
            ));
        }
        return Ok(Some((state, false)));
    }
    let legacy_path = path.with_file_name("bans.json");
    if !legacy_path.exists() {
        return Ok(None);
    }
    let bytes = std::fs::read(&legacy_path).map_err(|error| error.to_string())?;
    let now = Utc::now();
    let active_bans = if let Ok(records) = serde_json::from_slice::<Vec<LegacyBanRecord>>(&bytes) {
        records
            .into_iter()
            .filter_map(|record| {
                let expires_at = record
                    .expires_at
                    .unwrap_or_else(|| now + ChronoDuration::hours(1));
                (expires_at > now).then_some(crate::ban_attack::ActiveBan {
                    network: record.network,
                    source: "legacy".to_owned(),
                    reason: record.reason,
                    created_at: record.created_at.unwrap_or(now),
                    expires_at,
                    hit_count: record.hit_count,
                    offense_count: 1,
                })
            })
            .collect()
    } else {
        let legacy: LegacyEngineState =
            serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
        legacy
            .banned_ips
            .into_iter()
            .map(IpNet::from)
            .chain(legacy.banned_subnets)
            .map(|network| crate::ban_attack::ActiveBan {
                network,
                source: "legacy".to_owned(),
                reason: "migrated legacy ban".to_owned(),
                created_at: now,
                expires_at: now + ChronoDuration::hours(1),
                hit_count: 1,
                offense_count: 1,
            })
            .collect()
    };
    Ok(Some((
        crate::ban_attack::PersistentState {
            schema_version: 1,
            saved_at: Some(now),
            active_bans,
            scores: vec![],
            reputation: vec![],
            subnet_offenders: vec![],
            banned_ips: vec![],
            banned_subnets: vec![],
        },
        true,
    )))
}

fn save_state(
    path: &std::path::Path,
    state: &crate::ban_attack::PersistentState,
) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let parent = path
        .parent()
        .ok_or_else(|| "state file has no parent directory".to_owned())?;
    std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    let temp = parent.join(format!(
        ".{}-{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("ban-attack-state"),
        Uuid::new_v4()
    ));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp)
        .map_err(|error| error.to_string())?;
    let result = (|| -> Result<(), String> {
        file.write_all(&serde_json::to_vec_pretty(state).map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;
        file.sync_all().map_err(|error| error.to_string())?;
        std::fs::rename(&temp, path).map_err(|error| error.to_string())?;
        std::fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| error.to_string())?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn rejects_future_state_schema() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("ban-attack-state.json");
        std::fs::write(
            &path,
            br#"{"schema_version":2,"active_bans":[],"scores":[],"reputation":[]}"#,
        )
        .unwrap();

        assert!(
            load_state(&path)
                .unwrap_err()
                .contains("unsupported ban state schema version 2")
        );
    }

    #[test]
    fn imports_both_legacy_state_shapes_with_expiration() {
        let directory = tempdir().unwrap();
        let state_path = directory.path().join("ban-attack-state.json");
        let legacy_path = directory.path().join("bans.json");
        std::fs::write(
            &legacy_path,
            br#"[{"network":"192.0.2.4/32","reason":"old","created_at":"2026-07-30T00:00:00Z","expires_at":"2099-07-30T01:00:00Z","hit_count":2}]"#,
        )
        .unwrap();
        let (records, migrated) = load_state(&state_path).unwrap().unwrap();
        assert!(migrated);
        assert_eq!(records.active_bans.len(), 1);
        assert_eq!(records.active_bans[0].network.to_string(), "192.0.2.4/32");

        std::fs::write(
            &legacy_path,
            br#"{"banned_ips":["198.51.100.8"],"banned_subnets":["2001:db8::/64"]}"#,
        )
        .unwrap();
        let (records, migrated) = load_state(&state_path).unwrap().unwrap();
        assert!(migrated);
        assert_eq!(records.active_bans.len(), 2);
        assert!(
            records
                .active_bans
                .iter()
                .all(|ban| ban.expires_at > Utc::now())
        );
    }
}
