use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
};

use chrono::{DateTime, Duration, Utc};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::ban_attack::{AggregationConfig, BackendError, BanBackend, BanTarget};

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct RuleStats {
    pub match_count: u64,
    pub ban_count: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct RuleStatsEntry {
    pub name: String,
    pub match_count: u64,
    pub ban_count: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct PersistentState {
    #[serde(default = "state_schema_version")]
    pub schema_version: u32,
    #[serde(default)]
    pub saved_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub active_bans: Vec<ActiveBan>,
    #[serde(default)]
    pub scores: Vec<ScoreEntry>,
    #[serde(default)]
    pub reputation: Vec<ReputationEntry>,
    #[serde(default)]
    pub subnet_offenders: Vec<SubnetOffenderEntry>,
    #[serde(default)]
    pub rule_stats: Vec<RuleStatsEntry>,
    // Kept only to import the two historical engine documents. New writes use
    // the versioned fields above.
    #[serde(default, skip_serializing)]
    pub banned_ips: Vec<IpAddr>,
    #[serde(default, skip_serializing)]
    pub banned_subnets: Vec<IpNet>,
}

fn state_schema_version() -> u32 {
    0
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ActiveBan {
    pub network: IpNet,
    pub source: String,
    pub reason: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub hit_count: u64,
    pub offense_count: u32,
    #[serde(default)]
    pub triggering_rule: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ScoreEntry {
    pub ip: IpAddr,
    pub score: u64,
    pub last_seen: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ReputationEntry {
    pub network: IpNet,
    pub offense_count: u32,
    pub last_banned_at: DateTime<Utc>,
    pub retain_until: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct SubnetOffenderEntry {
    pub subnet: IpNet,
    pub ip: IpAddr,
    pub crossed_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Snapshot {
    pub ip_counts: Vec<(IpAddr, u64)>,
    pub subnet_counts: Vec<(IpNet, u64)>,
    pub banned_ips: Vec<IpAddr>,
    pub banned_subnets: Vec<IpNet>,
    pub active_bans: Vec<ActiveBan>,
    pub tracked_ip_count: usize,
    pub tracked_subnet_count: usize,
    pub active_ban_count: usize,
    pub eviction_count: u64,
    pub rule_stats: Vec<(String, RuleStats)>,
}

#[derive(Debug)]
pub(crate) struct RecordResult {
    pub ip_count: u64,
    pub subnet: IpNet,
    pub subnet_count: u64,
    pub transitions: Vec<BanTransition>,
    pub cleanup_errors: Vec<String>,
}

#[derive(Clone, Debug)]
pub(crate) enum BanTransition {
    Banned(BanTarget),
    Promoted {
        subnet: IpNet,
        removed_ips: Vec<IpAddr>,
    },
}

pub struct Aggregator {
    config: AggregationConfig,
    ip_counts: HashMap<IpAddr, u64>,
    subnet_counts: HashMap<IpNet, u64>,
    banned_ips: HashSet<IpAddr>,
    banned_subnets: HashSet<IpNet>,
    active_bans: HashMap<BanTarget, ActiveBan>,
    last_seen: HashMap<IpAddr, DateTime<Utc>>,
    reputation: HashMap<IpNet, ReputationEntry>,
    subnet_offenders: HashMap<IpNet, HashMap<IpAddr, DateTime<Utc>>>,
    eviction_count: u64,
    rule_stats: HashMap<String, RuleStats>,
}

impl Aggregator {
    pub fn new(config: AggregationConfig) -> Self {
        Self {
            config,
            ip_counts: HashMap::new(),
            subnet_counts: HashMap::new(),
            banned_ips: HashSet::new(),
            banned_subnets: HashSet::new(),
            active_bans: HashMap::new(),
            last_seen: HashMap::new(),
            reputation: HashMap::new(),
            subnet_offenders: HashMap::new(),
            eviction_count: 0,
            rule_stats: HashMap::new(),
        }
    }

    pub fn reconfigure(&mut self, config: AggregationConfig) {
        self.config = config;
        self.rebuild_subnet_counts();
    }

    pub fn apply_exceptions(
        &mut self,
        exceptions: &[IpNet],
        backend: &dyn BanBackend,
    ) -> Result<Vec<BanTarget>, BackendError> {
        let banned_ips: Vec<IpAddr> = self
            .banned_ips
            .iter()
            .copied()
            .filter(|ip| is_exception(*ip, exceptions))
            .collect();
        let banned_subnets: Vec<IpNet> = self
            .banned_subnets
            .iter()
            .copied()
            .filter(|subnet| is_network_covered(*subnet, exceptions))
            .collect();

        let mut removed = Vec::with_capacity(banned_ips.len() + banned_subnets.len());
        for ip in banned_ips {
            let target = BanTarget::Ip(ip);
            backend.remove(&target)?;
            self.banned_ips.remove(&ip);
            self.active_bans.remove(&target);
            removed.push(target);
        }
        for subnet in banned_subnets {
            let target = BanTarget::Subnet(subnet);
            backend.remove(&target)?;
            self.banned_subnets.remove(&subnet);
            self.active_bans.remove(&target);
            removed.push(target);
        }

        self.ip_counts
            .retain(|ip, _| !is_exception(*ip, exceptions));
        self.last_seen
            .retain(|ip, _| !is_exception(*ip, exceptions));
        self.reputation
            .retain(|network, _| !is_network_covered(*network, exceptions));
        self.subnet_offenders.retain(|subnet, offenders| {
            if is_network_covered(*subnet, exceptions) {
                return false;
            }
            offenders.retain(|ip, _| !is_exception(*ip, exceptions));
            !offenders.is_empty()
        });
        self.rebuild_subnet_counts();
        Ok(removed)
    }

    pub fn targets_excluding(&self, exceptions: &[IpNet]) -> Vec<BanTarget> {
        self.active_bans
            .keys()
            .filter(|target| match target {
                BanTarget::Ip(ip) => !is_exception(*ip, exceptions),
                BanTarget::Subnet(network) => !is_network_covered(*network, exceptions),
            })
            .cloned()
            .collect()
    }

    pub(crate) fn record(
        &mut self,
        ip: IpAddr,
        weight: u64,
        rule: &str,
        backend: &dyn BanBackend,
    ) -> Result<RecordResult, BackendError> {
        {
            let stats = self.rule_stats.entry(rule.to_owned()).or_default();
            stats.match_count = stats.match_count.saturating_add(1);
        }
        let now = Utc::now();
        if self.last_seen.get(&ip).is_some_and(|last_seen| {
            *last_seen + Duration::seconds(self.config.score_retention_seconds as i64) <= now
        }) {
            self.ip_counts.remove(&ip);
            self.last_seen.remove(&ip);
            self.rebuild_subnet_counts();
        }
        if self.make_room_for_ip(ip) {
            self.rebuild_subnet_counts();
        }
        self.last_seen.insert(ip, now);
        let subnet = self.subnet_for(ip);
        self.make_room_for_subnet(subnet);
        let previous_ip_count = self.ip_counts.get(&ip).copied().unwrap_or_default();
        let ip_count = self
            .ip_counts
            .entry(ip)
            .and_modify(|count| *count = count.saturating_add(weight))
            .or_insert(weight);
        let ip_count = *ip_count;
        let subnet_count = self
            .subnet_counts
            .entry(subnet)
            .and_modify(|count| *count = count.saturating_add(weight))
            .or_insert(weight);
        let subnet_count = *subnet_count;
        let mut transitions = Vec::new();
        let mut cleanup_errors = Vec::new();

        if self.is_covered_by_banned_subnet(ip) {
            return Ok(RecordResult {
                ip_count,
                subnet,
                subnet_count,
                transitions,
                cleanup_errors,
            });
        }

        let crossed_threshold =
            previous_ip_count < self.config.ip_failures && ip_count >= self.config.ip_failures;
        if crossed_threshold {
            self.record_subnet_offender(subnet, ip, now);
        }
        let distinct_offenders = self.subnet_offenders.get(&subnet).map_or(0, HashMap::len);
        let distributed_sources = if subnet_count >= self.config.subnet_failures {
            self.ip_counts
                .keys()
                .filter(|candidate| subnet.contains(*candidate))
                .take(self.config.promote_after_banned_ips)
                .count()
        } else {
            0
        };
        let reputation_repromote = ip_count >= self.config.ip_failures
            && self.reputation.get(&subnet).is_some_and(|entry| {
                entry.offense_count >= self.config.reputation_repromote_after_offenses
            });
        let should_promote = reputation_repromote
            || distinct_offenders >= self.config.promote_after_banned_ips
            || (subnet_count >= self.config.subnet_failures
                && distributed_sources >= self.config.promote_after_banned_ips);

        if should_promote {
            let (transition, errors) = self.promote(subnet, Some(rule.to_owned()), backend)?;
            transitions.push(transition);
            cleanup_errors.extend(errors);
        } else if ip_count >= self.config.ip_failures && !self.banned_ips.contains(&ip) {
            let target = BanTarget::Ip(ip);
            self.add_timed(
                target.clone(),
                "automatic",
                "threshold",
                ip_count,
                now,
                Some(rule.to_owned()),
                backend,
            )?;
            self.banned_ips.insert(ip);
            transitions.push(BanTransition::Banned(target));
        }

        if !transitions.is_empty() {
            let stats = self.rule_stats.entry(rule.to_owned()).or_default();
            stats.ban_count = stats.ban_count.saturating_add(transitions.len() as u64);
        }

        Ok(RecordResult {
            ip_count,
            subnet,
            subnet_count,
            transitions,
            cleanup_errors,
        })
    }

    pub fn add_manual(
        &mut self,
        target: BanTarget,
        duration: Duration,
        reason: String,
        backend: &dyn BanBackend,
    ) -> Result<ActiveBan, BackendError> {
        let now = Utc::now();
        if let BanTarget::Ip(ip) = &target {
            if self.is_covered_by_banned_subnet(*ip) {
                return Err(BackendError(format!(
                    "IP `{ip}` is already covered by an active subnet ban"
                )));
            }
        }
        self.add_timed(target.clone(), "manual", &reason, 1, now, None, backend)?;
        self.active_bans
            .get_mut(&target)
            .expect("manual ban inserted")
            .expires_at = now + duration;
        match &target {
            BanTarget::Ip(ip) => {
                self.banned_ips.insert(*ip);
            }
            BanTarget::Subnet(net) => {
                self.banned_subnets.insert(*net);
                let (_, cleanup_errors) = self.remove_covered_ip_bans(*net, backend);
                for error in cleanup_errors {
                    tracing::warn!(%error, "manual subnet ban cleanup failed");
                }
            }
        }
        Ok(self
            .active_bans
            .get(&target)
            .expect("manual ban remains active")
            .clone())
    }

    pub fn cleanup_expired(
        &mut self,
        backend: &dyn BanBackend,
    ) -> Result<Vec<BanTarget>, BackendError> {
        let now = Utc::now();
        let expired: Vec<_> = self
            .active_bans
            .iter()
            .filter_map(|(target, ban)| (ban.expires_at <= now).then_some(target.clone()))
            .collect();
        for target in &expired {
            backend.remove(target)?;
            self.active_bans.remove(target);
            match target {
                BanTarget::Ip(ip) => {
                    self.banned_ips.remove(ip);
                }
                BanTarget::Subnet(net) => {
                    self.banned_subnets.remove(net);
                }
            }
        }
        self.ip_counts.retain(|ip, _| {
            self.last_seen.get(ip).is_some_and(|seen| {
                *seen + Duration::seconds(self.config.score_retention_seconds as i64) > now
            })
        });
        self.last_seen.retain(|_, seen| {
            *seen + Duration::seconds(self.config.score_retention_seconds as i64) > now
        });
        self.reputation.retain(|_, entry| entry.retain_until > now);
        let promotion_cutoff =
            now - Duration::seconds(self.config.subnet_promotion_window_seconds as i64);
        self.subnet_offenders.retain(|_, offenders| {
            offenders.retain(|_, crossed_at| *crossed_at > promotion_cutoff);
            !offenders.is_empty()
        });
        self.rebuild_subnet_counts();
        Ok(expired)
    }

    pub fn reset_counts(&mut self, target: &BanTarget) {
        match target {
            BanTarget::Ip(ip) => {
                self.ip_counts.remove(ip);
                self.last_seen.remove(ip);
                self.reputation.remove(&IpNet::from(*ip));
                for offenders in self.subnet_offenders.values_mut() {
                    offenders.remove(ip);
                }
            }
            BanTarget::Subnet(subnet) => {
                self.ip_counts.retain(|ip, _| !subnet.contains(ip));
                self.last_seen.retain(|ip, _| !subnet.contains(ip));
                self.reputation
                    .retain(|network, _| !subnet.contains(&network.addr()));
                self.subnet_offenders
                    .retain(|network, _| !subnet.contains(&network.addr()));
            }
        }
        self.rebuild_subnet_counts();
    }

    #[allow(dead_code)]
    pub fn snapshot(&self) -> Snapshot {
        self.snapshot_limited(usize::MAX)
    }

    pub fn snapshot_limited(&self, limit: usize) -> Snapshot {
        let mut ip_counts: Vec<_> = self.ip_counts.iter().map(|(k, v)| (*k, *v)).collect();
        ip_counts.sort_by_key(|(ip, score)| (std::cmp::Reverse(*score), *ip));
        ip_counts.truncate(limit);

        let mut subnet_counts: Vec<_> = self.subnet_counts.iter().map(|(k, v)| (*k, *v)).collect();
        subnet_counts.sort_by_key(|(net, score)| (std::cmp::Reverse(*score), net.to_string()));
        subnet_counts.truncate(limit);

        let mut banned_ips: Vec<_> = self.banned_ips.iter().copied().collect();
        banned_ips.sort();

        let mut banned_subnets: Vec<_> = self.banned_subnets.iter().copied().collect();
        banned_subnets.sort_by_key(|net| net.to_string());

        let mut rule_stats: Vec<_> = self
            .rule_stats
            .iter()
            .map(|(name, stats)| (name.clone(), stats.clone()))
            .collect();
        rule_stats.sort_by_key(|(name, _)| name.clone());

        Snapshot {
            ip_counts,
            subnet_counts,
            banned_ips,
            banned_subnets,
            active_bans: {
                let mut active: Vec<_> = self.active_bans.values().cloned().collect();
                active.sort_by_key(|ban| ban.network.to_string());
                active.truncate(limit);
                active
            },
            tracked_ip_count: self.ip_counts.len(),
            tracked_subnet_count: self.subnet_counts.len(),
            active_ban_count: self.active_bans.len(),
            eviction_count: self.eviction_count,
            rule_stats,
        }
    }

    pub fn persistent_state(&self) -> PersistentState {
        let mut banned_ips: Vec<_> = self.banned_ips.iter().copied().collect();
        banned_ips.sort();
        let mut banned_subnets: Vec<_> = self.banned_subnets.iter().copied().collect();
        banned_subnets.sort_by_key(|net| net.to_string());
        let mut active_bans: Vec<_> = self.active_bans.values().cloned().collect();
        active_bans.sort_by_key(|ban| ban.network.to_string());
        let mut scores: Vec<_> = self
            .ip_counts
            .iter()
            .filter_map(|(ip, score)| {
                self.last_seen.get(ip).map(|last_seen| ScoreEntry {
                    ip: *ip,
                    score: *score,
                    last_seen: *last_seen,
                })
            })
            .collect();
        scores.sort_by_key(|entry| entry.ip);
        let mut reputation: Vec<_> = self.reputation.values().cloned().collect();
        reputation.sort_by_key(|entry| entry.network.to_string());
        let mut subnet_offenders: Vec<_> = self
            .subnet_offenders
            .iter()
            .flat_map(|(subnet, offenders)| {
                offenders
                    .iter()
                    .map(|(ip, crossed_at)| SubnetOffenderEntry {
                        subnet: *subnet,
                        ip: *ip,
                        crossed_at: *crossed_at,
                    })
            })
            .collect();
        subnet_offenders.sort_by_key(|entry| (entry.subnet.to_string(), entry.ip));
        let mut rule_stats: Vec<_> = self
            .rule_stats
            .iter()
            .map(|(name, stats)| RuleStatsEntry {
                name: name.clone(),
                match_count: stats.match_count,
                ban_count: stats.ban_count,
            })
            .collect();
        rule_stats.sort_by_key(|entry| entry.name.clone());
        PersistentState {
            schema_version: 1,
            saved_at: Some(Utc::now()),
            active_bans,
            scores,
            reputation,
            subnet_offenders,
            rule_stats,
            banned_ips,
            banned_subnets,
        }
    }

    pub fn active_targets(&self) -> Vec<BanTarget> {
        let mut targets: Vec<_> = self.active_bans.keys().cloned().collect();
        targets.sort_by_key(|target| match target {
            BanTarget::Ip(ip) => ip.to_string(),
            BanTarget::Subnet(network) => network.to_string(),
        });
        targets
    }

    pub fn restore_persistent_state(
        &mut self,
        state: &PersistentState,
        _backend: &dyn BanBackend,
    ) -> Result<(), BackendError> {
        if state.schema_version > 1 {
            return Err(BackendError(format!(
                "unsupported ban state schema version {}",
                state.schema_version
            )));
        }
        let now = Utc::now();
        // Restore subnets first so they win over any redundant contained IP
        // records, regardless of persistence ordering.
        for ban in state
            .active_bans
            .iter()
            .filter(|ban| ban.expires_at > now && !is_host_network(ban.network))
        {
            if self.active_bans.len() >= self.config.max_active_bans {
                self.eviction_count = self.eviction_count.saturating_add(1);
                break;
            }
            let target = BanTarget::Subnet(ban.network);
            self.banned_subnets.insert(ban.network);
            self.active_bans.insert(target, ban.clone());
        }
        for ban in state
            .active_bans
            .iter()
            .filter(|ban| ban.expires_at > now && is_host_network(ban.network))
        {
            let ip = ban.network.addr();
            if self.is_covered_by_banned_subnet(ip) {
                continue;
            }
            if self.active_bans.len() >= self.config.max_active_bans {
                self.eviction_count = self.eviction_count.saturating_add(1);
                break;
            }
            let target = BanTarget::Ip(ip);
            self.banned_ips.insert(ip);
            self.active_bans.insert(target, ban.clone());
        }
        for score in &state.scores {
            if score.last_seen + Duration::seconds(self.config.score_retention_seconds as i64) > now
                && self.ip_counts.len() < self.config.max_tracked_ips
            {
                self.ip_counts.insert(score.ip, score.score);
                self.last_seen.insert(score.ip, score.last_seen);
            }
        }
        for entry in &state.reputation {
            if entry.retain_until > now
                && self.reputation.len() < self.config.max_reputation_entries
            {
                self.reputation.insert(entry.network, entry.clone());
            }
        }
        let promotion_cutoff =
            now - Duration::seconds(self.config.subnet_promotion_window_seconds as i64);
        for entry in &state.subnet_offenders {
            if entry.crossed_at > promotion_cutoff {
                self.subnet_offenders
                    .entry(entry.subnet)
                    .or_default()
                    .insert(entry.ip, entry.crossed_at);
            }
        }
        for entry in &state.rule_stats {
            let stats = self.rule_stats.entry(entry.name.clone()).or_default();
            stats.match_count = stats.match_count.saturating_add(entry.match_count);
            stats.ban_count = stats.ban_count.saturating_add(entry.ban_count);
        }
        if state.schema_version == 0 {
            for &subnet in &state.banned_subnets {
                let target = BanTarget::Subnet(subnet);
                self.banned_subnets.insert(subnet);
                self.active_bans.insert(
                    target,
                    ActiveBan {
                        network: subnet,
                        source: "legacy".into(),
                        reason: "migrated legacy ban".into(),
                        created_at: now,
                        expires_at: now + Duration::seconds(self.config.first_ban_seconds as i64),
                        hit_count: 1,
                        offense_count: 1,
                        triggering_rule: None,
                    },
                );
            }
            for &ip in &state.banned_ips {
                if self.is_covered_by_banned_subnet(ip) {
                    continue;
                }
                let target = BanTarget::Ip(ip);
                self.banned_ips.insert(ip);
                self.active_bans.insert(
                    target,
                    ActiveBan {
                        network: IpNet::from(ip),
                        source: "legacy".into(),
                        reason: "migrated legacy ban".into(),
                        created_at: now,
                        expires_at: now + Duration::seconds(self.config.first_ban_seconds as i64),
                        hit_count: 1,
                        offense_count: 1,
                        triggering_rule: None,
                    },
                );
            }
        }
        self.rebuild_subnet_counts();
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn add_timed(
        &mut self,
        target: BanTarget,
        source: &str,
        reason: &str,
        hit_count: u64,
        now: DateTime<Utc>,
        triggering_rule: Option<String>,
        backend: &dyn BanBackend,
    ) -> Result<(), BackendError> {
        self.ensure_active_capacity_for(&target)?;
        backend.add(&target)?;
        let network = match target {
            BanTarget::Ip(ip) => IpNet::from(ip),
            BanTarget::Subnet(net) => net,
        };
        let offense_count = self
            .reputation
            .get(&network)
            .map_or(1, |entry| entry.offense_count.saturating_add(1));
        let seconds = match offense_count {
            1 => self.config.first_ban_seconds,
            2 => self.config.second_ban_seconds,
            3 => self.config.third_ban_seconds,
            _ => self.config.max_ban_seconds,
        };
        self.active_bans.insert(
            target,
            ActiveBan {
                network,
                source: source.to_owned(),
                reason: reason.to_owned(),
                created_at: now,
                expires_at: now + Duration::seconds(seconds as i64),
                hit_count,
                offense_count,
                triggering_rule,
            },
        );
        self.reputation.insert(
            network,
            ReputationEntry {
                network,
                offense_count,
                last_banned_at: now,
                retain_until: now
                    + Duration::seconds(self.config.reputation_retention_seconds as i64),
            },
        );
        self.trim_reputation();
        Ok(())
    }

    fn ensure_active_capacity_for(&self, target: &BanTarget) -> Result<(), BackendError> {
        if self.active_bans.contains_key(target)
            || self.active_bans.len() < self.config.max_active_bans
        {
            Ok(())
        } else {
            Err(BackendError(format!(
                "active ban capacity {} reached",
                self.config.max_active_bans
            )))
        }
    }

    fn make_room_for_ip(&mut self, ip: IpAddr) -> bool {
        if self.ip_counts.contains_key(&ip) {
            return false;
        }
        let mut evicted = false;
        while self.ip_counts.len() >= self.config.max_tracked_ips {
            let Some(oldest) = self
                .last_seen
                .iter()
                .min_by_key(|(_, seen)| **seen)
                .map(|(ip, _)| *ip)
            else {
                break;
            };
            self.ip_counts.remove(&oldest);
            self.last_seen.remove(&oldest);
            self.eviction_count = self.eviction_count.saturating_add(1);
            evicted = true;
        }
        evicted
    }

    fn make_room_for_subnet(&mut self, subnet: IpNet) {
        if self.subnet_counts.contains_key(&subnet)
            || self.subnet_counts.len() < self.config.max_tracked_subnets
        {
            return;
        }
        let oldest_subnet = self.subnet_counts.keys().copied().min_by_key(|candidate| {
            self.last_seen
                .iter()
                .filter(|(ip, _)| candidate.contains(*ip))
                .map(|(_, seen)| *seen)
                .max()
        });
        if let Some(oldest_subnet) = oldest_subnet {
            let evicted: Vec<_> = self
                .ip_counts
                .keys()
                .copied()
                .filter(|ip| oldest_subnet.contains(ip))
                .collect();
            for ip in evicted {
                self.ip_counts.remove(&ip);
                self.last_seen.remove(&ip);
                self.eviction_count = self.eviction_count.saturating_add(1);
            }
            self.subnet_counts.remove(&oldest_subnet);
            self.subnet_offenders.remove(&oldest_subnet);
        }
    }

    fn record_subnet_offender(&mut self, subnet: IpNet, ip: IpAddr, now: DateTime<Utc>) {
        let cutoff = now - Duration::seconds(self.config.subnet_promotion_window_seconds as i64);
        let already_tracked = self
            .subnet_offenders
            .get(&subnet)
            .is_some_and(|offenders| offenders.contains_key(&ip));
        if !already_tracked {
            let total: usize = self.subnet_offenders.values().map(HashMap::len).sum();
            if total >= self.config.max_tracked_ips {
                let oldest = self
                    .subnet_offenders
                    .iter()
                    .flat_map(|(network, offenders)| {
                        offenders
                            .iter()
                            .map(move |(address, crossed_at)| ((*network, *address), *crossed_at))
                    })
                    .min_by_key(|(_, crossed_at)| *crossed_at)
                    .map(|(key, _)| key);
                if let Some((network, address)) = oldest {
                    if let Some(offenders) = self.subnet_offenders.get_mut(&network) {
                        offenders.remove(&address);
                        if offenders.is_empty() {
                            self.subnet_offenders.remove(&network);
                        }
                    }
                    self.eviction_count = self.eviction_count.saturating_add(1);
                }
            }
        }
        let offenders = self.subnet_offenders.entry(subnet).or_default();
        offenders.retain(|_, crossed_at| *crossed_at > cutoff);
        offenders.insert(ip, now);
    }

    fn trim_reputation(&mut self) {
        while self.reputation.len() > self.config.max_reputation_entries {
            let Some(oldest) = self
                .reputation
                .iter()
                .min_by_key(|(_, entry)| entry.last_banned_at)
                .map(|(network, _)| *network)
            else {
                break;
            };
            self.reputation.remove(&oldest);
            self.eviction_count = self.eviction_count.saturating_add(1);
        }
    }

    fn promote(
        &mut self,
        subnet: IpNet,
        triggering_rule: Option<String>,
        backend: &dyn BanBackend,
    ) -> Result<(BanTransition, Vec<String>), BackendError> {
        let target = BanTarget::Subnet(subnet);
        let now = Utc::now();
        self.add_timed(
            target.clone(),
            "automatic",
            "subnet promotion",
            self.subnet_counts.get(&subnet).copied().unwrap_or_default(),
            now,
            triggering_rule,
            backend,
        )?;
        if let Some(ban) = self.active_bans.get_mut(&target) {
            ban.expires_at = ban
                .expires_at
                .max(now + Duration::seconds(self.config.subnet_ban_seconds as i64));
        }
        self.banned_subnets.insert(subnet);

        let (removed_ips, cleanup_errors) = self.remove_covered_ip_bans(subnet, backend);

        Ok((
            BanTransition::Promoted {
                subnet,
                removed_ips,
            },
            cleanup_errors,
        ))
    }

    fn is_covered_by_banned_subnet(&self, ip: IpAddr) -> bool {
        self.banned_subnets
            .iter()
            .any(|network| network.contains(&ip))
    }

    fn remove_covered_ip_bans(
        &mut self,
        subnet: IpNet,
        backend: &dyn BanBackend,
    ) -> (Vec<IpAddr>, Vec<String>) {
        let candidates: Vec<IpAddr> = self
            .banned_ips
            .iter()
            .copied()
            .filter(|ip| subnet.contains(ip))
            .collect();
        let mut removed_ips = Vec::new();
        let mut cleanup_errors = Vec::new();
        for ip in candidates {
            if let Err(error) = backend.remove(&BanTarget::Ip(ip)) {
                cleanup_errors.push(format!(
                    "subnet `{subnet}` was banned, but redundant IP ban `{ip}` could not be removed: {error}"
                ));
            }
            // The subnet is now the desired ban. Drop the redundant IP from
            // logical state even if the backend needs periodic reconciliation
            // to remove a stale entry.
            self.banned_ips.remove(&ip);
            self.active_bans.remove(&BanTarget::Ip(ip));
            removed_ips.push(ip);
        }
        removed_ips.sort();

        (removed_ips, cleanup_errors)
    }

    fn subnet_for(&self, ip: IpAddr) -> IpNet {
        let prefix = if ip.is_ipv4() {
            self.config.ipv4_prefix
        } else {
            self.config.ipv6_prefix
        };
        IpNet::new(ip, prefix)
            .expect("validated prefix must be valid")
            .trunc()
    }

    fn rebuild_subnet_counts(&mut self) {
        let counts: Vec<(IpAddr, u64)> = self
            .ip_counts
            .iter()
            .map(|(ip, count)| (*ip, *count))
            .collect();
        self.subnet_counts.clear();
        for (ip, count) in counts {
            let subnet = self.subnet_for(ip);
            self.subnet_counts
                .entry(subnet)
                .and_modify(|total| *total = total.saturating_add(count))
                .or_insert(count);
        }
    }
}

fn is_exception(ip: IpAddr, exceptions: &[IpNet]) -> bool {
    exceptions.iter().any(|network| network.contains(&ip))
}

fn is_host_network(network: IpNet) -> bool {
    network.prefix_len() == if network.addr().is_ipv4() { 32 } else { 128 }
}

fn is_network_covered(network: IpNet, exceptions: &[IpNet]) -> bool {
    exceptions.iter().any(|exception| {
        exception.addr().is_ipv4() == network.addr().is_ipv4()
            && exception.prefix_len() <= network.prefix_len()
            && exception.contains(&network.addr())
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::ban_attack::MemoryBanBackend;

    use super::*;

    #[test]
    fn promotes_two_banned_ips_to_subnet() {
        let backend = Arc::new(MemoryBanBackend::default());
        let mut aggregator = Aggregator::new(AggregationConfig {
            ip_failures: 2,
            subnet_failures: 100,
            promote_after_banned_ips: 2,
            ipv4_prefix: 24,
            ipv6_prefix: 64,
            ..AggregationConfig::default()
        });
        let first: IpAddr = "192.0.2.10".parse().unwrap();
        let second: IpAddr = "192.0.2.20".parse().unwrap();

        aggregator
            .record(first, 2, "test", backend.as_ref())
            .unwrap();
        aggregator
            .record(second, 2, "test", backend.as_ref())
            .unwrap();

        let entries = backend.entries();
        assert!(!entries.contains(&BanTarget::Ip(first)));
        assert!(entries.contains(&BanTarget::Subnet("192.0.2.0/24".parse().unwrap())));
    }

    #[test]
    fn promotes_distributed_subnet_score_before_any_ip_crosses_threshold() {
        let backend = Arc::new(MemoryBanBackend::default());
        let mut aggregator = Aggregator::new(AggregationConfig {
            ip_failures: 4,
            subnet_failures: 4,
            promote_after_banned_ips: 2,
            ipv4_prefix: 24,
            ..AggregationConfig::default()
        });

        aggregator
            .record("192.0.2.10".parse().unwrap(), 2, "test", backend.as_ref())
            .unwrap();
        aggregator
            .record("192.0.2.20".parse().unwrap(), 2, "test", backend.as_ref())
            .unwrap();

        assert_eq!(
            backend.entries(),
            HashSet::from([BanTarget::Subnet("192.0.2.0/24".parse().unwrap())])
        );
    }

    #[test]
    fn scores_survive_multi_day_spacing_within_retention_window() {
        let backend = Arc::new(MemoryBanBackend::default());
        let mut aggregator = Aggregator::new(AggregationConfig {
            ip_failures: 4,
            score_retention_seconds: 259_200,
            subnet_failures: 100,
            ..AggregationConfig::default()
        });
        let ip: IpAddr = "192.0.2.10".parse().unwrap();

        aggregator.record(ip, 2, "test", backend.as_ref()).unwrap();
        aggregator
            .last_seen
            .insert(ip, Utc::now() - Duration::days(2));
        aggregator.record(ip, 2, "test", backend.as_ref()).unwrap();

        assert_eq!(backend.entries(), HashSet::from([BanTarget::Ip(ip)]));
    }

    #[test]
    fn retained_subnet_reputation_repromotes_after_expiry() {
        let backend = Arc::new(MemoryBanBackend::default());
        let mut aggregator = Aggregator::new(AggregationConfig {
            ip_failures: 2,
            subnet_failures: 100,
            promote_after_banned_ips: 2,
            reputation_repromote_after_offenses: 1,
            ipv4_prefix: 24,
            ipv6_prefix: 64,
            ..AggregationConfig::default()
        });
        let subnet: IpNet = "192.0.2.0/24".parse().unwrap();
        let first: IpAddr = "192.0.2.10".parse().unwrap();
        let second: IpAddr = "192.0.2.20".parse().unwrap();
        let next: IpAddr = "192.0.2.30".parse().unwrap();

        aggregator
            .record(first, 2, "test", backend.as_ref())
            .unwrap();
        aggregator
            .record(second, 2, "test", backend.as_ref())
            .unwrap();
        let target = BanTarget::Subnet(subnet);
        assert!(backend.entries().contains(&target));
        assert_eq!(
            aggregator.active_bans.get(&target).unwrap().offense_count,
            1
        );

        aggregator.active_bans.get_mut(&target).unwrap().expires_at =
            Utc::now() - Duration::seconds(1);
        aggregator.cleanup_expired(backend.as_ref()).unwrap();
        assert!(backend.entries().is_empty());

        // Prove the fast path comes from retained subnet reputation rather
        // than score or distinct-offender promotion history.
        aggregator.ip_counts.clear();
        aggregator.subnet_counts.clear();
        aggregator.last_seen.clear();
        aggregator.subnet_offenders.clear();

        aggregator
            .record(next, 2, "test", backend.as_ref())
            .unwrap();

        assert_eq!(backend.entries(), HashSet::from([target.clone()]));
        assert!(!backend.entries().contains(&BanTarget::Ip(next)));
        assert_eq!(
            aggregator.active_bans.get(&target).unwrap().offense_count,
            2
        );
    }

    #[test]
    fn manual_subnet_replaces_contained_ip_and_suppresses_new_ip_bans() {
        let backend = Arc::new(MemoryBanBackend::default());
        let mut aggregator = Aggregator::new(AggregationConfig {
            ip_failures: 1,
            subnet_failures: 100,
            promote_after_banned_ips: 2,
            ..AggregationConfig::default()
        });
        let first: IpAddr = "192.0.2.10".parse().unwrap();
        let second: IpAddr = "192.0.2.20".parse().unwrap();
        let subnet: IpNet = "192.0.0.0/16".parse().unwrap();

        aggregator
            .record(first, 1, "test", backend.as_ref())
            .unwrap();
        aggregator
            .add_manual(
                BanTarget::Subnet(subnet),
                Duration::days(1),
                "manual range ban".into(),
                backend.as_ref(),
            )
            .unwrap();
        aggregator
            .record(second, 1, "test", backend.as_ref())
            .unwrap();

        assert_eq!(
            backend.entries(),
            HashSet::from([BanTarget::Subnet(subnet)])
        );
        assert_eq!(aggregator.active_targets(), vec![BanTarget::Subnet(subnet)]);
        assert!(
            aggregator
                .add_manual(
                    BanTarget::Ip(second),
                    Duration::days(1),
                    "redundant".into(),
                    backend.as_ref(),
                )
                .is_err()
        );
    }

    #[test]
    fn restore_discards_ips_covered_by_restored_subnet() {
        let backend = Arc::new(MemoryBanBackend::default());
        let now = Utc::now();
        let subnet: IpNet = "192.0.2.0/24".parse().unwrap();
        let ip: IpAddr = "192.0.2.10".parse().unwrap();
        let make_ban = |network| ActiveBan {
            network,
            source: "automatic".into(),
            reason: "test".into(),
            created_at: now,
            expires_at: now + Duration::days(1),
            hit_count: 4,
            offense_count: 1,
            triggering_rule: None,
        };
        let state = PersistentState {
            schema_version: 1,
            saved_at: Some(now),
            // Intentionally persist the IP first to verify ordering is not
            // relied upon.
            active_bans: vec![make_ban(IpNet::from(ip)), make_ban(subnet)],
            scores: vec![],
            reputation: vec![],
            subnet_offenders: vec![],
            rule_stats: vec![],
            banned_ips: vec![],
            banned_subnets: vec![],
        };
        let mut aggregator = Aggregator::new(AggregationConfig::default());

        aggregator
            .restore_persistent_state(&state, backend.as_ref())
            .unwrap();

        assert_eq!(aggregator.active_targets(), vec![BanTarget::Subnet(subnet)]);
    }

    #[test]
    fn counts_continue_after_ip_is_banned() {
        let backend = Arc::new(MemoryBanBackend::default());
        let mut aggregator = Aggregator::new(AggregationConfig {
            ip_failures: 1,
            subnet_failures: 100,
            promote_after_banned_ips: 2,
            ipv4_prefix: 24,
            ipv6_prefix: 64,
            ..AggregationConfig::default()
        });
        let ip: IpAddr = "192.0.2.10".parse().unwrap();

        aggregator.record(ip, 1, "test", backend.as_ref()).unwrap();
        aggregator.record(ip, 1, "test", backend.as_ref()).unwrap();

        assert_eq!(aggregator.snapshot().ip_counts, vec![(ip, 2)]);
        assert_eq!(backend.entries(), HashSet::from([BanTarget::Ip(ip)]));
    }

    #[test]
    fn runtime_exception_removes_covered_bans_and_counts() {
        let backend = Arc::new(MemoryBanBackend::default());
        let mut aggregator = Aggregator::new(AggregationConfig {
            ip_failures: 1,
            subnet_failures: 100,
            promote_after_banned_ips: 2,
            ipv4_prefix: 24,
            ipv6_prefix: 64,
            ..AggregationConfig::default()
        });
        let ip: IpAddr = "192.0.2.10".parse().unwrap();

        aggregator.record(ip, 1, "test", backend.as_ref()).unwrap();
        let removed = aggregator
            .apply_exceptions(&["192.0.2.0/24".parse().unwrap()], backend.as_ref())
            .unwrap();

        assert_eq!(removed, vec![BanTarget::Ip(ip)]);
        assert!(backend.entries().is_empty());
        assert!(aggregator.snapshot().ip_counts.is_empty());
        assert!(aggregator.reputation.is_empty());
    }

    #[test]
    fn versioned_restore_does_not_revive_expired_legacy_mirrors() {
        let backend = Arc::new(MemoryBanBackend::default());
        let ip: IpAddr = "192.0.2.55".parse().unwrap();
        let now = Utc::now();
        let state = PersistentState {
            schema_version: 1,
            saved_at: Some(now),
            active_bans: vec![ActiveBan {
                network: IpNet::from(ip),
                source: "automatic".into(),
                reason: "test".into(),
                created_at: now - Duration::hours(2),
                expires_at: now - Duration::hours(1),
                hit_count: 5,
                offense_count: 1,
                triggering_rule: None,
            }],
            scores: vec![],
            reputation: vec![],
            subnet_offenders: vec![],
            rule_stats: vec![],
            banned_ips: vec![ip],
            banned_subnets: vec![],
        };
        let mut aggregator = Aggregator::new(AggregationConfig::default());

        aggregator
            .restore_persistent_state(&state, backend.as_ref())
            .unwrap();

        assert!(backend.entries().is_empty());
        assert!(aggregator.snapshot().active_bans.is_empty());
    }

    #[test]
    fn tracked_ip_capacity_evicts_oldest_score() {
        let backend = Arc::new(MemoryBanBackend::default());
        let mut config = AggregationConfig {
            ip_failures: 100,
            max_tracked_ips: 2,
            ..AggregationConfig::default()
        };
        config.max_tracked_subnets = 2;
        let mut aggregator = Aggregator::new(config);
        for ip in ["192.0.2.1", "198.51.100.1", "203.0.113.1"] {
            aggregator
                .record(ip.parse().unwrap(), 1, "test", backend.as_ref())
                .unwrap();
        }

        let snapshot = aggregator.snapshot();
        assert_eq!(snapshot.tracked_ip_count, 2);
        assert_eq!(snapshot.eviction_count, 1);
        assert_eq!(
            snapshot
                .subnet_counts
                .iter()
                .map(|(_, score)| score)
                .sum::<u64>(),
            2
        );
    }

    #[test]
    fn exception_clears_ban_and_reputation() {
        let backend = Arc::new(MemoryBanBackend::default());
        let mut config = AggregationConfig {
            ip_failures: 1,
            ..AggregationConfig::default()
        };
        config.promote_after_banned_ips = 2;
        let mut aggregator = Aggregator::new(config);
        let ip: IpAddr = "192.0.2.80".parse().unwrap();
        aggregator.record(ip, 1, "test", backend.as_ref()).unwrap();
        aggregator
            .apply_exceptions(&[IpNet::from(ip)], backend.as_ref())
            .unwrap();

        assert!(aggregator.active_targets().is_empty());
        assert!(!aggregator.reputation.contains_key(&IpNet::from(ip)));
        assert!(
            !aggregator
                .subnet_offenders
                .values()
                .any(|ips| ips.contains_key(&ip))
        );
    }
}
