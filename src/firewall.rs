use std::{
    collections::{BTreeMap, HashSet},
    path::PathBuf,
    sync::Arc,
};

use anyhow::{Result, bail};
use ipnet::IpNet;
use tokio::sync::{Mutex, RwLock};

use crate::{
    ban_attack::{
        AggregationConfig, BanEngine, BanTarget, Config as BanAttackConfig, EngineHealth,
        EngineState, FileConfig, FirewallConfig as BanFirewallConfig,
        IpSetConfig as BanIpSetConfig, RuleConfig as BanRuleConfig, StartAt,
    },
    config::{AppConfig, days_to_seconds},
    models::{BanRecord, FirewallPolicy, FirewallSettings, FirewallStatus},
    storage::Stores,
};

#[derive(Clone)]
pub struct FirewallManager {
    inner: Arc<RwLock<Option<BanEngine>>>,
    policy_update: Arc<Mutex<()>>,
    config: AppConfig,
    stores: Stores,
}

impl FirewallManager {
    pub async fn new(config: AppConfig, stores: Stores) -> Result<Self> {
        Ok(Self {
            inner: Arc::new(RwLock::new(None)),
            policy_update: Arc::new(Mutex::new(())),
            config,
            stores,
        })
    }

    pub async fn start(&self) {
        let mut inner = self.inner.write().await;
        if inner.is_some() {
            return;
        }

        let policy = self.stores.firewall_policy.read().await.clone();
        if !policy.enabled {
            return;
        }
        if let Err(error) = validate_policy(&policy) {
            tracing::warn!(%error, "firewall policy validation failed");
            return;
        }
        if let Ok(ban_config) = self.build_ban_attack_config(&policy) {
            if ban_config.files.is_empty() {
                tracing::debug!("firewall policy enabled but no log files configured");
                return;
            }
            match BanEngine::start(ban_config) {
                Ok(engine) => {
                    *inner = Some(engine);
                }
                Err(error) => {
                    tracing::warn!(%error, "failed to start ban-attack engine");
                }
            }
        }
    }

    pub async fn status(&self) -> FirewallStatus {
        let policy = self.stores.firewall_policy.read().await.clone();
        let inner = self.inner.read().await;
        let handle = inner.as_ref().map(BanEngine::handle);
        drop(inner);
        let engine_status = if let Some(handle) = handle {
            tokio::task::spawn_blocking(move || handle.status())
                .await
                .ok()
                .unwrap_or(Err(crate::ban_attack::Error::EngineStopped))
                .map(Some)
        } else {
            Ok(None)
        };
        let (snapshot, health) = match engine_status {
            Ok(Some(status)) => (status.snapshot, status.health),
            Err(error) => (
                Default::default(),
                EngineHealth {
                    state: EngineState::Degraded,
                    started_at: None,
                    last_poll_at: None,
                    last_match_at: None,
                    last_reconcile_at: None,
                    last_persist_at: None,
                    last_error: Some(error.to_string()),
                    error_count: 1,
                    command_timeout_count: u64::from(matches!(
                        error,
                        crate::ban_attack::Error::CommandTimeout
                    )),
                    dropped_line_count: 0,
                    set_capacity: 0,
                    set_entries: 0,
                },
            ),
            Ok(None) => (
                Default::default(),
                EngineHealth {
                    state: if policy.enabled {
                        EngineState::Stopped
                    } else {
                        EngineState::Disabled
                    },
                    started_at: None,
                    last_poll_at: None,
                    last_match_at: None,
                    last_reconcile_at: None,
                    last_persist_at: None,
                    last_error: None,
                    error_count: 0,
                    command_timeout_count: 0,
                    dropped_line_count: 0,
                    set_capacity: 0,
                    set_entries: 0,
                },
            ),
        };

        let rule_id_by_name: std::collections::HashMap<&str, uuid::Uuid> = policy
            .rules
            .iter()
            .map(|r| (r.name.as_str(), r.id))
            .collect();
        let bans = snapshot
            .active_bans
            .iter()
            .map(|ban| BanRecord {
                network: ban.network,
                reason: ban.reason.clone(),
                rule_id: ban
                    .triggering_rule
                    .as_deref()
                    .and_then(|name| rule_id_by_name.get(name).copied()),
                created_at: ban.created_at,
                expires_at: ban.expires_at,
                hit_count: ban.hit_count as usize,
                source: ban.source.clone(),
                offense_count: ban.offense_count,
                triggering_rule: ban.triggering_rule.clone(),
            })
            .collect();
        FirewallStatus {
            policy,
            snapshot,
            bans,
            health,
            settings: FirewallSettings {
                global_threshold: self.config.firewall.ip_failures,
                score_retention_seconds: days_to_seconds(self.config.firewall.score_retention_days)
                    .unwrap_or_default(),
                escalation_seconds: [
                    days_to_seconds(self.config.firewall.first_ban_days).unwrap_or_default(),
                    days_to_seconds(self.config.firewall.second_ban_days).unwrap_or_default(),
                    days_to_seconds(self.config.firewall.third_ban_days).unwrap_or_default(),
                    days_to_seconds(self.config.firewall.max_ban_days).unwrap_or_default(),
                ],
                subnet_promotion_window_seconds: days_to_seconds(
                    self.config.firewall.subnet_promotion_window_days,
                )
                .unwrap_or_default(),
            },
        }
    }

    /// Applies the live policy before committing it to disk.  This is the
    /// single mutation path used by the API so a saved policy never describes
    /// an engine configuration that failed validation or application.
    pub async fn replace_policy(&self, candidate: FirewallPolicy) -> Result<()> {
        let _update = self.policy_update.lock().await;
        validate_policy(&candidate)?;
        let candidate_config = self.build_ban_attack_config(&candidate)?;
        if !candidate_config.files.is_empty() {
            crate::ban_attack::validate_config(candidate_config)?;
        }
        let previous = self.stores.firewall_policy.read().await.clone();
        self.update_policy(&candidate).await?;
        *self.stores.firewall_policy.write().await = candidate;
        if let Err(error) = self.stores.save_firewall_policy().await {
            *self.stores.firewall_policy.write().await = previous.clone();
            let _ = self.update_policy(&previous).await;
            return Err(error);
        }
        Ok(())
    }

    pub async fn update_policy(&self, policy: &FirewallPolicy) -> Result<()> {
        let ban_config = self.build_ban_attack_config(policy)?;
        let mut inner = self.inner.write().await;
        if let Some(ref mut engine) = *inner {
            if !policy.enabled || ban_config.files.is_empty() {
                engine.handle().disable()?;
                *inner = None;
            } else {
                if let Err(update_error) = engine.handle().update_config(ban_config.clone()) {
                    engine.handle().flush()?;
                    let new_engine = BanEngine::start(ban_config).map_err(|restart_error| {
                        anyhow::anyhow!(
                            "live policy update failed ({update_error}); replacement engine failed ({restart_error})"
                        )
                    })?;
                    *inner = Some(new_engine);
                }
            }
        } else if policy.enabled && !ban_config.files.is_empty() {
            let engine = BanEngine::start(ban_config)?;
            *inner = Some(engine);
        }
        Ok(())
    }

    pub async fn ban_manual(
        &self,
        network: IpNet,
        seconds: u64,
        reason: String,
    ) -> Result<BanRecord> {
        let policy = self.stores.firewall_policy.read().await.clone();
        if !policy.enabled {
            bail!("firewall policy is disabled");
        }
        if policy
            .allowlist
            .iter()
            .any(|allowed| networks_overlap(allowed, &network))
        {
            bail!("network overlaps the allowlist and cannot be banned");
        }

        let target = if network.prefix_len() == 32 || network.prefix_len() == 128 {
            BanTarget::Ip(network.addr())
        } else {
            BanTarget::Subnet(network)
        };

        let inner = self.inner.read().await;
        let Some(ref engine) = *inner else {
            bail!("firewall engine is not running");
        };

        let ban = engine.handle().add_ban(target, seconds, reason)?;
        Ok(BanRecord {
            network: ban.network,
            reason: ban.reason,
            rule_id: None,
            created_at: ban.created_at,
            expires_at: ban.expires_at,
            hit_count: ban.hit_count as usize,
            source: ban.source,
            offense_count: ban.offense_count,
            triggering_rule: ban.triggering_rule,
        })
    }

    pub async fn reconcile(&self) -> Result<()> {
        let inner = self.inner.read().await;
        let Some(ref engine) = *inner else {
            bail!("firewall engine is not running");
        };
        engine.handle().reconcile()?;
        Ok(())
    }

    pub async fn unban(&self, network: IpNet) -> Result<()> {
        let mut policy = self.stores.firewall_policy.read().await.clone();
        if !policy
            .allowlist
            .iter()
            .any(|allowed| network_covers(allowed, &network))
        {
            policy.allowlist.push(network);
        }
        // A policy update makes the exception durable and atomically asks the
        // running engine to remove covered bans, scores, promotion history,
        // and reputation.
        self.replace_policy(policy).await
    }

    pub async fn reset_counts(&self, network: IpNet) -> Result<()> {
        let target = if network.prefix_len() == 32 || network.prefix_len() == 128 {
            BanTarget::Ip(network.addr())
        } else {
            BanTarget::Subnet(network)
        };

        let inner = self.inner.read().await;
        let Some(ref engine) = *inner else {
            bail!("firewall engine is not running");
        };
        engine.handle().reset_counts(target)?;
        Ok(())
    }

    fn build_ban_attack_config(&self, policy: &FirewallPolicy) -> Result<BanAttackConfig> {
        let mut file_map: BTreeMap<PathBuf, Vec<BanRuleConfig>> = BTreeMap::new();

        {
            for rule in &policy.rules {
                if !rule.enabled {
                    continue;
                }
                let ban_rule = BanRuleConfig {
                    name: rule.name.clone(),
                    regex: rule.pattern.clone(),
                    ip_group: rule.ip_group.clone(),
                    group_values: rule.group_values.clone(),
                    weight: rule.weight,
                };
                for log_path in &rule.log_paths {
                    file_map
                        .entry(log_path.clone())
                        .or_default()
                        .push(ban_rule.clone());
                }
            }
        }

        let files = file_map
            .into_iter()
            .map(|(path, rules)| FileConfig {
                path,
                start_at: StartAt::End,
                rules,
            })
            .collect();

        // The engine owns its state.  In particular, do not share the old
        // `bans.json` file with Stores: it has a different schema.
        let persistence_file = Some(self.config.paths.data_dir.join("ban-attack-state.json"));

        Ok(BanAttackConfig {
            poll_interval_ms: self.config.firewall.poll_interval_ms,
            regex_dfa_cache_bytes: self.config.firewall.regex_dfa_cache_bytes,
            regex_size_limit_bytes: self.config.firewall.regex_size_limit_bytes,
            test_mode: self.config.test_mode,
            persistence_file,
            persist_interval_seconds: self.config.firewall.persist_interval_seconds,
            cleanup_interval_seconds: self.config.firewall.cleanup_interval_seconds,
            max_status_entries: self.config.firewall.max_status_entries,
            command_queue_capacity: 128,
            command_timeout_seconds: self.config.firewall.command_timeout_seconds,
            log_dirs: self.config.firewall.log_dirs.clone(),
            max_read_bytes_per_file_poll: self.config.firewall.max_read_bytes_per_file_poll,
            max_lines_per_file_poll: self.config.firewall.max_lines_per_file_poll,
            max_line_bytes: self.config.firewall.max_line_bytes,
            firewall: BanFirewallConfig {
                enabled: policy.enabled,
                observe_only: policy.observe_only,
                iptables_command: self.config.commands.iptables.clone(),
                ip6tables_command: self.config.commands.ip6tables.clone(),
                protect_input: self.config.firewall.protect_input,
                protect_forward: self.config.firewall.protect_forward,
                reverify_interval_seconds: self.config.firewall.reverify_interval_seconds,
                command_timeout_seconds: self.config.firewall.command_timeout_seconds,
            },
            aggregation: AggregationConfig {
                ip_failures: self.config.firewall.ip_failures,
                subnet_failures: self.config.firewall.subnet_failures,
                promote_after_banned_ips: self.config.firewall.promote_after_banned_ips,
                ipv4_prefix: self.config.firewall.subnet_prefix_v4,
                ipv6_prefix: self.config.firewall.subnet_prefix_v6,
                score_retention_seconds: days_to_seconds(
                    self.config.firewall.score_retention_days,
                )?,
                reputation_retention_seconds: days_to_seconds(
                    self.config.firewall.reputation_retention_days,
                )?,
                subnet_promotion_window_seconds: days_to_seconds(
                    self.config.firewall.subnet_promotion_window_days,
                )?,
                subnet_ban_seconds: days_to_seconds(self.config.firewall.subnet_ban_days)?,
                first_ban_seconds: days_to_seconds(self.config.firewall.first_ban_days)?,
                second_ban_seconds: days_to_seconds(self.config.firewall.second_ban_days)?,
                third_ban_seconds: days_to_seconds(self.config.firewall.third_ban_days)?,
                max_ban_seconds: days_to_seconds(self.config.firewall.max_ban_days)?,
                max_tracked_ips: self.config.firewall.max_tracked_ips,
                max_tracked_subnets: self.config.firewall.max_tracked_subnets,
                max_reputation_entries: self.config.firewall.max_reputation_entries,
                max_active_bans: self.config.firewall.max_active_bans,
            },
            ipset: BanIpSetConfig {
                command: self.config.commands.ipset.clone(),
                v4_set: self.config.firewall.set_name_v4.clone(),
                v6_set: self.config.firewall.set_name_v6.clone(),
                max_entries: 65536,
            },
            exceptions: policy.allowlist.clone(),
            files,
        })
    }
}

fn networks_overlap(left: &IpNet, right: &IpNet) -> bool {
    left.contains(&right.addr()) || right.contains(&left.addr())
}

fn network_covers(outer: &IpNet, inner: &IpNet) -> bool {
    outer.addr().is_ipv4() == inner.addr().is_ipv4()
        && outer.prefix_len() <= inner.prefix_len()
        && outer.contains(&inner.addr())
}

fn validate_policy(policy: &FirewallPolicy) -> Result<()> {
    let mut ids = HashSet::new();
    let mut names = HashSet::new();
    for rule in &policy.rules {
        if rule.id.is_nil() {
            bail!("firewall rule IDs must be non-nil");
        }
        if !ids.insert(rule.id) {
            bail!("firewall rule ID `{}` is duplicated", rule.id);
        }
        let name = rule.name.trim();
        if name.is_empty() {
            bail!("firewall rule names cannot be empty");
        }
        if !names.insert(name.to_owned()) {
            bail!("firewall rule name `{name}` is duplicated");
        }
    }
    for network in &policy.allowlist {
        let suspicious = match network {
            IpNet::V4(network) => {
                !network.addr().is_private()
                    && !network.addr().is_loopback()
                    && network.prefix_len() < 16
            }
            IpNet::V6(network) => {
                !network.addr().is_loopback()
                    && (network.addr().segments()[0] & 0xfe00) != 0xfc00
                    && network.prefix_len() < 48
            }
        };
        if suspicious {
            bail!("public allowlist entry `{network}` is suspiciously broad");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn detects_overlapping_networks() {
        let a: IpNet = "192.168.1.0/24".parse().unwrap();
        let b: IpNet = "192.168.1.42/32".parse().unwrap();
        let c: IpNet = "192.168.2.0/24".parse().unwrap();
        assert!(networks_overlap(&a, &b));
        assert!(!networks_overlap(&a, &c));
        assert!(network_covers(&a, &b));
        assert!(!network_covers(&b, &a));
    }

    #[tokio::test]
    async fn start_skips_when_disabled_or_empty_files() {
        let mut config = AppConfig::default();
        config
            .apply_test_mode(std::path::Path::new("test-config.toml"))
            .unwrap();
        let stores = Stores::load(&config).await.unwrap();
        let manager = FirewallManager::new(config, stores).await.unwrap();

        // Set policy disabled in stores and verify start does not launch engine
        let disabled_policy = FirewallPolicy {
            enabled: false,
            observe_only: false,
            rules: vec![],
            allowlist: vec![],
        };
        *manager.stores.firewall_policy.write().await = disabled_policy.clone();
        manager.update_policy(&disabled_policy).await.unwrap();
        manager.start().await;
        assert!(manager.inner.read().await.is_none());

        // Policy enabled but 0 rules/files
        let empty_rules_policy = FirewallPolicy {
            enabled: true,
            observe_only: false,
            rules: vec![],
            allowlist: vec![],
        };
        *manager.stores.firewall_policy.write().await = empty_rules_policy.clone();
        manager.update_policy(&empty_rules_policy).await.unwrap();
        assert!(manager.inner.read().await.is_none());
    }

    #[tokio::test]
    async fn shipped_policy_compiles_against_raw_log_fixtures() {
        let root = std::env::current_dir().unwrap();
        let mut config = AppConfig::default();
        config
            .apply_test_mode(&root.join("config/router-hub.toml"))
            .unwrap();
        let data = tempdir().unwrap();
        config.paths.data_dir = data.path().to_path_buf();
        let fixture_root = root.join("test-fixtures/logs/nginx");
        config.firewall.log_dirs = vec![fixture_root.clone()];
        let stores = Stores::load(&config).await.unwrap();
        let manager = FirewallManager::new(config, stores).await.unwrap();
        let mut policy: FirewallPolicy = serde_json::from_slice(
            &std::fs::read(root.join("config/firewall-policy.example.json")).unwrap(),
        )
        .unwrap();
        for rule in &mut policy.rules {
            for path in &mut rule.log_paths {
                *path = fixture_root.join(path.file_name().unwrap());
            }
        }

        validate_policy(&policy).unwrap();
        let engine_config = manager.build_ban_attack_config(&policy).unwrap();
        crate::ban_attack::validate_config(engine_config).unwrap();
    }
}
