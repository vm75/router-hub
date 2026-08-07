use std::{
    collections::HashSet,
    path::{Component, Path, PathBuf},
    time::Duration,
};

use ipnet::IpNet;

use crate::ban_attack::{
    Error,
    config::{AggregationConfig, Config, FirewallConfig, IpSetConfig, StartAt},
    rule::CompiledRule,
};

pub(crate) struct CompiledConfig {
    pub poll_interval: Duration,
    pub persistence_file: Option<PathBuf>,
    pub persist_interval: Duration,
    pub cleanup_interval: Duration,
    pub max_status_entries: usize,
    pub max_read_bytes_per_file_poll: usize,
    pub max_lines_per_file_poll: usize,
    pub max_line_bytes: usize,
    #[allow(dead_code)]
    pub firewall: FirewallConfig,
    pub aggregation: AggregationConfig,
    pub ipset: IpSetConfig,
    pub exceptions: Vec<IpNet>,
    pub files: Vec<CompiledFile>,
}

pub(crate) struct CompiledFile {
    pub path: PathBuf,
    pub start_at: StartAt,
    pub rules: Vec<CompiledRule>,
}

impl CompiledConfig {
    pub fn compile(config: Config) -> Result<Self, Error> {
        validate(&config)?;

        let mut files = Vec::with_capacity(config.files.len());
        for file in &config.files {
            let mut rules = Vec::with_capacity(file.rules.len());
            for rule in &file.rules {
                rules.push(CompiledRule::compile(
                    rule,
                    config.regex_dfa_cache_bytes,
                    config.regex_size_limit_bytes,
                )?);
            }
            files.push(CompiledFile {
                path: file.path.clone(),
                start_at: file.start_at,
                rules,
            });
        }

        Ok(Self {
            poll_interval: Duration::from_millis(config.poll_interval_ms),
            persistence_file: config.persistence_file,
            persist_interval: Duration::from_secs(config.persist_interval_seconds),
            cleanup_interval: Duration::from_secs(config.cleanup_interval_seconds),
            max_status_entries: config.max_status_entries,
            max_read_bytes_per_file_poll: config.max_read_bytes_per_file_poll,
            max_lines_per_file_poll: config.max_lines_per_file_poll,
            max_line_bytes: config.max_line_bytes,
            firewall: config.firewall,
            aggregation: config.aggregation,
            ipset: config.ipset,
            exceptions: config.exceptions,
            files,
        })
    }

    pub fn is_exception(&self, ip: &std::net::IpAddr) -> bool {
        self.exceptions.iter().any(|network| network.contains(ip))
    }
}

fn validate(config: &Config) -> Result<(), Error> {
    if config.poll_interval_ms < 10 {
        return Err(Error::Config(
            "poll_interval_ms must be at least 10".to_owned(),
        ));
    }
    if config.persist_interval_seconds == 0
        || config.cleanup_interval_seconds == 0
        || config.max_status_entries == 0
        || config.command_queue_capacity == 0
        || config.command_timeout_seconds == 0
        || config.max_read_bytes_per_file_poll == 0
        || config.max_lines_per_file_poll == 0
        || config.max_line_bytes == 0
    {
        return Err(Error::Config(
            "persistence, command, status, and log limits must be non-zero".to_owned(),
        ));
    }
    if config.regex_dfa_cache_bytes < 1024 {
        return Err(Error::Config(
            "regex_dfa_cache_bytes must be at least 1024".to_owned(),
        ));
    }
    if config.regex_size_limit_bytes < 1024 {
        return Err(Error::Config(
            "regex_size_limit_bytes must be at least 1024".to_owned(),
        ));
    }
    if config.aggregation.ip_failures == 0 {
        return Err(Error::Config("ip_failures must be non-zero".to_owned()));
    }
    if config.aggregation.subnet_failures == 0 {
        return Err(Error::Config("subnet_failures must be non-zero".to_owned()));
    }
    if config.aggregation.promote_after_banned_ips < 2 {
        return Err(Error::Config(
            "promote_after_banned_ips must be at least 2".to_owned(),
        ));
    }
    if config.aggregation.reputation_repromote_after_offenses == 0 {
        return Err(Error::Config(
            "reputation_repromote_after_offenses must be non-zero".to_owned(),
        ));
    }
    if config.aggregation.score_retention_seconds == 0
        || config.aggregation.reputation_retention_seconds == 0
        || config.aggregation.subnet_promotion_window_seconds == 0
        || config.aggregation.subnet_ban_seconds == 0
    {
        return Err(Error::Config(
            "retention, promotion, and ban durations must be non-zero".to_owned(),
        ));
    }
    if config.aggregation.first_ban_seconds == 0
        || config.aggregation.first_ban_seconds > config.aggregation.second_ban_seconds
        || config.aggregation.second_ban_seconds > config.aggregation.third_ban_seconds
        || config.aggregation.third_ban_seconds > config.aggregation.max_ban_seconds
    {
        return Err(Error::Config(
            "ban durations must be non-zero and monotonically increasing".to_owned(),
        ));
    }
    if config.aggregation.max_tracked_ips == 0
        || config.aggregation.max_tracked_subnets == 0
        || config.aggregation.max_reputation_entries == 0
        || config.aggregation.max_active_bans == 0
    {
        return Err(Error::Config(
            "aggregation capacities must be non-zero".to_owned(),
        ));
    }
    if !(1..=32).contains(&config.aggregation.ipv4_prefix) {
        return Err(Error::Config(
            "ipv4_prefix must be between 1 and 32".to_owned(),
        ));
    }
    if !(1..=128).contains(&config.aggregation.ipv6_prefix) {
        return Err(Error::Config(
            "ipv6_prefix must be between 1 and 128".to_owned(),
        ));
    }
    if config.ipset.v4_set.trim().is_empty() || config.ipset.v6_set.trim().is_empty() {
        return Err(Error::Config("ipset names cannot be empty".to_owned()));
    }
    if config.ipset.max_entries == 0 {
        return Err(Error::Config(
            "ipset max_entries must be non-zero".to_owned(),
        ));
    }
    if config.files.is_empty() {
        return Err(Error::Config("at least one file is required".to_owned()));
    }

    let mut paths = HashSet::new();
    for file in &config.files {
        validate_log_path(&file.path, &config.log_dirs)?;
        if !paths.insert(file.path.clone()) {
            return Err(Error::Config(format!(
                "duplicate file path `{}`",
                file.path.display()
            )));
        }
        if file.rules.is_empty() {
            return Err(Error::Config(format!(
                "file `{}` has no rules",
                file.path.display()
            )));
        }
        let mut names = HashSet::new();
        for rule in &file.rules {
            if !names.insert(rule.name.clone()) {
                return Err(Error::Config(format!(
                    "file `{}` contains duplicate rule name `{}`",
                    file.path.display(),
                    rule.name
                )));
            }
        }
    }
    Ok(())
}

fn validate_log_path(path: &Path, allowed_roots: &[PathBuf]) -> Result<(), Error> {
    if !path.is_absolute() {
        return Err(Error::Config(format!(
            "log path `{}` must be absolute",
            path.display()
        )));
    }
    if path
        .to_string_lossy()
        .chars()
        .any(|character| "*?[]{}".contains(character))
    {
        return Err(Error::Config(format!(
            "log path `{}` must be exact and cannot contain glob characters",
            path.display()
        )));
    }
    if path
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(Error::Config(format!(
            "log path `{}` cannot contain parent traversal",
            path.display()
        )));
    }
    let existing_parent = nearest_existing(path).ok_or_else(|| {
        Error::Config(format!(
            "log path `{}` has no existing parent",
            path.display()
        ))
    })?;
    let canonical_parent = existing_parent.canonicalize().map_err(|error| {
        Error::Config(format!(
            "failed to resolve log path parent `{}`: {error}",
            existing_parent.display()
        ))
    })?;
    let allowed = allowed_roots.iter().any(|root| {
        root.canonicalize()
            .ok()
            .is_some_and(|canonical_root| canonical_parent.starts_with(canonical_root))
    });
    if !allowed {
        return Err(Error::Config(format!(
            "log path `{}` is outside configured firewall.log_dirs",
            path.display()
        )));
    }
    if path.exists() {
        let metadata = std::fs::symlink_metadata(path).map_err(|error| {
            Error::Config(format!(
                "failed to inspect log path `{}`: {error}",
                path.display()
            ))
        })?;
        if metadata.file_type().is_symlink() {
            return Err(Error::Config(format!(
                "log path `{}` is a symlink",
                path.display()
            )));
        }
        if !metadata.file_type().is_file() {
            return Err(Error::Config(format!(
                "log path `{}` is not a regular file",
                path.display()
            )));
        }
    }
    Ok(())
}

fn nearest_existing(path: &Path) -> Option<&Path> {
    let mut current = Some(path);
    while let Some(candidate) = current {
        if candidate.exists() {
            return Some(candidate);
        }
        current = candidate.parent();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn validate_log_path_allows_symlink_parent_dirs() {
        let dir = tempdir().unwrap();
        let real_dir = dir.path().join("real_opt");
        let sym_dir = dir.path().join("opt");
        std::fs::create_dir_all(&real_dir).unwrap();
        std::os::unix::fs::symlink(&real_dir, &sym_dir).unwrap();

        let log_file = sym_dir.join("access.log");
        std::fs::write(real_dir.join("access.log"), b"test").unwrap();

        let allowed_roots = vec![sym_dir.clone()];
        assert!(validate_log_path(&log_file, &allowed_roots).is_ok());
    }

    #[test]
    fn validate_log_path_rejects_symlink_file() {
        let dir = tempdir().unwrap();
        let real_file = dir.path().join("real.log");
        let sym_file = dir.path().join("sym.log");
        std::fs::write(&real_file, b"test").unwrap();
        std::os::unix::fs::symlink(&real_file, &sym_file).unwrap();

        let allowed_roots = vec![dir.path().to_path_buf()];
        let err = validate_log_path(&sym_file, &allowed_roots).unwrap_err();
        assert!(err.to_string().contains("symlink"));
    }
}
