use std::{fs, net::IpAddr, sync::Arc, thread, time::Duration};

use ipnet::IpNet;
use router_hub::ban_attack::{
    AggregationConfig, BanEngine, BanTarget, Config, FileConfig, FirewallConfig, IpSetConfig,
    MemoryBanBackend, PersistentState, RuleConfig, StartAt,
};
use tempfile::tempdir;

#[test]
fn tails_and_bans_with_memory_backend() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("app.log");
    fs::write(&path, b"").unwrap();

    let config = Config {
        poll_interval_ms: 10,
        regex_dfa_cache_bytes: 1024 * 1024,
        regex_size_limit_bytes: 1024 * 1024,
        test_mode: true,
        persistence_file: None,
        persist_interval_seconds: 30,
        cleanup_interval_seconds: 60,
        max_status_entries: 100,
        command_queue_capacity: 128,
        command_timeout_seconds: 5,
        log_dirs: vec![dir.path().to_path_buf()],
        max_read_bytes_per_file_poll: 262_144,
        max_lines_per_file_poll: 1_000,
        max_line_bytes: 16_384,
        firewall: FirewallConfig::default(),
        aggregation: AggregationConfig {
            ip_failures: 2,
            subnet_failures: 100,
            promote_after_banned_ips: 2,
            ipv4_prefix: 24,
            ipv6_prefix: 64,
            ..AggregationConfig::default()
        },
        ipset: IpSetConfig::default(),
        exceptions: vec![],
        files: vec![FileConfig {
            path: path.clone(),
            start_at: StartAt::End,
            rules: vec![RuleConfig {
                name: "failure".to_owned(),
                regex: r"failure ip=(?P<ip>[0-9.]+)".to_owned(),
                ip_group: "ip".to_owned(),
                group_values: Default::default(),
                weight: 1,
            }],
        }],
    };

    let backend = Arc::new(MemoryBanBackend::default());
    let engine = BanEngine::start_with_backend(config, backend.clone()).unwrap();

    let mut file = fs::OpenOptions::new().append(true).open(&path).unwrap();
    use std::io::Write;
    writeln!(file, "failure ip=192.0.2.10").unwrap();
    writeln!(file, "failure ip=192.0.2.10").unwrap();
    file.flush().unwrap();

    let target = BanTarget::Ip("192.0.2.10".parse().unwrap());
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while std::time::Instant::now() < deadline && !backend.entries().contains(&target) {
        thread::sleep(Duration::from_millis(10));
    }

    assert!(backend.entries().contains(&target));
    engine.shutdown().unwrap();
}

#[test]
fn shipped_xmlrpc_trap_causes_exactly_one_immediate_ban() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("traps.log");
    fs::write(
        &path,
        b"75.119.132.40 - - [30/Jul/2026:19:00:00 +0000] \"GET /xmlrpc.php HTTP/1.1\" 444 0 \"-\" \"Mozilla/5.0\" trap=\"1\" badbot=\"0\"\n",
    )
    .unwrap();
    let config = Config {
        poll_interval_ms: 10,
        regex_dfa_cache_bytes: 1024 * 1024,
        regex_size_limit_bytes: 1024 * 1024,
        test_mode: true,
        persistence_file: None,
        persist_interval_seconds: 30,
        cleanup_interval_seconds: 60,
        max_status_entries: 100,
        command_queue_capacity: 128,
        command_timeout_seconds: 5,
        log_dirs: vec![dir.path().to_path_buf()],
        max_read_bytes_per_file_poll: 262_144,
        max_lines_per_file_poll: 1_000,
        max_line_bytes: 16_384,
        firewall: FirewallConfig::default(),
        aggregation: AggregationConfig::default(),
        ipset: IpSetConfig::default(),
        exceptions: vec![],
        files: vec![FileConfig {
            path,
            start_at: StartAt::Beginning,
            rules: vec![
                RuleConfig {
                    name: "trap".into(),
                    regex: r#"^(?P<ip>[0-9A-Fa-f:.]+).*trap="1""#.into(),
                    ip_group: "ip".into(),
                    group_values: Default::default(),
                    weight: 5,
                },
                RuleConfig {
                    name: "badbot".into(),
                    regex: r#"^(?P<ip>[0-9A-Fa-f:.]+).*badbot="1""#.into(),
                    ip_group: "ip".into(),
                    group_values: Default::default(),
                    weight: 2,
                },
            ],
        }],
    };
    let backend = Arc::new(MemoryBanBackend::default());
    let engine = BanEngine::start_with_backend(config, backend).unwrap();
    thread::sleep(Duration::from_millis(100));
    let snapshot = engine.handle().snapshot().unwrap();

    assert_eq!(snapshot.active_ban_count, 1);
    assert_eq!(
        snapshot.ip_counts,
        vec![("75.119.132.40".parse().unwrap(), 5)]
    );
    engine.shutdown().unwrap();
}

#[test]
fn test_mode_command_simulation_succeeds_without_root() {
    let dir = tempdir().unwrap();
    let log_path = dir.path().join("auth.log");
    fs::write(
        &log_path,
        "Failed password for root from 192.0.2.45 port 22 ssh2\n",
    )
    .unwrap();

    let config = Config {
        poll_interval_ms: 50,
        regex_dfa_cache_bytes: 1024 * 1024,
        regex_size_limit_bytes: 1024 * 1024,
        test_mode: true,
        persistence_file: None,
        persist_interval_seconds: 30,
        cleanup_interval_seconds: 60,
        max_status_entries: 100,
        command_queue_capacity: 128,
        command_timeout_seconds: 5,
        log_dirs: vec![dir.path().to_path_buf()],
        max_read_bytes_per_file_poll: 262_144,
        max_lines_per_file_poll: 1_000,
        max_line_bytes: 16_384,
        firewall: FirewallConfig {
            enabled: true,
            observe_only: false,
            iptables_command: "/bin/false".into(),
            ip6tables_command: "/bin/false".into(),
            protect_input: true,
            protect_forward: true,
            reverify_interval_seconds: 60,
            command_timeout_seconds: 5,
        },
        aggregation: AggregationConfig {
            ip_failures: 1,
            subnet_failures: 50,
            promote_after_banned_ips: 2,
            ipv4_prefix: 24,
            ipv6_prefix: 64,
            ..AggregationConfig::default()
        },
        ipset: IpSetConfig {
            command: "/bin/false".into(),
            v4_set: "test_ban_v4".into(),
            v6_set: "test_ban_v6".into(),
            max_entries: 1000,
        },
        exceptions: vec![],
        files: vec![FileConfig {
            path: log_path.clone(),
            start_at: StartAt::Beginning,
            rules: vec![RuleConfig {
                name: "ssh-fail".into(),
                regex: r"Failed password for .* from (?P<ip>[0-9A-Fa-f:.]+)".into(),
                ip_group: "ip".into(),
                group_values: Default::default(),
                weight: 1,
            }],
        }],
    };

    let engine = BanEngine::start(config.clone()).unwrap();
    let handle = engine.handle();

    thread::sleep(Duration::from_millis(300));
    let snapshot = handle.snapshot().unwrap();
    let target_ip: IpAddr = "192.0.2.45".parse().unwrap();
    assert_eq!(snapshot.banned_ips, vec![target_ip]);
    engine.shutdown().unwrap();
}

#[test]
fn ban_persistence_saves_and_restores_bans_across_restarts() {
    let dir = tempdir().unwrap();
    let log_path = dir.path().join("app.log");
    let state_path = dir.path().join("bans_persistent.json");

    fs::write(&log_path, "Invalid login attempt from 198.51.100.10\n").unwrap();

    let config = Config {
        poll_interval_ms: 50,
        regex_dfa_cache_bytes: 1024 * 1024,
        regex_size_limit_bytes: 1024 * 1024,
        test_mode: true,
        persistence_file: Some(state_path.clone()),
        persist_interval_seconds: 30,
        cleanup_interval_seconds: 60,
        max_status_entries: 100,
        command_queue_capacity: 128,
        command_timeout_seconds: 5,
        log_dirs: vec![dir.path().to_path_buf()],
        max_read_bytes_per_file_poll: 262_144,
        max_lines_per_file_poll: 1_000,
        max_line_bytes: 16_384,
        firewall: FirewallConfig::default(),
        aggregation: AggregationConfig {
            ip_failures: 1,
            subnet_failures: 50,
            promote_after_banned_ips: 2,
            ipv4_prefix: 24,
            ipv6_prefix: 64,
            ..AggregationConfig::default()
        },
        ipset: IpSetConfig::default(),
        exceptions: vec![],
        files: vec![FileConfig {
            path: log_path.clone(),
            start_at: StartAt::Beginning,
            rules: vec![RuleConfig {
                name: "app-fail".into(),
                regex: r"Invalid login attempt from (?P<ip>[0-9A-Fa-f:.]+)".into(),
                ip_group: "ip".into(),
                group_values: Default::default(),
                weight: 1,
            }],
        }],
    };

    // First run: triggers ban and persists state
    {
        let engine = BanEngine::start(config.clone()).unwrap();
        thread::sleep(Duration::from_millis(300));
        let snapshot = engine.handle().snapshot().unwrap();
        let target_ip: IpAddr = "198.51.100.10".parse().unwrap();
        assert_eq!(snapshot.banned_ips, vec![target_ip]);
        engine.shutdown().unwrap();
    }

    // Verify persistence file exists and contains banned IP
    assert!(state_path.exists());
    let file_content = fs::read_to_string(&state_path).unwrap();
    let saved_state: PersistentState = serde_json::from_str(&file_content).unwrap();
    let target_ip: IpAddr = "198.51.100.10".parse().unwrap();
    assert_eq!(
        saved_state
            .active_bans
            .iter()
            .map(|ban| ban.network)
            .collect::<Vec<_>>(),
        vec![IpNet::from(target_ip)]
    );

    // Second run: start engine with empty log file, should restore saved ban from persistence file
    let empty_log = dir.path().join("empty.log");
    fs::write(&empty_log, "").unwrap();

    let mut restored_config = config.clone();
    restored_config.files[0].path = empty_log;
    restored_config.files[0].start_at = StartAt::End;

    let engine2 = BanEngine::start(restored_config).unwrap();
    let restored_snapshot = engine2.handle().snapshot().unwrap();
    assert_eq!(restored_snapshot.banned_ips, vec![target_ip]);
    engine2.shutdown().unwrap();
}

#[test]
fn graceful_shutdown_flushes_subthreshold_scores() {
    let dir = tempdir().unwrap();
    let log_path = dir.path().join("scores.log");
    let state_path = dir.path().join("ban-attack-state.json");
    fs::write(
        &log_path,
        "failure ip=192.0.2.90\nfailure ip=192.0.2.90\nfailure ip=192.0.2.90\nfailure ip=192.0.2.90\n",
    )
    .unwrap();
    let config = Config {
        poll_interval_ms: 10,
        regex_dfa_cache_bytes: 1024 * 1024,
        regex_size_limit_bytes: 1024 * 1024,
        test_mode: true,
        persistence_file: Some(state_path.clone()),
        persist_interval_seconds: 3600,
        cleanup_interval_seconds: 60,
        max_status_entries: 100,
        command_queue_capacity: 128,
        command_timeout_seconds: 5,
        log_dirs: vec![dir.path().to_path_buf()],
        max_read_bytes_per_file_poll: 262_144,
        max_lines_per_file_poll: 1_000,
        max_line_bytes: 16_384,
        firewall: FirewallConfig::default(),
        aggregation: AggregationConfig {
            ip_failures: 5,
            ..AggregationConfig::default()
        },
        ipset: IpSetConfig::default(),
        exceptions: vec![],
        files: vec![FileConfig {
            path: log_path,
            start_at: StartAt::Beginning,
            rules: vec![RuleConfig {
                name: "score".into(),
                regex: r"failure ip=(?P<ip>[0-9.]+)".into(),
                ip_group: "ip".into(),
                group_values: Default::default(),
                weight: 1,
            }],
        }],
    };
    let engine = BanEngine::start(config).unwrap();
    thread::sleep(Duration::from_millis(150));
    engine.shutdown().unwrap();

    let state: PersistentState = serde_json::from_slice(&fs::read(state_path).unwrap()).unwrap();
    assert_eq!(state.scores.len(), 1);
    assert_eq!(state.scores[0].score, 4);
    assert!(state.active_bans.is_empty());
}
