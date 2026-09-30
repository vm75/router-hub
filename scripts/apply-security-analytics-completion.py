#!/usr/bin/env python3
from pathlib import Path


def replace(path: str, old: str, new: str, count: int = 1) -> None:
    file = Path(path)
    text = file.read_text()
    actual = text.count(old)
    if actual != count:
        raise SystemExit(
            f"{path}: expected {count} occurrence(s), found {actual}: {old[:120]!r}"
        )
    file.write_text(text.replace(old, new, count))


# Pass live stores to analytics so the strict outbound scanner can compare
# against locally configured certificate-hook and AdGuard secrets.
replace(
    "src/main.rs",
    "let analytics = AnalyticsManager::initialize(config.clone()).await?;",
    "let analytics = AnalyticsManager::initialize(config.clone(), stores.clone()).await?;",
)

# Model: retain the latest engine state in each rollup so history/UI can show it.
replace(
    "src/analytics/model.rs",
    """    pub repeat_offender_bans: usize,\n    pub engine_errors: u64,""",
    """    pub repeat_offender_bans: usize,\n    pub engine_state: String,\n    pub engine_errors: u64,""",
)
replace(
    "src/analytics/model.rs",
    """            repeat_offender_bans: 0,\n            engine_errors: 0,""",
    """            repeat_offender_bans: 0,\n            engine_state: String::new(),\n            engine_errors: 0,""",
)

# AI transport: scan and size-gate the exact final JSON request body against a
# caller-provided bounded set of locally known secrets.
replace(
    "src/analytics/ai.rs",
    """pub fn validate_request_body(\n    settings: &AiSettings,\n    request: &Value,\n    router_auth_token: &str,\n) -> Result<Vec<u8>> {""",
    """pub fn validate_request_body(\n    settings: &AiSettings,\n    request: &Value,\n    secrets: &[String],\n) -> Result<Vec<u8>> {""",
)
replace(
    "src/analytics/ai.rs",
    """    scan_outbound_payload(\n        &request_bytes,\n        &[router_auth_token, settings.api_key.as_str()],\n    )?;""",
    """    let secret_refs: Vec<&str> = secrets.iter().map(String::as_str).collect();\n    scan_outbound_payload(&request_bytes, &secret_refs)?;""",
)
replace(
    "src/analytics/ai.rs",
    """pub async fn analyze(\n    settings: &AiSettings,\n    payload: &Value,\n    router_auth_token: &str,\n    test_mode: bool,\n) -> Result<AiCallResult> {""",
    """pub async fn analyze(\n    settings: &AiSettings,\n    payload: &Value,\n    secrets: &[String],\n    test_mode: bool,\n) -> Result<AiCallResult> {""",
)
replace(
    "src/analytics/ai.rs",
    "let request_bytes = validate_request_body(settings, &request, router_auth_token)?;",
    "let request_bytes = validate_request_body(settings, &request, secrets)?;",
)
replace(
    "src/analytics/ai.rs",
    """    #[test]\n    fn sensitive_custom_headers_are_rejected() {\n        let mut settings = AiSettings::default();\n        settings\n            .additional_headers\n            .insert(\"X-Api-Key\".into(), \"secret\".into());\n        assert!(validate_ai_settings(&settings, false).is_err());\n    }\n}""",
    """    #[test]\n    fn sensitive_custom_headers_are_rejected() {\n        let mut settings = AiSettings::default();\n        settings\n            .additional_headers\n            .insert(\"X-Api-Key\".into(), \"secret\".into());\n        assert!(validate_ai_settings(&settings, false).is_err());\n    }\n\n    #[test]\n    fn final_request_body_is_scanned_for_local_secrets() {\n        let settings = AiSettings::default();\n        let payload = serde_json::json!({\"note\": \"certificate-hook-secret-123\"});\n        let request = request_json(&settings, &payload).unwrap();\n        let secrets = vec![\"certificate-hook-secret-123\".to_owned()];\n        assert!(validate_request_body(&settings, &request, &secrets).is_err());\n    }\n}""",
)

# Privacy scanner: cover common serialized-header/session/private-key shapes and
# ensure obvious email/IP path identifiers are removed before sampling.
replace(
    "src/analytics/privacy.rs",
    """        \"authorization:\",\n        \"proxy-authorization:\",\n        \"cookie:\",\n        \"set-cookie:\",\n        \"bearer \",\n        \"basic \",\n        \"-----begin private key\",\n        \"-----begin rsa private key\",\n        \"password=\",\n        \"password\\\":\",\n        \"secret=\",\n        \"secret\\\":\",\n        \"token=\",""",
    """        \"authorization:\",\n        \"\\\"authorization\\\":\",\n        \"proxy-authorization:\",\n        \"\\\"proxy-authorization\\\":\",\n        \"cookie:\",\n        \"\\\"cookie\\\":\",\n        \"set-cookie:\",\n        \"\\\"set-cookie\\\":\",\n        \"bearer \",\n        \"basic \",\n        \"-----begin private key\",\n        \"-----begin rsa private key\",\n        \"-----begin openssh private key\",\n        \"password=\",\n        \"password\\\":\",\n        \"secret=\",\n        \"secret\\\":\",\n        \"token=\",\n        \"sessionid=\",\n        \"\\\"session\\\":\",""",
)
replace(
    "src/analytics/privacy.rs",
    """        if segment.chars().all(|character| character.is_ascii_digit()) {\n            sanitized.push_str(\":id\");\n        } else if looks_like_uuid(segment) {\n            sanitized.push_str(\":uuid\");\n        } else if looks_like_secret_segment(segment) {\n            sanitized.push_str(\":token\");""",
    """        if segment.chars().all(|character| character.is_ascii_digit()) {\n            sanitized.push_str(\":id\");\n        } else if looks_like_uuid(segment) {\n            sanitized.push_str(\":uuid\");\n        } else if segment.parse::<IpAddr>().is_ok() {\n            sanitized.push_str(\":ip\");\n        } else if segment.contains('@') {\n            sanitized.push_str(\":id\");\n        } else if looks_like_secret_segment(segment) {\n            sanitized.push_str(\":token\");""",
)
replace(
    "src/analytics/privacy.rs",
    """    #[test]\n    fn manual_hmac_is_deterministic() {\n        let digest = hmac_sha256(b\"key\", b\"data\");\n        assert_eq!(hex_encode(&digest).len(), 64);\n        assert_eq!(hex_decode_32(&hex_encode(&digest)), Some(digest));\n    }\n}""",
    """    #[test]\n    fn manual_hmac_is_deterministic() {\n        let digest = hmac_sha256(b\"key\", b\"data\");\n        assert_eq!(hex_encode(&digest).len(), 64);\n        assert_eq!(hex_decode_32(&hex_encode(&digest)), Some(digest));\n    }\n\n    #[test]\n    fn scanner_rejects_adversarial_secret_shapes() {\n        for payload in [\n            br#\"{\\\"Authorization\\\":\\\"Bearer abcdefgh\\\"}\"#.as_slice(),\n            br#\"{\\\"cookie\\\":\\\"sessionid=abcdefgh\\\"}\"#.as_slice(),\n            br#\"{\\\"password\\\":\\\"abcdefgh\\\"}\"#.as_slice(),\n            b\"-----BEGIN OPENSSH PRIVATE KEY-----\".as_slice(),\n        ] {\n            assert!(scan_outbound_payload(payload, &[]).is_err());\n        }\n    }\n\n    #[test]\n    fn paths_remove_email_ip_uuid_and_token_identifiers() {\n        assert_eq!(\n            sanitize_path(Some(\"/user/alice@example.com\"), 256).as_deref(),\n            Some(\"/user/:id\")\n        );\n        assert_eq!(\n            sanitize_path(Some(\"/host/192.168.1.25\"), 256).as_deref(),\n            Some(\"/host/:ip\")\n        );\n        assert_eq!(\n            sanitize_path(\n                Some(\"/item/550e8400-e29b-41d4-a716-446655440000\"),\n                256\n            )\n            .as_deref(),\n            Some(\"/item/:uuid\")\n        );\n        assert_eq!(\n            sanitize_path(Some(\"/reset/AbCdEfGhIjKlMnOpQrSt1234\"), 256).as_deref(),\n            Some(\"/reset/:token\")\n        );\n    }\n}""",
)

# Core manager: retain engine state, scan against live secrets, establish a
# kernel baseline immediately after enable, and explicitly verify parent hooks
# at a lower cadence while keeping the process-launch budget below 4/hour.
replace(
    "src/analytics/mod.rs",
    """    firewall::FirewallManager,\n    models::FirewallStatus,\n};""",
    """    firewall::FirewallManager,\n    models::FirewallStatus,\n    storage::Stores,\n};""",
)
replace(
    "src/analytics/mod.rs",
    """const MAX_AI_RECORDS: usize = 30;""",
    """const MAX_AI_RECORDS: usize = 30;\nconst RULE_COMMENT: &str = \"router-hub:ban-attack\";\nconst HOOK_VERIFY_EVERY_KERNEL_RUNS: u64 = 3;\nconst MAX_OUTBOUND_SECRET_VALUES: usize = 128;""",
)
replace(
    "src/analytics/mod.rs",
    """    repeat_offender_bans: usize,\n    engine_errors: u64,""",
    """    repeat_offender_bans: usize,\n    engine_state: String,\n    engine_errors: u64,""",
)
replace(
    "src/analytics/mod.rs",
    """            repeat_offender_bans: 0,\n            engine_errors: 0,""",
    """            repeat_offender_bans: 0,\n            engine_state: String::new(),\n            engine_errors: 0,""",
)
replace(
    "src/analytics/mod.rs",
    """            repeat_offender_bans: self.repeat_offender_bans,\n            engine_errors: self.engine_errors,""",
    """            repeat_offender_bans: self.repeat_offender_bans,\n            engine_state: self.engine_state.clone(),\n            engine_errors: self.engine_errors,""",
)
replace(
    "src/analytics/mod.rs",
    """pub struct AnalyticsManager {\n    config: Arc<AppConfig>,""",
    """pub struct AnalyticsManager {\n    config: Arc<AppConfig>,\n    stores: Stores,""",
)
replace(
    "src/analytics/mod.rs",
    """    dropped_events: Arc<AtomicU64>,\n    privacy_key: [u8; 32],""",
    """    dropped_events: Arc<AtomicU64>,\n    kernel_verify_runs: AtomicU64,\n    privacy_key: [u8; 32],""",
)
replace(
    "src/analytics/mod.rs",
    """    pub async fn initialize(config: AppConfig) -> Result<Arc<Self>> {""",
    """    pub async fn initialize(config: AppConfig, stores: Stores) -> Result<Arc<Self>> {""",
)
replace(
    "src/analytics/mod.rs",
    """        let manager = Arc::new(Self {\n            config: Arc::new(config),\n            settings: RwLock::new(settings),""",
    """        let manager = Arc::new(Self {\n            config: Arc::new(config),\n            stores,\n            settings: RwLock::new(settings),""",
)
replace(
    "src/analytics/mod.rs",
    """            dropped_events: dropped_events.clone(),\n            privacy_key,""",
    """            dropped_events: dropped_events.clone(),\n            kernel_verify_runs: AtomicU64::new(0),\n            privacy_key,""",
)
replace(
    "src/analytics/mod.rs",
    """        let mut last_kernel = Instant::now();""",
    """        let mut last_kernel = Instant::now()\n            .checked_sub(Duration::from_secs(24 * 3600))\n            .unwrap_or_else(Instant::now);""",
)
replace(
    "src/analytics/mod.rs",
    """            accumulator.repeat_offender_bans = status\n                .snapshot\n                .active_bans\n                .iter()\n                .filter(|ban| ban.offense_count >= 2)\n                .count();\n            accumulator.kernel_state_consistent =""",
    """            accumulator.repeat_offender_bans = status\n                .snapshot\n                .active_bans\n                .iter()\n                .filter(|ban| ban.offense_count >= 2)\n                .count();\n            accumulator.engine_state = format!(\"{:?}\", status.health.state).to_ascii_lowercase();\n            accumulator.kernel_state_consistent =""",
)
replace(
    "src/analytics/mod.rs",
    """        if status.policy.enabled\n            && matches!(\n                status.health.state,\n                EngineState::Degraded | EngineState::Stopped\n            )\n        {""",
    """        if status.policy.enabled\n            && matches!(\n                status.health.state,\n                EngineState::Degraded | EngineState::Stopped\n            )\n        {""",
)
# Insert stale-poll detection immediately after the engine-state finding block.
replace(
    "src/analytics/mod.rs",
    """                source: \"local\".into(),\n            });\n        }\n        if status.health.set_capacity > 0""",
    """                source: \"local\".into(),\n            });\n        }\n        if status.policy.enabled {\n            let stale_after_seconds = self\n                .config\n                .firewall\n                .poll_interval_ms\n                .saturating_mul(10)\n                .div_ceil(1000)\n                .max(30);\n            let stale = status\n                .health\n                .last_poll_at\n                .map(|last| {\n                    Utc::now().signed_duration_since(last).num_seconds()\n                        > stale_after_seconds as i64\n                })\n                .unwrap_or_else(|| {\n                    status\n                        .health\n                        .started_at\n                        .map(|started| {\n                            Utc::now().signed_duration_since(started).num_seconds()\n                                > stale_after_seconds as i64\n                        })\n                        .unwrap_or(false)\n                });\n            if stale {\n                self.add_finding(AnalyticsFinding {\n                    severity: \"critical\".into(),\n                    category: \"engine_health\".into(),\n                    title: \"Ban Shield polling is stale\".into(),\n                    evidence: vec![format!(\n                        \"no engine poll was observed within {stale_after_seconds} seconds\"\n                    )],\n                    recommendation: Some(\n                        \"Inspect Router Hub process health before relying on new log events being enforced.\"\n                            .into(),\n                    ),\n                    confidence: None,\n                    source: \"local\".into(),\n                });\n            }\n        }\n        if status.health.set_capacity > 0""",
)
# Replace the opening of kernel verification to add low-cadence parent-hook checks.
replace(
    "src/analytics/mod.rs",
    """    async fn verify_kernel(&self, status: &FirewallStatus) -> Result<()> {\n        let counters = self.collect_kernel_counters().await?;\n        let (set_v4, set_v6) = self.collect_ipset_counts().await?;""",
    """    async fn verify_kernel(&self, status: &FirewallStatus) -> Result<()> {\n        let counters = self.collect_kernel_counters().await?;\n        let (set_v4, set_v6) = self.collect_ipset_counts().await?;\n        let verify_hooks = self\n            .kernel_verify_runs\n            .fetch_add(1, Ordering::Relaxed)\n            % HOOK_VERIFY_EVERY_KERNEL_RUNS\n            == 0;\n        let hooks_consistent = if verify_hooks {\n            Some(self.collect_hook_consistency().await?)\n        } else {\n            None\n        };""",
)
replace(
    "src/analytics/mod.rs",
    """        let set_consistent = set_v4.map(|count| count == expected_v4).unwrap_or(true)\n            && set_v6.map(|count| count == expected_v6).unwrap_or(true);\n        {\n            let mut accumulator = self.accumulator.lock();\n            accumulator.kernel_state_consistent = Some(set_consistent);\n        }\n        if !set_consistent {""",
    """        let set_consistent = set_v4.map(|count| count == expected_v4).unwrap_or(true)\n            && set_v6.map(|count| count == expected_v6).unwrap_or(true);\n        let kernel_consistent = {\n            let mut accumulator = self.accumulator.lock();\n            let prior = accumulator.kernel_state_consistent.unwrap_or(true);\n            let combined = set_consistent && hooks_consistent.unwrap_or(prior);\n            accumulator.kernel_state_consistent = Some(combined);\n            combined\n        };\n        if !set_consistent {""",
)
replace(
    "src/analytics/mod.rs",
    """        }\n\n        let mut previous = self.last_kernel_counters.lock().await;""",
    """        }\n        if hooks_consistent == Some(false) {\n            self.add_finding(AnalyticsFinding {\n                severity: \"critical\".into(),\n                category: \"enforcement\".into(),\n                title: \"Router Hub firewall parent hook is missing\".into(),\n                evidence: vec![\n                    \"At least one expected INPUT/FORWARD jump into a Router Hub-owned chain is absent\"\n                        .into(),\n                ],\n                recommendation: Some(\n                    \"Run firewall reconciliation and verify the Router Hub hooks before relying on enforcement.\"\n                        .into(),\n                ),\n                confidence: None,\n                source: \"local\".into(),\n            });\n        }\n        if !kernel_consistent {\n            warn!(\"analytics kernel verification found inconsistent enforcement state\");\n        }\n\n        let mut previous = self.last_kernel_counters.lock().await;""",
    count=1,
)
# Add parent-hook command helpers before IP-set collection.
replace(
    "src/analytics/mod.rs",
    """    async fn collect_ipset_counts(&self) -> Result<(Option<usize>, Option<usize>)> {""",
    """    async fn collect_hook_consistency(&self) -> Result<bool> {\n        let timeout = Duration::from_secs(self.config.firewall.command_timeout_seconds.min(10));\n        let mut consistent = true;\n        if self.config.firewall.protect_input {\n            for command in [&self.config.commands.iptables, &self.config.commands.ip6tables] {\n                if let Some(present) = self\n                    .read_parent_hook(command, \"INPUT\", \"ROUTER_HUB_INPUT\", timeout)\n                    .await?\n                {\n                    consistent &= present;\n                }\n            }\n        }\n        if self.config.firewall.protect_forward {\n            for command in [&self.config.commands.iptables, &self.config.commands.ip6tables] {\n                if let Some(present) = self\n                    .read_parent_hook(command, \"FORWARD\", \"ROUTER_HUB_FORWARD\", timeout)\n                    .await?\n                {\n                    consistent &= present;\n                }\n            }\n        }\n        Ok(consistent)\n    }\n\n    async fn read_parent_hook(\n        &self,\n        command: &Path,\n        parent: &str,\n        owned: &str,\n        timeout: Duration,\n    ) -> Result<Option<bool>> {\n        {\n            let mut overhead = self.overhead.lock();\n            overhead.external_commands = overhead.external_commands.saturating_add(1);\n        }\n        let result = CommandRunner::new(self.config.test_mode)\n            .run(\n                command,\n                [\n                    \"-C\",\n                    parent,\n                    \"-m\",\n                    \"comment\",\n                    \"--comment\",\n                    RULE_COMMENT,\n                    \"-j\",\n                    owned,\n                ],\n                timeout,\n            )\n            .await?;\n        if result.simulated {\n            return Ok(None);\n        }\n        Ok(Some(result.success))\n    }\n\n    async fn collect_ipset_counts(&self) -> Result<(Option<usize>, Option<usize>)> {""",
)
# Preserve latest engine state across rollup boundaries.
replace(
    "src/analytics/mod.rs",
    """            let repeat = accumulator.repeat_offender_bans;\n            let consistency = accumulator.kernel_state_consistent;\n            *accumulator = Accumulator::new(now);\n            accumulator.active_ip_bans = active_ip;\n            accumulator.active_subnet_bans = active_subnet;\n            accumulator.repeat_offender_bans = repeat;\n            accumulator.kernel_state_consistent = consistency;""",
    """            let repeat = accumulator.repeat_offender_bans;\n            let engine_state = accumulator.engine_state.clone();\n            let consistency = accumulator.kernel_state_consistent;\n            *accumulator = Accumulator::new(now);\n            accumulator.active_ip_bans = active_ip;\n            accumulator.active_subnet_bans = active_subnet;\n            accumulator.repeat_offender_bans = repeat;\n            accumulator.engine_state = engine_state;\n            accumulator.kernel_state_consistent = consistency;""",
)
# Add bounded local-secret collection and use it for preview + actual AI calls.
replace(
    "src/analytics/mod.rs",
    """    pub async fn preview_ai_payload(&self) -> Result<AiPreview> {""",
    """    async fn outbound_secrets(&self, settings: &AnalyticsSettings) -> Vec<String> {\n        let mut secrets = Vec::with_capacity(24);\n        let mut push_secret = |value: &str| {\n            let value = value.trim();\n            if value.len() >= 6\n                && value.len() <= 4096\n                && secrets.len() < MAX_OUTBOUND_SECRET_VALUES\n            {\n                secrets.push(value.to_owned());\n            }\n        };\n        push_secret(&self.config.server.auth_token);\n        push_secret(&settings.ai.api_key);\n        push_secret(&self.config.adguard.password);\n        for value in settings.ai.additional_headers.values() {\n            push_secret(value);\n        }\n        if let Some(adguard) = self.stores.adguard.read().await.as_ref() {\n            push_secret(&adguard.password);\n        }\n        let certificates = self.stores.certificates.read().await;\n        for certificate in certificates.iter() {\n            for (name, value) in &certificate.hook_env {\n                if sensitive_secret_name(name) {\n                    push_secret(value);\n                }\n            }\n        }\n        secrets.sort();\n        secrets.dedup();\n        secrets\n    }\n\n    pub async fn preview_ai_payload(&self) -> Result<AiPreview> {""",
)
replace(
    "src/analytics/mod.rs",
    """        let request = ai::request_json(&settings.ai, &payload)?;\n        let bytes =\n            ai::validate_request_body(&settings.ai, &request, &self.config.server.auth_token)?;""",
    """        let request = ai::request_json(&settings.ai, &payload)?;\n        let secrets = self.outbound_secrets(&settings).await;\n        let bytes = ai::validate_request_body(&settings.ai, &request, &secrets)?;""",
)
replace(
    "src/analytics/mod.rs",
    """        let result = match ai::analyze(\n            &settings.ai,\n            &payload,\n            &self.config.server.auth_token,\n            self.config.test_mode,\n        )""",
    """        let secrets = self.outbound_secrets(&settings).await;\n        let result = match ai::analyze(\n            &settings.ai,\n            &payload,\n            &secrets,\n            self.config.test_mode,\n        )""",
)
# Enforce process budget: six regular checks every >=2h plus four hook checks
# only every third verification averages under four external processes/hour.
replace(
    "src/analytics/mod.rs",
    """    if !(3600..=86_400).contains(&settings.kernel_verify_interval_seconds) {\n        bail!(\"analytics kernel_verify_interval_seconds must be between 3600 and 86400\");\n    }""",
    """    if !(7200..=86_400).contains(&settings.kernel_verify_interval_seconds) {\n        bail!(\"analytics kernel_verify_interval_seconds must be between 7200 and 86400\");\n    }""",
)
# Add helper for selecting certificate-hook values that are actually secret-like.
replace(
    "src/analytics/mod.rs",
    """fn load_json<T>(path: &Path) -> Result<T>""",
    """fn sensitive_secret_name(name: &str) -> bool {\n    let normalized = name.trim().to_ascii_lowercase().replace('-', \"_\");\n    normalized.contains(\"token\")\n        || normalized.contains(\"secret\")\n        || normalized.contains(\"password\")\n        || normalized.contains(\"passwd\")\n        || normalized.contains(\"credential\")\n        || normalized.contains(\"api_key\")\n        || normalized.contains(\"apikey\")\n        || normalized.ends_with(\"_key\")\n}\n\nfn load_json<T>(path: &Path) -> Result<T>""",
)
# Aggregate active-state fields by taking the latest value.
replace(
    "src/analytics/mod.rs",
    """        output.repeat_offender_bans = rollup.repeat_offender_bans;\n        output.engine_errors =""",
    """        output.repeat_offender_bans = rollup.repeat_offender_bans;\n        output.engine_state = rollup.engine_state.clone();\n        output.engine_errors =""",
)
# Extend tests for the enforced process budget and secret-name classifier.
replace(
    "src/analytics/mod.rs",
    """        settings.rollup_interval_minutes = 60;\n        settings.max_samples_per_hour = 1000;\n        assert!(validate_settings(&settings, false).is_err());\n    }""",
    """        settings.rollup_interval_minutes = 60;\n        settings.max_samples_per_hour = 1000;\n        assert!(validate_settings(&settings, false).is_err());\n        settings.max_samples_per_hour = 32;\n        settings.kernel_verify_interval_seconds = 3600;\n        assert!(validate_settings(&settings, false).is_err());\n        settings.kernel_verify_interval_seconds = 7200;\n        assert!(validate_settings(&settings, false).is_ok());\n    }\n\n    #[test]\n    fn secret_name_classifier_is_conservative() {\n        assert!(sensitive_secret_name(\"DUCKDNS_TOKEN\"));\n        assert!(sensitive_secret_name(\"API_KEY\"));\n        assert!(sensitive_secret_name(\"provider-secret\"));\n        assert!(!sensitive_secret_name(\"DNS_PROVIDER\"));\n    }""",
)
