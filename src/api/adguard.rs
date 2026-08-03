use std::{net::IpAddr, time::Duration};

use axum::{Json, extract::State};
use serde::{Deserialize, Serialize};

use crate::{
    adguard::{AdGuardClient, get_lan_ip, has_underscore_domain},
    api::ApiError,
    config::AdGuardConfig,
    models::ApiMessage,
    nginx,
    state::AppState,
};

#[derive(Serialize)]
pub struct AdGuardInfo {
    pub enabled: bool,
    pub api_endpoint: String,
    pub username: String,
    pub lan_ip: String,
    pub launch_url: String,
}

#[derive(Deserialize)]
pub struct ProtectionRequest {
    pub enabled: bool,
    pub duration_minutes: Option<u64>,
}

#[derive(Deserialize)]
pub struct UpdateAdGuardRequest {
    pub enabled: bool,
    pub api_endpoint: String,
    pub username: String,
    pub password: Option<String>,
    pub lan_ip: String,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct RewriteEntry {
    pub domain: String,
    pub answer: String,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct HostsEntry {
    pub ip: String,
    pub hostnames: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct DnsmasqHostEntry {
    pub mac: String,
    pub hostname: String,
    pub ip: String,
}

fn validate_hostname(hostname: &str) -> bool {
    !hostname.is_empty()
        && hostname.len() <= 253
        && !hostname.starts_with('.')
        && !hostname.ends_with('.')
        && !hostname.chars().any(|c| c.is_whitespace() || c == '#')
}

fn parse_hosts(content: &str) -> Result<Vec<HostsEntry>, ApiError> {
    let mut entries = Vec::new();
    for (line_number, line) in content.lines().enumerate() {
        let line = line.split('#').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }
        let mut fields = line.split_whitespace();
        let ip = fields.next().unwrap_or_default();
        if ip.parse::<IpAddr>().is_err() {
            return Err(ApiError::internal(anyhow::anyhow!(
                "invalid IP address on hosts.add line {}",
                line_number + 1
            )));
        }
        let hostnames: Vec<_> = fields.map(str::to_string).collect();
        if hostnames.is_empty() || hostnames.iter().any(|host| !validate_hostname(host)) {
            return Err(ApiError::internal(anyhow::anyhow!(
                "invalid hostname on hosts.add line {}",
                line_number + 1
            )));
        }
        entries.push(HostsEntry {
            ip: ip.to_string(),
            hostnames,
        });
    }
    Ok(entries)
}

fn hosts_content(entries: &[HostsEntry]) -> Result<String, ApiError> {
    let mut content = String::new();
    for entry in entries {
        if entry.ip.parse::<IpAddr>().is_err()
            || entry.hostnames.is_empty()
            || entry.hostnames.iter().any(|host| !validate_hostname(host))
        {
            return Err(ApiError::bad_request(
                "each hosts.add entry requires a valid IP and one or more hostnames",
            ));
        }
        content.push_str(&entry.ip);
        for hostname in &entry.hostnames {
            content.push(' ');
            content.push_str(hostname);
        }
        content.push('\n');
    }
    Ok(content)
}

fn validate_dnsmasq_field(value: &str, label: &str) -> Result<(), ApiError> {
    if value.is_empty() || value.chars().any(|c| c.is_whitespace() || ",#".contains(c)) {
        return Err(ApiError::bad_request(format!("invalid dnsmasq {label}")));
    }
    Ok(())
}

fn parse_dnsmasq_hosts(content: &str) -> Result<Vec<DnsmasqHostEntry>, ApiError> {
    let mut entries = Vec::new();
    for (line_number, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if !trimmed.starts_with("dhcp-host=") {
            continue;
        }
        let fields: Vec<_> = trimmed["dhcp-host=".len()..].split(',').collect();
        if fields.len() < 4 {
            return Err(ApiError::internal(anyhow::anyhow!(
                "invalid dhcp-host line {}",
                line_number + 1
            )));
        }
        let mac = fields[0].trim().to_string();
        let hostname = fields[2].trim().to_string();
        let ip = fields[3]
            .split('#')
            .next()
            .unwrap_or_default()
            .trim()
            .to_string();
        validate_dnsmasq_field(&mac, "MAC address")?;
        validate_hostname(&hostname).then_some(()).ok_or_else(|| {
            ApiError::internal(anyhow::anyhow!(
                "invalid hostname on dhcp-host line {}",
                line_number + 1
            ))
        })?;
        if ip.parse::<IpAddr>().is_err() {
            return Err(ApiError::internal(anyhow::anyhow!(
                "invalid IP address on dhcp-host line {}",
                line_number + 1
            )));
        }
        entries.push(DnsmasqHostEntry { mac, hostname, ip });
    }
    Ok(entries)
}

fn dnsmasq_hosts_content(entries: &[DnsmasqHostEntry]) -> Result<String, ApiError> {
    let mut content = String::new();
    for entry in entries {
        validate_dnsmasq_field(entry.mac.trim(), "MAC address")?;
        validate_hostname(entry.hostname.trim())
            .then_some(())
            .ok_or_else(|| ApiError::bad_request("invalid dnsmasq hostname"))?;
        if entry.ip.parse::<IpAddr>().is_err() {
            return Err(ApiError::bad_request("invalid dnsmasq IP address"));
        }
        let mac = entry.mac.trim();
        content.push_str(&format!(
            "dhcp-host={mac},set:{mac},{},{}\n",
            entry.hostname.trim(),
            entry.ip
        ));
    }
    Ok(content)
}

async fn read_dnsmasq_hosts(state: &AppState) -> Result<(String, Vec<DnsmasqHostEntry>), ApiError> {
    let path = &state.config.paths.dnsmasq_conf_add;
    let content = match tokio::fs::read_to_string(path).await {
        Ok(content) => content,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(error) => return Err(ApiError::internal(error)),
    };
    let entries = parse_dnsmasq_hosts(&content)?;
    Ok((content, entries))
}

pub async fn get_dnsmasq_hosts(
    State(state): State<AppState>,
) -> Result<Json<Vec<DnsmasqHostEntry>>, ApiError> {
    Ok(Json(read_dnsmasq_hosts(&state).await?.1))
}

pub async fn update_dnsmasq_hosts(
    State(state): State<AppState>,
    Json(entries): Json<Vec<DnsmasqHostEntry>>,
) -> Result<Json<Vec<DnsmasqHostEntry>>, ApiError> {
    let (existing, _) = read_dnsmasq_hosts(&state).await?;
    let managed = dnsmasq_hosts_content(&entries)?;
    let mut content = String::new();
    let mut inserted = false;
    for line in existing.lines() {
        if line.trim().starts_with("dhcp-host=") {
            if !inserted {
                content.push_str(&managed);
                inserted = true;
            }
            continue;
        }
        content.push_str(line);
        content.push('\n');
    }
    if !inserted {
        content.push_str(&managed);
    }
    crate::nginx::atomic_write(&state.config.paths.dnsmasq_conf_add, content.as_bytes())
        .map_err(ApiError::internal)?;
    let result = state
        .runner
        .run(
            &state.config.commands.service,
            ["dnsmasq", "restart"],
            Duration::from_secs(30),
        )
        .await
        .map_err(ApiError::internal)?;
    if !result.success {
        return Err(ApiError::conflict(format!(
            "dnsmasq restart failed: {}",
            result.stderr
        )));
    }
    Ok(Json(entries))
}

pub async fn get_hosts(State(state): State<AppState>) -> Result<Json<Vec<HostsEntry>>, ApiError> {
    let path = &state.config.paths.hosts_add;
    let content = match tokio::fs::read_to_string(path).await {
        Ok(content) => content,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(error) => return Err(ApiError::internal(error)),
    };
    Ok(Json(parse_hosts(&content)?))
}

pub async fn update_hosts(
    State(state): State<AppState>,
    Json(entries): Json<Vec<HostsEntry>>,
) -> Result<Json<Vec<HostsEntry>>, ApiError> {
    let content = hosts_content(&entries)?;
    crate::nginx::atomic_write(&state.config.paths.hosts_add, content.as_bytes())
        .map_err(ApiError::internal)?;
    let result = state
        .runner
        .run(
            &state.config.commands.service,
            ["dnsmasq", "restart"],
            Duration::from_secs(30),
        )
        .await
        .map_err(ApiError::internal)?;
    if !result.success {
        return Err(ApiError::conflict(format!(
            "dnsmasq restart failed: {}",
            result.stderr
        )));
    }
    Ok(Json(entries))
}

pub async fn get_effective_config(state: &AppState) -> AdGuardConfig {
    let mut config = if let Some(saved) = &*state.stores.adguard.read().await {
        saved.clone()
    } else {
        state.config.adguard.clone()
    };

    if config.lan_ip.is_empty() || config.lan_ip == "192.168.1.1" {
        let fetched_ip = get_lan_ip(&state.runner, &state.config.commands.nvram).await;
        if config.lan_ip.is_empty()
            || (fetched_ip != "192.168.1.1" && config.lan_ip == "192.168.1.1")
        {
            config.lan_ip = fetched_ip;
        }
    }
    config
}

pub async fn get_config(State(state): State<AppState>) -> Json<AdGuardInfo> {
    let cfg = get_effective_config(&state).await;
    let launch_url = if !cfg.api_endpoint.trim().is_empty() {
        cfg.api_endpoint.clone()
    } else {
        format!("http://{}:3000", cfg.lan_ip)
    };

    Json(AdGuardInfo {
        enabled: cfg.enabled,
        api_endpoint: cfg.api_endpoint,
        username: cfg.username,
        lan_ip: cfg.lan_ip,
        launch_url,
    })
}

pub async fn update_config(
    State(state): State<AppState>,
    Json(req): Json<UpdateAdGuardRequest>,
) -> Result<Json<ApiMessage>, ApiError> {
    let mut current = get_effective_config(&state).await;
    current.enabled = req.enabled;
    current.api_endpoint = req.api_endpoint;
    current.username = req.username;
    if let Some(pwd) = req.password {
        if !pwd.is_empty() || current.password.is_empty() {
            current.password = pwd;
        }
    }
    current.lan_ip = req.lan_ip;

    *state.stores.adguard.write().await = Some(current);
    state
        .stores
        .save_adguard()
        .await
        .map_err(ApiError::internal)?;

    Ok(Json(ApiMessage::new("AdGuard configuration updated")))
}

pub async fn set_protection(
    State(state): State<AppState>,
    Json(req): Json<ProtectionRequest>,
) -> Result<Json<ApiMessage>, ApiError> {
    let cfg = get_effective_config(&state).await;
    if !cfg.enabled {
        return Err(ApiError::bad_request(
            "AdGuard Home integration is disabled",
        ));
    }

    let client = AdGuardClient::new(&cfg).map_err(ApiError::internal)?;

    let duration_ms = req.duration_minutes.map(|m| m * 60 * 1000);

    client
        .toggle_protection(req.enabled, duration_ms)
        .await
        .map_err(ApiError::internal)?;

    let status = if req.enabled { "enabled" } else { "disabled" };
    Ok(Json(ApiMessage::new(format!("Protection {}", status))))
}

async fn managed_domains(state: &AppState) -> Result<std::collections::HashSet<String>, ApiError> {
    let objects = nginx::list_objects(&state.config, super::nginx::nginx_running(state).await)
        .map_err(ApiError::internal)?;
    let mut domains = std::collections::HashSet::new();
    for object in objects {
        let content = nginx::read_object(&state.config, object.kind, &object.domain, &object.name)
            .map_err(ApiError::internal)?;
        let names = nginx::extract_server_names(&content);
        if names.is_empty() {
            let domain = match object.kind {
                crate::models::NginxObjectKind::Domain => object.domain,
                crate::models::NginxObjectKind::Subdomain => {
                    format!("{}.{}", object.name, object.domain)
                }
                crate::models::NginxObjectKind::Subfolder => continue,
            };
            domains.insert(domain.to_ascii_lowercase());
        } else {
            domains.extend(names.into_iter().map(|name| name.to_ascii_lowercase()));
        }
    }
    Ok(domains)
}

async fn editable_rewrites(
    state: &AppState,
    client: &AdGuardClient,
) -> Result<Vec<RewriteEntry>, ApiError> {
    let managed = managed_domains(state).await?;
    Ok(client
        .get_rewrites()
        .await
        .map_err(ApiError::internal)?
        .into_iter()
        .filter(|rewrite| {
            !has_underscore_domain(&rewrite.domain)
                && !managed.contains(&rewrite.domain.to_ascii_lowercase())
        })
        .map(|rewrite| RewriteEntry {
            domain: rewrite.domain,
            answer: rewrite.answer,
        })
        .collect())
}

pub async fn get_rewrites(
    State(state): State<AppState>,
) -> Result<Json<Vec<RewriteEntry>>, ApiError> {
    let cfg = get_effective_config(&state).await;
    if !cfg.enabled {
        return Err(ApiError::bad_request(
            "AdGuard Home integration is disabled",
        ));
    }
    let client = AdGuardClient::new(&cfg).map_err(ApiError::internal)?;
    Ok(Json(editable_rewrites(&state, &client).await?))
}

pub async fn update_rewrites(
    State(state): State<AppState>,
    Json(requested): Json<Vec<RewriteEntry>>,
) -> Result<Json<Vec<RewriteEntry>>, ApiError> {
    let cfg = get_effective_config(&state).await;
    if !cfg.enabled {
        return Err(ApiError::bad_request(
            "AdGuard Home integration is disabled",
        ));
    }
    let client = AdGuardClient::new(&cfg).map_err(ApiError::internal)?;
    let managed = managed_domains(&state).await?;
    let mut desired = Vec::new();
    for rewrite in requested {
        let domain = rewrite.domain.trim().to_string();
        let answer = rewrite.answer.trim().to_string();
        if domain.is_empty() || answer.is_empty() {
            return Err(ApiError::bad_request(
                "DNS rewrite domain and answer are required",
            ));
        }
        if has_underscore_domain(&domain) {
            return Err(ApiError::bad_request(
                "DNS rewrite domains may not contain underscores",
            ));
        }
        if managed.contains(&domain.to_ascii_lowercase()) {
            return Err(ApiError::bad_request(format!(
                "DNS rewrite for nginx site {domain} is managed by Router Hub"
            )));
        }
        let entry = RewriteEntry { domain, answer };
        if !desired.contains(&entry) {
            desired.push(entry);
        }
    }

    let existing = client.get_rewrites().await.map_err(ApiError::internal)?;
    for rewrite in existing.iter().filter(|rewrite| {
        !has_underscore_domain(&rewrite.domain)
            && !managed.contains(&rewrite.domain.to_ascii_lowercase())
            && !desired
                .iter()
                .any(|wanted| wanted.domain == rewrite.domain && wanted.answer == rewrite.answer)
    }) {
        client
            .delete_rewrite(&rewrite.domain, &rewrite.answer)
            .await
            .map_err(ApiError::internal)?;
    }
    for rewrite in &desired {
        if !existing
            .iter()
            .any(|current| current.domain == rewrite.domain && current.answer == rewrite.answer)
        {
            client
                .ensure_rewrite(&rewrite.domain, &rewrite.answer)
                .await
                .map_err(ApiError::internal)?;
        }
    }

    Ok(Json(editable_rewrites(&state, &client).await?))
}
