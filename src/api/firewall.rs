use axum::{
    Json,
    extract::{Path, Query, State},
};
use chrono::Utc;
use ipnet::IpNet;
use serde::Deserialize;
use uuid::Uuid;

use crate::{
    api::ApiError,
    config::days_to_seconds,
    models::{ApiMessage, BanRecord, BanRule, FirewallPolicy, FirewallStatus},
    state::AppState,
};

#[derive(Debug, Deserialize)]
pub struct StatusQuery {
    include_bans: Option<bool>,
}

pub async fn status(
    State(state): State<AppState>,
    Query(query): Query<StatusQuery>,
) -> Json<FirewallStatus> {
    let mut status = state.firewall.status().await;
    if query.include_bans == Some(false) {
        status.bans.clear();
    }
    Json(status)
}

pub async fn list_bans(State(state): State<AppState>) -> Json<Vec<BanRecord>> {
    Json(state.firewall.status().await.bans)
}

pub async fn update_policy(
    State(state): State<AppState>,
    Json(mut policy): Json<FirewallPolicy>,
) -> Result<Json<FirewallPolicy>, ApiError> {
    for rule in &mut policy.rules {
        validate_rule(rule)?;
        if rule.id.is_nil() {
            rule.id = Uuid::new_v4();
        }
    }
    state.firewall.replace_policy(policy.clone()).await?;
    Ok(Json(policy))
}

pub async fn create_rule(
    State(state): State<AppState>,
    Json(mut rule): Json<BanRule>,
) -> Result<Json<BanRule>, ApiError> {
    validate_rule(&rule)?;
    rule.id = Uuid::new_v4();
    rule.updated_at = Utc::now();
    let mut policy = state.stores.firewall_policy.read().await.clone();
    policy.rules.push(rule.clone());
    state.firewall.replace_policy(policy).await?;
    Ok(Json(rule))
}

pub async fn update_rule(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(mut rule): Json<BanRule>,
) -> Result<Json<BanRule>, ApiError> {
    validate_rule(&rule)?;
    rule.id = id;
    rule.updated_at = Utc::now();
    let mut policy = state.stores.firewall_policy.read().await.clone();
    let existing = policy
        .rules
        .iter_mut()
        .find(|rule| rule.id == id)
        .ok_or_else(|| ApiError::not_found("firewall rule not found"))?;
    *existing = rule.clone();
    state.firewall.replace_policy(policy).await?;
    Ok(Json(rule))
}

pub async fn delete_rule(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiMessage>, ApiError> {
    let mut policy = state.stores.firewall_policy.read().await.clone();
    let before = policy.rules.len();
    policy.rules.retain(|rule| rule.id != id);
    if policy.rules.len() == before {
        return Err(ApiError::not_found("firewall rule not found"));
    }
    state.firewall.replace_policy(policy).await?;
    Ok(Json(ApiMessage::new("firewall rule deleted")))
}

#[derive(Deserialize)]
pub struct NetworkRequest {
    network: String,
}

pub async fn add_allowlist(
    State(state): State<AppState>,
    Json(request): Json<NetworkRequest>,
) -> Result<Json<FirewallPolicy>, ApiError> {
    let network: IpNet = request
        .network
        .parse()
        .map_err(|error| ApiError::bad_request(format!("invalid network: {error}")))?;
    let mut policy = state.stores.firewall_policy.read().await.clone();
    if !policy.allowlist.contains(&network) {
        policy.allowlist.push(network);
    }
    let updated = policy.clone();
    state.firewall.replace_policy(policy).await?;
    Ok(Json(updated))
}

pub async fn delete_allowlist(
    State(state): State<AppState>,
    Path(network): Path<String>,
) -> Result<Json<FirewallPolicy>, ApiError> {
    let network: IpNet = network.parse().map_err(ApiError::bad_request)?;
    let mut policy = state.stores.firewall_policy.read().await.clone();
    policy.allowlist.retain(|entry| entry != &network);
    let updated = policy.clone();
    state.firewall.replace_policy(policy).await?;
    Ok(Json(updated))
}

#[derive(Deserialize)]
pub struct BanRequest {
    network: IpNet,
    #[serde(default = "default_ban")]
    seconds: u64,
    #[serde(default = "default_reason")]
    reason: String,
}

fn default_ban() -> u64 {
    3600
}
fn default_reason() -> String {
    "manual ban".into()
}

pub async fn manual_ban(
    State(state): State<AppState>,
    Json(request): Json<BanRequest>,
) -> Result<Json<BanRecord>, ApiError> {
    let max_ban_seconds = days_to_seconds(state.config.firewall.max_ban_days).unwrap_or_default();
    if request.seconds < 60 || request.seconds > max_ban_seconds {
        return Err(ApiError::bad_request(format!(
            "seconds must be between 60 and {}",
            max_ban_seconds
        )));
    }
    if request.reason.trim().is_empty() {
        return Err(ApiError::bad_request("manual ban reason is required"));
    }
    Ok(Json(
        state
            .firewall
            .ban_manual(request.network, request.seconds, request.reason)
            .await?,
    ))
}

pub async fn unban(
    State(state): State<AppState>,
    Path(network): Path<String>,
) -> Result<Json<ApiMessage>, ApiError> {
    let network: IpNet = network.parse().map_err(ApiError::bad_request)?;
    state.firewall.unban(network).await?;
    Ok(Json(ApiMessage::new(
        "network unbanned, history cleared, and exception added",
    )))
}

/// Backwards-compatible alias for clients that used the former reset route.
pub async fn unban_and_reset(
    State(state): State<AppState>,
    Path(network): Path<String>,
) -> Result<Json<ApiMessage>, ApiError> {
    let network: IpNet = network.parse().map_err(ApiError::bad_request)?;
    state.firewall.unban(network).await?;
    Ok(Json(ApiMessage::new(
        "network unbanned, history cleared, and exception added",
    )))
}

pub async fn reset_counts(
    State(state): State<AppState>,
    Path(network): Path<String>,
) -> Result<Json<ApiMessage>, ApiError> {
    let network: IpNet = network.parse().map_err(ApiError::bad_request)?;
    state.firewall.reset_counts(network).await?;
    Ok(Json(ApiMessage::new("network failure counts reset")))
}

fn validate_rule(rule: &BanRule) -> Result<(), ApiError> {
    if rule.name.trim().is_empty() {
        return Err(ApiError::bad_request("rule name is required"));
    }
    if rule.log_paths.is_empty() {
        return Err(ApiError::bad_request("at least one log path is required"));
    }
    if rule.weight == 0 {
        return Err(ApiError::bad_request(
            "rule weight must be greater than zero",
        ));
    }
    regex_automata::hybrid::regex::Regex::new(&rule.pattern).map_err(ApiError::bad_request)?;
    Ok(())
}
