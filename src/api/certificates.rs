use axum::{
    Json,
    extract::{Path, State},
};
use chrono::Utc;
use uuid::Uuid;

use crate::{
    api::ApiError,
    models::{
        ApiMessage, CertificateSpec, CertificateStatus, CommandResult, DehydratedLockStatus,
        DehydratedUpdate,
    },
    state::AppState,
    util::validate_simple_name,
};

pub async fn list(State(state): State<AppState>) -> Json<Vec<CertificateStatus>> {
    let specs = state.stores.certificates.read().await.clone();
    let mut statuses = Vec::with_capacity(specs.len());
    for spec in &specs {
        statuses.push(state.certificate_status(spec).await);
    }
    Json(statuses)
}

pub async fn create(
    State(state): State<AppState>,
    Json(mut spec): Json<CertificateSpec>,
) -> Result<Json<CertificateSpec>, ApiError> {
    validate(&spec)?;
    if state
        .stores
        .certificates
        .read()
        .await
        .iter()
        .any(|existing| existing.name == spec.name)
    {
        return Err(ApiError::conflict("certificate name already exists"));
    }
    spec.id = Uuid::new_v4();
    spec.updated_at = Utc::now();
    state.stores.certificates.write().await.push(spec.clone());
    state.stores.save_certificates().await?;
    Ok(Json(spec))
}

pub async fn update(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(mut spec): Json<CertificateSpec>,
) -> Result<Json<CertificateSpec>, ApiError> {
    validate(&spec)?;
    if state
        .stores
        .certificates
        .read()
        .await
        .iter()
        .any(|existing| existing.id != id && existing.name == spec.name)
    {
        return Err(ApiError::conflict("certificate name already exists"));
    }
    spec.id = id;
    spec.updated_at = Utc::now();
    let mut specs = state.stores.certificates.write().await;
    let existing = specs
        .iter_mut()
        .find(|existing| existing.id == id)
        .ok_or_else(|| ApiError::not_found("certificate not found"))?;
    *existing = spec.clone();
    drop(specs);
    state.stores.save_certificates().await?;
    Ok(Json(spec))
}

pub async fn delete(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiMessage>, ApiError> {
    let mut specs = state.stores.certificates.write().await;
    let before = specs.len();
    specs.retain(|spec| spec.id != id);
    if specs.len() == before {
        return Err(ApiError::not_found("certificate not found"));
    }
    drop(specs);
    state.stores.save_certificates().await?;
    Ok(Json(ApiMessage::new(
        "certificate definition deleted; dehydrated config and certificate files were left intact",
    )))
}

pub async fn issue(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<CommandResult>, ApiError> {
    ensure_dehydrated_unlocked(&state).await?;
    Ok(Json(state.issue_certificate(id, false).await?))
}

pub async fn renew(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<CommandResult>, ApiError> {
    ensure_dehydrated_unlocked(&state).await?;
    Ok(Json(state.issue_certificate(id, true).await?))
}

pub async fn dehydrated_lock(
    State(state): State<AppState>,
) -> Result<Json<DehydratedLockStatus>, ApiError> {
    Ok(Json(state.dehydrated_lock_status().await?))
}

pub async fn clear_dehydrated_lock(
    State(state): State<AppState>,
) -> Result<Json<DehydratedLockStatus>, ApiError> {
    Ok(Json(state.clear_dehydrated_lock().await?))
}

pub async fn update_dehydrated(
    State(state): State<AppState>,
) -> Result<Json<DehydratedUpdate>, ApiError> {
    Ok(Json(state.update_dehydrated().await?))
}

async fn ensure_dehydrated_unlocked(state: &AppState) -> Result<(), ApiError> {
    if state.dehydrated_lock_status().await?.locked {
        return Err(ApiError::conflict(
            "dehydrated lock file is present; clear it before issuing or renewing certificates",
        ));
    }
    Ok(())
}

fn validate(spec: &CertificateSpec) -> Result<(), ApiError> {
    validate_simple_name(&spec.name, "certificate name").map_err(ApiError::bad_request)?;
    if spec.name == "."
        || spec.name == ".."
        || spec.name.starts_with('.')
        || spec.name.ends_with('.')
    {
        return Err(ApiError::bad_request(
            "certificate name cannot start or end with a dot",
        ));
    }
    if spec.domains.is_empty() {
        return Err(ApiError::bad_request("at least one domain is required"));
    }
    if spec
        .hook
        .as_ref()
        .is_some_and(|path| path.as_os_str().is_empty())
    {
        return Err(ApiError::bad_request("certificate hook cannot be empty"));
    }
    if spec
        .hook
        .as_ref()
        .is_some_and(|path| path.to_string_lossy().contains(['\n', '\r']))
    {
        return Err(ApiError::bad_request(
            "certificate hook cannot contain newlines",
        ));
    }
    for domain in &spec.domains {
        if domain.is_empty()
            || domain.chars().any(|c| {
                c.is_whitespace() || matches!(c, '#' | '>' | '\\' | '\'' | '"' | '/' | ':')
            })
        {
            return Err(ApiError::bad_request("domain contains invalid characters"));
        }
    }
    for name in spec.hook_env.keys() {
        if name.is_empty()
            || !name.chars().enumerate().all(|(index, character)| {
                if index == 0 {
                    character.is_ascii_alphabetic() || character == '_'
                } else {
                    character.is_ascii_alphanumeric() || character == '_'
                }
            })
        {
            return Err(ApiError::bad_request(
                "hook environment names must be shell variable names",
            ));
        }
    }
    if spec
        .hook_env
        .values()
        .any(|value| value.contains(['\n', '\r']))
    {
        return Err(ApiError::bad_request(
            "hook environment values cannot contain newlines",
        ));
    }
    Ok(())
}
