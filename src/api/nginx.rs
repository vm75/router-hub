use std::{net::SocketAddr, path::Path as FsPath, path::PathBuf, time::Duration};

use anyhow::Context;
use axum::{
    Json,
    extract::{Path, State},
};
use serde::{Deserialize, Serialize};
use tokio::{net::TcpStream, time::timeout};

use crate::{
    api::ApiError,
    models::{
        ApiMessage, CommandResult, NginxFileEntry, NginxLogEntry, NginxObject, NginxObjectKind,
        NginxTemplateEntry,
    },
    nginx as nginx_core,
    state::AppState,
};

#[derive(Serialize)]
pub struct NginxStatus {
    running: bool,
    config_path: PathBuf,
    root_dir: PathBuf,
    domains_available_dir: PathBuf,
    domains_enabled_dir: PathBuf,
    templates_dir: PathBuf,
    log_dir: PathBuf,
}

#[derive(Serialize, Deserialize)]
pub struct FileContent {
    content: String,
}

#[derive(Deserialize)]
pub struct TemplateContent {
    content: String,
    #[serde(default)]
    name: Option<String>,
}

#[derive(Serialize)]
pub struct ObjectContent {
    object: NginxObject,
    content: String,
    server_names: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    upstream: Option<String>,
}

#[derive(Deserialize)]
pub struct CreateObject {
    domain: String,
    name: String,
    #[serde(default)]
    template: Option<String>,
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    server_names: Vec<String>,
    /// Optional target for the generated domain/subdomain/subfolder upstream map.
    #[serde(default)]
    upstream: Option<String>,
    #[serde(default)]
    enabled: bool,
}

#[derive(Deserialize)]
pub struct UpdateObject {
    #[serde(default)]
    template: Option<String>,
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    server_names: Option<Vec<String>>,
    /// Omit to keep the current map entry; send an empty string to remove it.
    #[serde(default)]
    upstream: Option<String>,
}

pub async fn status(State(state): State<AppState>) -> Json<NginxStatus> {
    Json(NginxStatus {
        running: nginx_running(&state).await,
        config_path: state.config.nginx.config_path.clone(),
        root_dir: state.config.nginx.root_dir.clone(),
        domains_available_dir: state.config.nginx.domains_available_dir.clone(),
        domains_enabled_dir: state.config.nginx.domains_enabled_dir.clone(),
        templates_dir: state.config.nginx.templates_dir.clone(),
        log_dir: state.config.nginx.log_dir.clone(),
    })
}

pub async fn nginx_running(state: &AppState) -> bool {
    if state.config.test_mode {
        return true;
    }
    let Ok(pid) = tokio::fs::read_to_string(&state.config.nginx.pid_path).await else {
        return false;
    };
    let Ok(pid) = pid.trim().parse::<u32>() else {
        return false;
    };
    FsPath::new("/proc").join(pid.to_string()).exists()
}

pub async fn list_objects(
    State(state): State<AppState>,
) -> Result<Json<Vec<NginxObject>>, ApiError> {
    let running = nginx_running(&state).await;
    let objects = nginx_core::list_objects(&state.config, running)?;
    let objects = futures_util::future::join_all(objects.into_iter().map(|mut object| {
        let config = state.config.clone();
        async move {
            let upstream = nginx_core::object_upstream(&config, &object)?;
            let reachable = match upstream.as_deref() {
                Some(upstream) => upstream_reachable(upstream).await,
                None => true,
            };
            object.state =
                nginx_core::site_state(object.enabled, object.running && running, reachable)
                    .to_string();
            Ok::<_, anyhow::Error>(object)
        }
    }))
    .await
    .into_iter()
    .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(objects))
}

async fn upstream_reachable(upstream: &str) -> bool {
    let Ok(url) = url::Url::parse(upstream) else {
        return false;
    };
    let Some(host) = url.host_str() else {
        return false;
    };
    let port = url.port_or_known_default().unwrap_or(0);
    if port == 0 {
        return false;
    }
    let addresses = match tokio::net::lookup_host((host, port)).await {
        Ok(addresses) => addresses.collect::<Vec<SocketAddr>>(),
        Err(_) => return false,
    };
    for address in addresses {
        if timeout(Duration::from_secs(2), TcpStream::connect(address))
            .await
            .is_ok_and(|result| result.is_ok())
        {
            return true;
        }
    }
    false
}

pub async fn get_object(
    State(state): State<AppState>,
    Path((kind, domain, name)): Path<(String, String, String)>,
) -> Result<Json<ObjectContent>, ApiError> {
    let kind = nginx_core::parse_kind(&kind).map_err(ApiError::bad_request)?;
    let content = nginx_core::read_object(&state.config, kind, &domain, &name)
        .map_err(not_found_or_internal)?;
    let object = find_object(&state, kind, &domain, &name).await?;
    let server_names = nginx_core::extract_server_names(&content);
    let map_key = (kind == NginxObjectKind::Subfolder)
        .then(|| nginx_core::subfolder_map_key(&content, &name))
        .transpose()?;
    let upstream = nginx_core::site_upstream_with_key(
        &state.config,
        kind,
        &domain,
        &name,
        &server_names,
        map_key.as_deref(),
    )?;
    Ok(Json(ObjectContent {
        object,
        content,
        server_names,
        upstream,
    }))
}

pub async fn create_object(
    State(state): State<AppState>,
    Path(kind): Path<String>,
    Json(mut request): Json<CreateObject>,
) -> Result<Json<ObjectContent>, ApiError> {
    let kind = nginx_core::parse_kind(&kind).map_err(ApiError::bad_request)?;
    if kind == NginxObjectKind::Domain {
        request.name.clone_from(&request.domain);
    }
    let template = request
        .template
        .as_deref()
        .filter(|value| !value.is_empty());
    let content = render_object_content(
        &state,
        kind,
        &request.domain,
        &request.name,
        template,
        request.content.as_deref(),
        &request.server_names,
    )?;
    let server_names = nginx_core::normalize_server_names(
        kind,
        &request.domain,
        &request.name,
        &request.server_names,
    )
    .map_err(ApiError::bad_request)?;
    let upstream = request
        .upstream
        .as_deref()
        .filter(|value| !value.trim().is_empty());
    let map_key = (kind == NginxObjectKind::Subfolder)
        .then(|| nginx_core::subfolder_map_key(&content, &request.name))
        .transpose()?;
    nginx_core::validate_site_upstream(kind, upstream).map_err(ApiError::bad_request)?;
    nginx_core::write_object(
        &state.config,
        kind,
        &request.domain,
        &request.name,
        &content,
        true,
    )
    .map_err(conflict_or_bad_request)?;

    if let Err(error) = nginx_core::sync_site_upstream(
        &state.config,
        kind,
        &request.domain,
        &request.name,
        map_key.as_deref(),
        map_key.as_deref(),
        &[],
        &server_names,
        upstream,
    ) {
        let _ = nginx_core::delete_object(&state.config, kind, &request.domain, &request.name);
        return Err(error.into());
    }

    if request.enabled {
        if let Err(error) = change_enabled(
            &state,
            kind,
            &request.domain,
            &request.name,
            true,
            true,
            false,
        )
        .await
        {
            let _ = nginx_core::sync_site_upstream(
                &state.config,
                kind,
                &request.domain,
                &request.name,
                map_key.as_deref(),
                map_key.as_deref(),
                &server_names,
                &[],
                None,
            );
            let _ = nginx_core::reconcile_http_forwarder(&state.config);
            let _ = nginx_core::delete_object(&state.config, kind, &request.domain, &request.name);
            return Err(error);
        }
    } else if let Err(error) = nginx_core::reconcile_http_forwarder(&state.config) {
        let _ = nginx_core::sync_site_upstream(
            &state.config,
            kind,
            &request.domain,
            &request.name,
            map_key.as_deref(),
            map_key.as_deref(),
            &server_names,
            &[],
            None,
        );
        let _ = nginx_core::delete_object(&state.config, kind, &request.domain, &request.name);
        return Err(error.into());
    }
    let object = find_object(&state, kind, &request.domain, &request.name).await?;
    let server_names = nginx_core::extract_server_names(&content);
    let upstream = nginx_core::site_upstream_with_key(
        &state.config,
        kind,
        &request.domain,
        &request.name,
        &server_names,
        map_key.as_deref(),
    )?;
    Ok(Json(ObjectContent {
        object,
        content,
        server_names,
        upstream,
    }))
}

pub async fn update_object(
    State(state): State<AppState>,
    Path((kind, domain, name)): Path<(String, String, String)>,
    Json(body): Json<UpdateObject>,
) -> Result<Json<ObjectContent>, ApiError> {
    let kind = nginx_core::parse_kind(&kind).map_err(ApiError::bad_request)?;
    let previous = nginx_core::read_object(&state.config, kind, &domain, &name)
        .map_err(not_found_or_internal)?;
    let previous_server_names = nginx_core::extract_server_names(&previous);
    let previous_server_names =
        nginx_core::normalize_server_names(kind, &domain, &name, &previous_server_names)
            .map_err(ApiError::bad_request)?;
    let previous_map_key = (kind == NginxObjectKind::Subfolder)
        .then(|| nginx_core::subfolder_map_key(&previous, &name))
        .transpose()?;
    let previous_upstream = nginx_core::site_upstream_with_key(
        &state.config,
        kind,
        &domain,
        &name,
        &previous_server_names,
        previous_map_key.as_deref(),
    )?;
    let template = body.template.as_deref().filter(|value| !value.is_empty());
    let server_names = body
        .server_names
        .as_deref()
        .filter(|names| !names.is_empty())
        .unwrap_or(&previous_server_names);
    let server_names = nginx_core::normalize_server_names(kind, &domain, &name, server_names)
        .map_err(ApiError::bad_request)?;
    let upstream = match body.upstream.as_deref().map(str::trim) {
        Some("") => None,
        Some(value) => Some(value),
        None => previous_upstream.as_deref(),
    };
    nginx_core::validate_site_upstream(kind, upstream).map_err(ApiError::bad_request)?;
    let content = render_object_content(
        &state,
        kind,
        &domain,
        &name,
        template,
        body.content.as_deref(),
        &server_names,
    )?;
    let map_key = (kind == NginxObjectKind::Subfolder)
        .then(|| nginx_core::subfolder_map_key(&content, &name))
        .transpose()?;
    nginx_core::write_object(&state.config, kind, &domain, &name, &content, false)
        .map_err(conflict_or_bad_request)?;

    if let Err(error) = nginx_core::sync_site_upstream(
        &state.config,
        kind,
        &domain,
        &name,
        previous_map_key.as_deref(),
        map_key.as_deref(),
        &previous_server_names,
        &server_names,
        upstream,
    ) {
        nginx_core::write_object(&state.config, kind, &domain, &name, &previous, false)?;
        return Err(error.into());
    }
    if let Err(error) = nginx_core::reconcile_http_forwarder(&state.config) {
        nginx_core::write_object(&state.config, kind, &domain, &name, &previous, false)?;
        let _ = nginx_core::sync_site_upstream(
            &state.config,
            kind,
            &domain,
            &name,
            map_key.as_deref(),
            previous_map_key.as_deref(),
            &server_names,
            &previous_server_names,
            previous_upstream.as_deref(),
        );
        return Err(error.into());
    }

    let enabled = nginx_core::symlink_exists(&nginx_core::enabled_path(
        &state.config,
        kind,
        &domain,
        &name,
    )?);
    if enabled {
        let result = nginx_test(&state).await?;
        if !result.success {
            nginx_core::write_object(&state.config, kind, &domain, &name, &previous, false)?;
            let _ = nginx_core::sync_site_upstream(
                &state.config,
                kind,
                &domain,
                &name,
                map_key.as_deref(),
                previous_map_key.as_deref(),
                &server_names,
                &previous_server_names,
                previous_upstream.as_deref(),
            );
            let _ = nginx_core::reconcile_http_forwarder(&state.config);
            return Err(ApiError::conflict(format!(
                "nginx test failed; the previous configuration was restored: {}",
                result.stderr
            )));
        }
        if nginx_running(&state).await {
            let result = nginx_reload(&state).await?;
            if !result.success {
                nginx_core::write_object(&state.config, kind, &domain, &name, &previous, false)?;
                let _ = nginx_core::sync_site_upstream(
                    &state.config,
                    kind,
                    &domain,
                    &name,
                    map_key.as_deref(),
                    previous_map_key.as_deref(),
                    &server_names,
                    &previous_server_names,
                    previous_upstream.as_deref(),
                );
                let _ = nginx_core::reconcile_http_forwarder(&state.config);
                let _ = nginx_reload(&state).await;
                return Err(ApiError::conflict(format!(
                    "nginx reload failed; the previous configuration was restored: {}",
                    result.stderr
                )));
            }
        }
    }
    let object = find_object(&state, kind, &domain, &name).await?;
    let upstream = nginx_core::site_upstream_with_key(
        &state.config,
        kind,
        &domain,
        &name,
        &server_names,
        map_key.as_deref(),
    )?;
    Ok(Json(ObjectContent {
        object,
        server_names,
        content,
        upstream,
    }))
}

fn render_object_content(
    state: &AppState,
    kind: NginxObjectKind,
    domain: &str,
    name: &str,
    template: Option<&str>,
    custom_content: Option<&str>,
    server_names: &[String],
) -> Result<String, ApiError> {
    let (source, template) = match template {
        Some(template) => (
            nginx_core::read_template(&state.config, kind, template)
                .map_err(not_found_or_internal)?,
            Some(template),
        ),
        None => (
            custom_content
                .map(nginx_core::strip_template_comment)
                .ok_or_else(|| {
                    ApiError::bad_request("either template or custom content is required")
                })?,
            None,
        ),
    };
    let rendered = nginx_core::render_template(&source, kind, domain, name, server_names)
        .map_err(ApiError::bad_request)?;
    match template {
        Some(template) => {
            nginx_core::with_template_comment(template, &rendered).map_err(ApiError::bad_request)
        }
        None => Ok(rendered),
    }
}

pub async fn delete_object(
    State(state): State<AppState>,
    Path((kind, domain, name)): Path<(String, String, String)>,
) -> Result<Json<ApiMessage>, ApiError> {
    let kind = nginx_core::parse_kind(&kind).map_err(ApiError::bad_request)?;
    nginx_core::read_object(&state.config, kind, &domain, &name).map_err(not_found_or_internal)?;
    let cleanup_objects = nginx_core::list_objects(&state.config, false)?
        .into_iter()
        .filter(|object| {
            (kind == NginxObjectKind::Domain && object.domain == domain)
                || (object.kind == kind && object.domain == domain && object.name == name)
        })
        .map(|object| {
            let content =
                nginx_core::read_object(&state.config, object.kind, &object.domain, &object.name)?;
            let names = nginx_core::normalize_server_names(
                object.kind,
                &object.domain,
                &object.name,
                &nginx_core::extract_server_names(&content),
            )?;
            let map_key = (object.kind == NginxObjectKind::Subfolder)
                .then(|| nginx_core::subfolder_map_key(&content, &object.name))
                .transpose()?;
            let upstream = nginx_core::site_upstream_with_key(
                &state.config,
                object.kind,
                &object.domain,
                &object.name,
                &names,
                map_key.as_deref(),
            )?;
            Ok::<_, anyhow::Error>((object, names, map_key, upstream))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let enabled_path = nginx_core::enabled_path(&state.config, kind, &domain, &name)?;
    let was_enabled = nginx_core::symlink_exists(&enabled_path);
    if was_enabled {
        change_enabled(&state, kind, &domain, &name, false, true, false).await?;
    }
    nginx_core::delete_object(&state.config, kind, &domain, &name)?;
    for (object, names, map_key, upstream) in cleanup_objects {
        nginx_core::sync_site_upstream(
            &state.config,
            object.kind,
            &object.domain,
            &object.name,
            map_key.as_deref(),
            None,
            &names,
            &[],
            upstream.as_deref(),
        )?;
    }
    nginx_core::reconcile_http_forwarder(&state.config)?;
    Ok(Json(ApiMessage::new("nginx object deleted")))
}

pub async fn object_action(
    State(state): State<AppState>,
    Path((kind, domain, name, action)): Path<(String, String, String, String)>,
) -> Result<Json<NginxObject>, ApiError> {
    let kind = nginx_core::parse_kind(&kind).map_err(ApiError::bad_request)?;
    nginx_core::read_object(&state.config, kind, &domain, &name).map_err(not_found_or_internal)?;
    let (enabled, start_global) = match action.as_str() {
        "enable" => (true, false),
        "disable" => (false, false),
        "start" => (true, true),
        "stop" => (false, false),
        _ => {
            return Err(ApiError::bad_request(
                "action must be start, stop, enable, or disable",
            ));
        }
    };
    if action == "start"
        && kind != NginxObjectKind::Domain
        && !nginx_core::symlink_exists(&state.config.nginx.domains_enabled_dir.join(&domain))
    {
        return Err(ApiError::conflict(
            "enable or start the parent domain before starting this object",
        ));
    }
    change_enabled(&state, kind, &domain, &name, enabled, true, start_global).await?;
    find_object(&state, kind, &domain, &name).await.map(Json)
}

async fn change_enabled(
    state: &AppState,
    kind: NginxObjectKind,
    domain: &str,
    name: &str,
    enabled: bool,
    apply: bool,
    start_global: bool,
) -> Result<(), ApiError> {
    let enabled_path = nginx_core::enabled_path(&state.config, kind, domain, name)?;
    let was_enabled = nginx_core::symlink_exists(&enabled_path);
    nginx_core::set_enabled(&state.config, kind, domain, name, enabled)
        .map_err(conflict_or_bad_request)?;

    if let Err(error) = nginx_core::reconcile_http_forwarder(&state.config) {
        nginx_core::set_enabled(&state.config, kind, domain, name, was_enabled)?;
        let _ = nginx_core::reconcile_http_forwarder(&state.config);
        return Err(ApiError::internal(error));
    }

    let test_result = nginx_test(state).await?;
    if !test_result.success {
        nginx_core::set_enabled(&state.config, kind, domain, name, was_enabled)?;
        let _ = nginx_core::reconcile_http_forwarder(&state.config);
        return Err(ApiError::conflict(format!(
            "nginx test failed; enabled state was restored: {}",
            test_result.stderr
        )));
    }
    if apply {
        let running = nginx_running(state).await;
        let result = if enabled && !running && start_global {
            nginx_start(state).await?
        } else if running {
            nginx_reload(state).await?
        } else {
            return Ok(());
        };
        if !result.success {
            nginx_core::set_enabled(&state.config, kind, domain, name, was_enabled)?;
            let _ = nginx_core::reconcile_http_forwarder(&state.config);
            return Err(ApiError::conflict(format!(
                "nginx action failed; enabled state was restored: {}",
                result.stderr
            )));
        }
    }

    let adguard_cfg = super::adguard::get_effective_config(state).await;
    if adguard_cfg.enabled {
        if let Ok(client) = crate::adguard::AdGuardClient::new(&adguard_cfg) {
            let full_domain = match kind {
                NginxObjectKind::Domain => domain.to_string(),
                NginxObjectKind::Subdomain => format!("{}.{}", name, domain),
                NginxObjectKind::Subfolder => String::new(),
            };
            if !full_domain.is_empty() {
                if enabled {
                    let _ = client
                        .ensure_rewrite(&full_domain, &adguard_cfg.lan_ip)
                        .await;
                } else {
                    let _ = client
                        .remove_all_rewrites(&full_domain, &adguard_cfg.lan_ip)
                        .await;
                }
            }
        }
    }

    Ok(())
}

async fn find_object(
    state: &AppState,
    kind: NginxObjectKind,
    domain: &str,
    name: &str,
) -> Result<NginxObject, ApiError> {
    let running = nginx_running(state).await;
    nginx_core::list_objects(&state.config, running)?
        .into_iter()
        .find(|object| {
            object.kind == kind
                && object.domain == domain
                && (object.name == name || kind == NginxObjectKind::Domain)
        })
        .ok_or_else(|| ApiError::not_found("nginx object not found"))
}

pub async fn test(State(state): State<AppState>) -> Result<Json<CommandResult>, ApiError> {
    Ok(Json(nginx_test(&state).await?))
}

pub async fn reload(State(state): State<AppState>) -> Result<Json<CommandResult>, ApiError> {
    let test_result = nginx_test(&state).await?;
    if !test_result.success {
        return Err(ApiError::conflict(format!(
            "nginx configuration test failed: {}",
            test_result.stderr
        )));
    }
    Ok(Json(nginx_reload(&state).await?))
}

pub async fn start(State(state): State<AppState>) -> Result<Json<CommandResult>, ApiError> {
    let test_result = nginx_test(&state).await?;
    if !test_result.success {
        return Err(ApiError::conflict(format!(
            "nginx configuration test failed: {}",
            test_result.stderr
        )));
    }
    Ok(Json(nginx_start(&state).await?))
}

pub async fn stop(State(state): State<AppState>) -> Result<Json<CommandResult>, ApiError> {
    Ok(Json(nginx_stop(&state).await?))
}

async fn nginx_test(state: &AppState) -> anyhow::Result<CommandResult> {
    run_nginx(
        state,
        vec![
            "-t".to_string(),
            "-c".to_string(),
            state.config.nginx.config_path.to_string_lossy().to_string(),
        ],
    )
    .await
}

async fn nginx_reload(state: &AppState) -> anyhow::Result<CommandResult> {
    run_nginx(
        state,
        vec![
            "-s".to_string(),
            "reload".to_string(),
            "-c".to_string(),
            state.config.nginx.config_path.to_string_lossy().to_string(),
        ],
    )
    .await
}

async fn nginx_start(state: &AppState) -> anyhow::Result<CommandResult> {
    run_nginx(
        state,
        vec![
            "-c".to_string(),
            state.config.nginx.config_path.to_string_lossy().to_string(),
        ],
    )
    .await
}

async fn nginx_stop(state: &AppState) -> anyhow::Result<CommandResult> {
    run_nginx(
        state,
        vec![
            "-s".to_string(),
            "quit".to_string(),
            "-c".to_string(),
            state.config.nginx.config_path.to_string_lossy().to_string(),
        ],
    )
    .await
}

async fn run_nginx(state: &AppState, args: Vec<String>) -> anyhow::Result<CommandResult> {
    state
        .runner
        .run(
            &state.config.commands.nginx,
            args,
            Duration::from_secs(state.config.nginx.reload_timeout_seconds),
        )
        .await
}

pub async fn list_files(
    State(state): State<AppState>,
) -> Result<Json<Vec<NginxFileEntry>>, ApiError> {
    Ok(Json(nginx_core::list_root_files(&state.config)?))
}

pub async fn get_file(
    State(state): State<AppState>,
    Path(path): Path<String>,
) -> Result<Json<FileContent>, ApiError> {
    let path = nginx_core::root_file_path(&state.config, &path).map_err(ApiError::bad_request)?;
    let content = tokio::fs::read_to_string(&path)
        .await
        .with_context(|| format!("failed to read {}", path.display()))
        .map_err(not_found_or_internal)?;
    Ok(Json(FileContent { content }))
}

pub async fn put_file(
    State(state): State<AppState>,
    Path(path): Path<String>,
    Json(body): Json<FileContent>,
) -> Result<Json<ApiMessage>, ApiError> {
    let path = nginx_core::root_file_path(&state.config, &path).map_err(ApiError::bad_request)?;
    let previous = read_optional(&path).await?;
    nginx_core::atomic_write(&path, body.content.as_bytes())?;
    let result = nginx_test(&state).await?;
    if !result.success {
        restore_optional(&path, previous.as_deref()).await?;
        return Err(ApiError::conflict(format!(
            "nginx test failed; the previous file was restored: {}",
            result.stderr
        )));
    }
    Ok(Json(ApiMessage::new("nginx file saved")))
}

pub async fn delete_file(
    State(state): State<AppState>,
    Path(path): Path<String>,
) -> Result<Json<ApiMessage>, ApiError> {
    let path = nginx_core::root_file_path(&state.config, &path).map_err(ApiError::bad_request)?;
    let previous = read_optional(&path)
        .await?
        .ok_or_else(|| ApiError::not_found("nginx file not found"))?;
    tokio::fs::remove_file(&path).await?;
    let result = nginx_test(&state).await?;
    if !result.success {
        nginx_core::atomic_write(&path, &previous)?;
        return Err(ApiError::conflict(format!(
            "nginx test failed; the deleted file was restored: {}",
            result.stderr
        )));
    }
    Ok(Json(ApiMessage::new("nginx file deleted")))
}

pub async fn list_templates(
    State(state): State<AppState>,
    Path(kind): Path<String>,
) -> Result<Json<Vec<NginxTemplateEntry>>, ApiError> {
    let kind = nginx_core::parse_kind(&kind).map_err(ApiError::bad_request)?;
    Ok(Json(nginx_core::list_templates(&state.config, kind)?))
}

pub async fn get_template(
    State(state): State<AppState>,
    Path((kind, name)): Path<(String, String)>,
) -> Result<Json<FileContent>, ApiError> {
    let kind = nginx_core::parse_kind(&kind).map_err(ApiError::bad_request)?;
    let content =
        nginx_core::read_template(&state.config, kind, &name).map_err(not_found_or_internal)?;
    Ok(Json(FileContent { content }))
}

pub async fn put_template(
    State(state): State<AppState>,
    Path((kind, name)): Path<(String, String)>,
    Json(body): Json<TemplateContent>,
) -> Result<Json<ApiMessage>, ApiError> {
    let kind = nginx_core::parse_kind(&kind).map_err(ApiError::bad_request)?;
    if let Some(new_name) = body.name.as_deref().filter(|value| *value != name) {
        nginx_core::rename_template(&state.config, kind, &name, new_name, &body.content)
            .map_err(conflict_or_bad_request)?;
    } else {
        nginx_core::write_template(&state.config, kind, &name, &body.content)
            .map_err(conflict_or_bad_request)?;
    }
    Ok(Json(ApiMessage::new("nginx template saved")))
}

pub async fn delete_template(
    State(state): State<AppState>,
    Path((kind, name)): Path<(String, String)>,
) -> Result<Json<ApiMessage>, ApiError> {
    let kind = nginx_core::parse_kind(&kind).map_err(ApiError::bad_request)?;
    nginx_core::delete_template(&state.config, kind, &name).map_err(conflict_or_bad_request)?;
    Ok(Json(ApiMessage::new("nginx template deleted")))
}

pub async fn list_logs(
    State(state): State<AppState>,
) -> Result<Json<Vec<NginxLogEntry>>, ApiError> {
    Ok(Json(nginx_core::list_logs(&state.config)?))
}

pub async fn get_log(
    State(state): State<AppState>,
    Path(path): Path<String>,
) -> Result<Json<FileContent>, ApiError> {
    let content = nginx_core::read_log(&state.config, &path).map_err(not_found_or_internal)?;
    Ok(Json(FileContent { content }))
}

async fn read_optional(path: &FsPath) -> Result<Option<Vec<u8>>, ApiError> {
    match tokio::fs::read(path).await {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

async fn restore_optional(path: &FsPath, content: Option<&[u8]>) -> Result<(), ApiError> {
    match content {
        Some(content) => nginx_core::atomic_write(path, content)?,
        None => {
            if path.exists() {
                tokio::fs::remove_file(path).await?;
            }
        }
    }
    Ok(())
}

fn not_found_or_internal(error: anyhow::Error) -> ApiError {
    if error
        .chain()
        .filter_map(|source| source.downcast_ref::<std::io::Error>())
        .any(|error| error.kind() == std::io::ErrorKind::NotFound)
    {
        ApiError::not_found(error.to_string())
    } else {
        error.into()
    }
}

fn conflict_or_bad_request(error: anyhow::Error) -> ApiError {
    let message = error.to_string();
    if message.contains("already exists") || message.contains("does not exist") {
        ApiError::conflict(message)
    } else {
        ApiError::bad_request(message)
    }
}
