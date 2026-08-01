pub mod adguard;
pub mod certificates;
pub mod firewall;
pub mod nginx;
pub mod services;
pub mod wol;

use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::{delete, get, post, put},
};
use serde::Serialize;

use tower_http::{
    cors::{Any, CorsLayer},
    limit::RequestBodyLimitLayer,
};

use crate::{
    asus_ui,
    auth::require_auth,
    models::{ApiMessage, Dashboard, RuntimeInfo},
    state::AppState,
};

pub fn app(state: AppState) -> anyhow::Result<Router> {
    let api = router().route_layer(axum::middleware::from_fn_with_state(
        state.clone(),
        require_auth,
    ));

    let cors = if state
        .config
        .server
        .allowed_origins
        .iter()
        .any(|origin| origin == "*")
    {
        CorsLayer::new()
            .allow_origin(Any)
            .allow_headers(Any)
            .allow_methods(Any)
    } else {
        let origins = state.config.server.allowed_origin_values()?;
        CorsLayer::new()
            .allow_origin(origins)
            .allow_headers(Any)
            .allow_methods(Any)
    };

    Ok(Router::new()
        .route("/", get(index))
        .route("/healthz", get(health))
        .route("/api/version", get(version))
        .nest("/api", api)
        .layer(RequestBodyLimitLayer::new(
            state.config.server.max_request_bytes,
        ))
        .layer(cors)
        .with_state(state))
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/auth/check", get(auth_check))
        .route("/runtime", get(runtime))
        .route("/dashboard", get(dashboard))
        .route("/services", get(services::list))
        .route("/services/{name}/{action}", post(services::action))
        .route("/services/{name}/logs", get(services::logs))
        .route("/nginx/status", get(nginx::status))
        .route("/nginx/test", post(nginx::test))
        .route("/nginx/reload", post(nginx::reload))
        .route("/nginx/start", post(nginx::start))
        .route("/nginx/stop", post(nginx::stop))
        .route("/nginx/objects", get(nginx::list_objects))
        .route("/nginx/objects/{kind}", post(nginx::create_object))
        .route(
            "/nginx/objects/{kind}/{domain}/{name}",
            get(nginx::get_object)
                .put(nginx::update_object)
                .delete(nginx::delete_object),
        )
        .route(
            "/nginx/objects/{kind}/{domain}/{name}/{action}",
            post(nginx::object_action),
        )
        .route("/nginx/files", get(nginx::list_files))
        .route(
            "/nginx/files/{*path}",
            get(nginx::get_file)
                .put(nginx::put_file)
                .delete(nginx::delete_file),
        )
        .route("/nginx/templates/{kind}", get(nginx::list_templates))
        .route(
            "/nginx/templates/{kind}/{name}",
            get(nginx::get_template)
                .put(nginx::put_template)
                .delete(nginx::delete_template),
        )
        .route("/nginx/logs", get(nginx::list_logs))
        .route("/nginx/logs/{*path}", get(nginx::get_log))
        .route(
            "/certificates",
            get(certificates::list).post(certificates::create),
        )
        .route(
            "/certificates/dehydrated/lock",
            get(certificates::dehydrated_lock).delete(certificates::clear_dehydrated_lock),
        )
        .route(
            "/certificates/{id}",
            put(certificates::update).delete(certificates::delete),
        )
        .route("/certificates/{id}/issue", post(certificates::issue))
        .route("/certificates/{id}/renew", post(certificates::renew))
        .route(
            "/certificates/dehydrated/update",
            post(certificates::update_dehydrated),
        )
        .route("/wol", get(wol::list).post(wol::create))
        .route("/wol/status", get(wol::status))
        .route("/wol/{id}", put(wol::update).delete(wol::delete))
        .route("/wol/{id}/wake", post(wol::wake))
        .route(
            "/firewall",
            get(firewall::status).put(firewall::update_policy),
        )
        .route("/firewall/rules", post(firewall::create_rule))
        .route(
            "/firewall/rules/{id}",
            put(firewall::update_rule).delete(firewall::delete_rule),
        )
        .route("/firewall/allowlist", post(firewall::add_allowlist))
        .route(
            "/firewall/allowlist/{network}",
            delete(firewall::delete_allowlist),
        )
        .route(
            "/firewall/bans",
            get(firewall::list_bans).post(firewall::manual_ban),
        )
        .route(
            "/firewall/bans/{network}/reset",
            delete(firewall::unban_and_reset),
        )
        .route("/firewall/bans/{network}", delete(firewall::unban))
        .route(
            "/firewall/reset-counts/{network}",
            post(firewall::reset_counts),
        )
        .route(
            "/adguard/config",
            get(adguard::get_config).put(adguard::update_config),
        )
        .route(
            "/adguard/rewrites",
            get(adguard::get_rewrites).put(adguard::update_rewrites),
        )
        .route("/adguard/protection", post(adguard::set_protection))
}

pub async fn index(State(state): State<AppState>) -> Response {
    Html(asus_ui::render_ui(&state.config)).into_response()
}

pub async fn health() -> &'static str {
    "ok"
}

pub async fn version() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "version": env!("CARGO_PKG_VERSION") }))
}

pub async fn runtime(State(state): State<AppState>) -> Json<RuntimeInfo> {
    let token = &state.config.server.auth_token;
    Json(RuntimeInfo {
        version: env!("CARGO_PKG_VERSION").into(),
        api_base_url: state.config.asus_ui.api_base_url.clone(),
        token_hint: {
            let mut suffix = token.chars().rev().take(4).collect::<String>();
            if suffix.is_empty() {
                "unset".into()
            } else {
                suffix = suffix.chars().rev().collect();
                format!("…{suffix}")
            }
        },
        test_mode: state.config.test_mode,
    })
}

pub async fn auth_check() -> Json<ApiMessage> {
    Json(ApiMessage::new("API token is valid"))
}

async fn dashboard(State(state): State<AppState>) -> Result<Json<Dashboard>, ApiError> {
    let services = services::collect_services(&state).await?;
    let nginx_running = nginx::nginx_running(&state).await;
    let nginx_object_count = crate::nginx::list_objects(&state.config, nginx_running)?.len();
    let certificates = state.stores.certificates.read().await.clone();
    let machines_len = state.stores.wol_machines.read().await.len();
    let firewall_status = state.firewall.status().await;
    let firewall_enabled = firewall_status.policy.enabled;
    let active_bans = firewall_status.snapshot.active_ban_count;
    let active_ip_bans = firewall_status.snapshot.banned_ips.len();
    let active_subnet_bans = firewall_status.snapshot.banned_subnets.len();
    let mut certificates_due = 0;
    for certificate in &certificates {
        if state.certificate_status(certificate).await.renewal_due {
            certificates_due += 1;
        }
    }
    Ok(Json(Dashboard {
        version: env!("CARGO_PKG_VERSION").into(),
        test_mode: state.config.test_mode,
        services_total: services.len(),
        services_running: services.iter().filter(|service| service.running).count(),
        nginx_running,
        nginx_objects: nginx_object_count,
        certificates: certificates.len(),
        certificates_due,
        wol_machines: machines_len,
        active_bans,
        active_ip_bans,
        active_subnet_bans,
        firewall_enabled,
    }))
}

#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    pub fn bad_request(error: impl std::fmt::Display) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: error.to_string(),
        }
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: message.into(),
        }
    }

    pub fn conflict(error: impl std::fmt::Display) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            message: error.to_string(),
        }
    }

    pub fn internal(error: impl std::fmt::Display) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: error.to_string(),
        }
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(error: anyhow::Error) -> Self {
        tracing::error!(%error, "API request failed");
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: error.to_string(),
        }
    }
}

impl From<std::io::Error> for ApiError {
    fn from(error: std::io::Error) -> Self {
        anyhow::Error::from(error).into()
    }
}

impl From<walkdir::Error> for ApiError {
    fn from(error: walkdir::Error) -> Self {
        anyhow::Error::from(error).into()
    }
}

impl From<std::path::StripPrefixError> for ApiError {
    fn from(error: std::path::StripPrefixError) -> Self {
        anyhow::Error::from(error).into()
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(ErrorBody {
                error: self.message,
            }),
        )
            .into_response()
    }
}

#[derive(Serialize)]
struct ErrorBody {
    error: String,
}
