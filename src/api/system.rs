use super::ApiError;
use crate::{
    state::AppState,
    system::{SystemUsage, get_system_usage},
};
use axum::{Json, extract::State};

pub async fn usage(State(state): State<AppState>) -> Result<Json<SystemUsage>, ApiError> {
    let usage = get_system_usage(
        &state.config.paths.proc_stat,
        &state.config.paths.proc_meminfo,
        &state.config.paths.proc_net_dev,
        &state.config.paths.proc_uptime,
        &state.config.paths.proc_loadavg,
        &state.config.system.wan_interface,
    )?;
    Ok(Json(usage))
}
