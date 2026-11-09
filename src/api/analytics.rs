use axum::Json;

use crate::analytics::{
    global,
    model::{
        AiAnalysisRecord, AiPreview, AnalyticsHistory, AnalyticsSettingsUpdate,
        AnalyticsSettingsView, AnalyticsStatus,
    },
};

use super::ApiError;

fn manager() -> Result<&'static std::sync::Arc<crate::analytics::AnalyticsManager>, ApiError> {
    global().ok_or_else(|| ApiError::internal("security analytics manager is unavailable"))
}

pub async fn status() -> Result<Json<AnalyticsStatus>, ApiError> {
    Ok(Json(manager()?.status().await))
}

pub async fn history() -> Result<Json<AnalyticsHistory>, ApiError> {
    Ok(Json(manager()?.history().await))
}

pub async fn get_config() -> Result<Json<AnalyticsSettingsView>, ApiError> {
    Ok(Json(manager()?.settings_view().await))
}

pub async fn update_config(
    Json(update): Json<AnalyticsSettingsUpdate>,
) -> Result<Json<AnalyticsSettingsView>, ApiError> {
    manager()?
        .update_settings(update)
        .await
        .map(Json)
        .map_err(ApiError::bad_request)
}

pub async fn preview_ai_payload() -> Result<Json<AiPreview>, ApiError> {
    manager()?
        .preview_ai_payload()
        .await
        .map(Json)
        .map_err(ApiError::bad_request)
}

pub async fn analyze() -> Result<Json<AiAnalysisRecord>, ApiError> {
    manager()?
        .analyze_now()
        .await
        .map(Json)
        .map_err(ApiError::bad_request)
}
