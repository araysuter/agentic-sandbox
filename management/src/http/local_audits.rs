//! The local audit control plane requires an explicit authenticated administrator.
use super::{operator_auth::OperatorRole, server::AppState};
use crate::local_audits::{Error, LocalAuditService, RepositoryInput};
use axum::{
    extract::{DefaultBodyLimit, Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Extension, Json, Router,
};
use std::sync::Arc;
type ApiError = (StatusCode, Json<serde_json::Value>);
fn error(e: Error) -> ApiError {
    let (status, message) = match e {
        Error::Invalid(s) => (StatusCode::BAD_REQUEST, s),
        Error::NotFound => (
            StatusCode::NOT_FOUND,
            "repository or audit run not found".into(),
        ),
        Error::Busy => (
            StatusCode::CONFLICT,
            "another sandbox or audit is active; this run was not queued".into(),
        ),
        Error::Unavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            "local audit prerequisites are unavailable".into(),
        ),
        Error::Storage => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "could not durably update local audit state".into(),
        ),
    };
    (status, Json(serde_json::json!({"error":message})))
}
fn admin(role: Option<Extension<OperatorRole>>) -> Result<(), ApiError> {
    if matches!(role, Some(Extension(OperatorRole::Admin))) {
        Ok(())
    } else {
        Err((
            StatusCode::FORBIDDEN,
            Json(
                serde_json::json!({"error":"explicit authenticated administrator identity required"}),
            ),
        ))
    }
}
fn service(state: &AppState) -> Result<Arc<LocalAuditService>, ApiError> {
    state
        .local_audits
        .clone()
        .ok_or_else(|| error(Error::Unavailable))
}
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(list).post(create))
        .route("/{id}", axum::routing::put(update).delete(delete))
        .route("/{id}/run", post(run))
        .route("/runs/{id}/cancel", post(cancel))
        .route("/runs/{id}/report", get(report))
        .layer(DefaultBodyLimit::max(128 * 1024))
}
async fn list(
    State(state): State<AppState>,
    role: Option<Extension<OperatorRole>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    admin(role)?;
    Ok(Json(
        state.local_audits.map(|s| s.snapshot()).unwrap_or_else(
            || serde_json::json!({"enabled":false,"repositories":[],"runs":[],"busy":false}),
        ),
    ))
}
async fn create(
    State(state): State<AppState>,
    role: Option<Extension<OperatorRole>>,
    Json(input): Json<RepositoryInput>,
) -> Result<Response, ApiError> {
    admin(role)?;
    Ok((
        StatusCode::CREATED,
        Json(service(&state)?.upsert(None, input).map_err(error)?),
    )
        .into_response())
}
async fn update(
    State(state): State<AppState>,
    role: Option<Extension<OperatorRole>>,
    Path(id): Path<String>,
    Json(input): Json<RepositoryInput>,
) -> Result<Json<serde_json::Value>, ApiError> {
    admin(role)?;
    Ok(Json(
        service(&state)?.upsert(Some(&id), input).map_err(error)?,
    ))
}
async fn delete(
    State(state): State<AppState>,
    role: Option<Extension<OperatorRole>>,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    admin(role)?;
    service(&state)?.delete(&id).map_err(error)?;
    Ok(StatusCode::NO_CONTENT)
}
async fn run(
    State(state): State<AppState>,
    role: Option<Extension<OperatorRole>>,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    admin(role)?;
    Ok((
        StatusCode::ACCEPTED,
        Json(service(&state)?.run_now(&id).map_err(error)?),
    )
        .into_response())
}
async fn cancel(
    State(state): State<AppState>,
    role: Option<Extension<OperatorRole>>,
    Path(id): Path<String>,
) -> Result<Json<crate::local_audits::AuditRun>, ApiError> {
    admin(role)?;
    Ok(Json(service(&state)?.cancel(&id).map_err(error)?))
}
async fn report(
    State(state): State<AppState>,
    role: Option<Extension<OperatorRole>>,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    admin(role)?;
    Ok((
        [
            ("content-type", "application/json"),
            ("x-content-type-options", "nosniff"),
            ("cache-control", "no-store"),
        ],
        service(&state)?.report(&id).map_err(error)?,
    )
        .into_response())
}
