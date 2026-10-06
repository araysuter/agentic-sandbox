//! Explicitly authenticated administrative surface for disposable sessions.
//! This profile never inherits the legacy "missing token file means admin" rule.
use super::{operator_auth::OperatorRole, server::AppState};
use crate::disposable::{CreateRequest, DisposableController, Error, MAX_SOURCE};
use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Extension, Json, Router,
};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use std::sync::Arc;
type ApiError = (StatusCode, Json<serde_json::Value>);
fn api_error(error: Error) -> ApiError {
    let (status, message) = match error {
        Error::Busy => (
            StatusCode::CONFLICT,
            "VM capacity is unavailable or awaiting verified cleanup".into(),
        ),
        Error::Invalid(s) => (StatusCode::BAD_REQUEST, s),
        Error::Unavailable(s) => (StatusCode::SERVICE_UNAVAILABLE, s),
        Error::NotFound => (
            StatusCode::NOT_FOUND,
            "session or artifact not found".into(),
        ),
        Error::Internal(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "could not durably update session state; admission remains closed".into(),
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
fn controller(state: &AppState) -> Result<Arc<DisposableController>, ApiError> {
    state.disposable.clone().ok_or_else(|| {
        api_error(Error::Unavailable(
            "disposable runtime is disabled; configure its host prerequisites first".into(),
        ))
    })
}
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(list).post(create))
        .route("/presets", get(presets))
        .route("/{id}", get(detail).delete(cancel))
        .route("/{id}/source", axum::routing::put(source))
        .route("/{id}/report", get(report))
        .route("/{id}/output", get(output))
        .route("/{id}/terminal", get(terminal).post(terminal_control))
        .route("/{id}/messages", post(message))
        .route("/{id}/grants", get(grants).post(grant))
        .route("/{id}/grants/{grant_id}", axum::routing::delete(revoke))
        .layer(DefaultBodyLimit::max(MAX_SOURCE))
}
async fn list(
    State(state): State<AppState>,
    role: Option<Extension<OperatorRole>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    admin(role)?;
    match &state.disposable {
        Some(c) => {
            let sessions = c.list();
            let active = sessions
                .iter()
                .find(|s| !s.terminal())
                .map(|s| s.id.clone());
            Ok(Json(
                serde_json::json!({"enabled":true,"sessions":sessions,"active_session_id":active,"active_session_ids":sessions.iter().filter(|s|!s.terminal()).map(|s|s.id.clone()).collect::<Vec<_>>(),"resource_usage":c.resource_usage()}),
            ))
        }
        None => Ok(Json(
            serde_json::json!({"enabled":false,"sessions":[],"active_session_id":null}),
        )),
    }
}
async fn presets(
    State(state): State<AppState>,
    role: Option<Extension<OperatorRole>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    admin(role)?;
    Ok(Json(
        serde_json::json!({"enabled":state.disposable.is_some(),"endpoints":state.disposable.as_ref().map(|c|c.gateway.presets()).unwrap_or_default(),"default_resources":{"memory_mb":8192,"vcpus":2},"default_lifetime":"until_deleted","resource_presets":[{"id":"small","name":"Small","memory_mb":8192,"vcpus":2},{"id":"medium","name":"Medium","memory_mb":12288,"vcpus":4},{"id":"security","name":"Security audit","memory_mb":16384,"vcpus":6}],"resource_usage":state.disposable.as_ref().map(|c|c.resource_usage()),"max_duration_seconds":18000}),
    ))
}
async fn create(
    State(state): State<AppState>,
    role: Option<Extension<OperatorRole>>,
    Json(mut input): Json<serde_json::Value>,
) -> Result<Response, ApiError> {
    admin(role)?;
    if input.get("audit_profile").is_some() {
        return Err(api_error(Error::Invalid(
            "audit profiles are selected by host policy, not caller input".into(),
        )));
    }
    let github_token = input
        .as_object_mut()
        .and_then(|o| o.remove("github_token"))
        .map(|v| {
            v.as_str()
                .map(String::from)
                .ok_or_else(|| api_error(Error::Invalid("github_token must be a string".into())))
        })
        .transpose()?;
    let request: CreateRequest =
        serde_json::from_value(input).map_err(|e| api_error(Error::Invalid(e.to_string())))?;
    let session = controller(&state)?
        .create_with_github_token(request, github_token)
        .await
        .map_err(api_error)?;
    Ok((StatusCode::ACCEPTED, Json(session)).into_response())
}
async fn detail(
    State(state): State<AppState>,
    role: Option<Extension<OperatorRole>>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    admin(role)?;
    let s = controller(&state)?.get(&id).map_err(api_error)?;
    let mut value = serde_json::to_value(&s).unwrap();
    value["policy"] = serde_json::json!({"isolation":"kvm","fresh_disk":true,"host_mounts":false,"default_deny_egress":true,"guest_docker":true,"enforcement":if s.state=="running"{"runtime_confirmed"}else{"runtime_preflight_required"}});
    Ok(Json(value))
}
async fn cancel(
    State(state): State<AppState>,
    role: Option<Extension<OperatorRole>>,
    Path(id): Path<String>,
) -> Result<Json<crate::disposable::Session>, ApiError> {
    admin(role)?;
    Ok(Json(controller(&state)?.cancel(&id).map_err(api_error)?))
}
async fn source(
    State(state): State<AppState>,
    role: Option<Extension<OperatorRole>>,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Json<crate::disposable::Session>, ApiError> {
    admin(role)?;
    Ok(Json(
        controller(&state)?
            .upload(&id, body.to_vec())
            .await
            .map_err(api_error)?,
    ))
}
async fn report(
    State(state): State<AppState>,
    role: Option<Extension<OperatorRole>>,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    admin(role)?;
    let bytes = controller(&state)?
        .bounded_file(&id, "report.json")
        .map_err(api_error)?;
    serde_json::from_slice::<serde_json::Value>(&bytes)
        .map_err(|_| api_error(Error::Invalid("guest report is not valid JSON".into())))?;
    Ok((
        [
            ("content-type", "application/json"),
            ("x-content-type-options", "nosniff"),
        ],
        bytes,
    )
        .into_response())
}
async fn output(
    State(state): State<AppState>,
    role: Option<Extension<OperatorRole>>,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    admin(role)?;
    let c = controller(&state)?;
    c.get(&id).map_err(api_error)?;
    c.refresh_output(&id).await.map_err(api_error)?;
    let bytes = c.bounded_file(&id, "events.jsonl").map_err(api_error)?;
    Ok((
        [
            ("content-type", "text/plain; charset=utf-8"),
            ("x-content-type-options", "nosniff"),
        ],
        bytes,
    )
        .into_response())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Message {
    prompt: String,
}
async fn message(
    State(state): State<AppState>,
    role: Option<Extension<OperatorRole>>,
    Path(id): Path<String>,
    Json(request): Json<Message>,
) -> Result<StatusCode, ApiError> {
    admin(role)?;
    controller(&state)?
        .message(&id, request.prompt)
        .await
        .map_err(api_error)?;
    Ok(StatusCode::ACCEPTED)
}
async fn grants(
    State(state): State<AppState>,
    role: Option<Extension<OperatorRole>>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    admin(role)?;
    let c = controller(&state)?;
    c.get(&id).map_err(api_error)?;
    Ok(Json(
        serde_json::json!({"grants":c.gateway.list_grants(&id)}),
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GrantRequest {
    preset_id: String,
    expires_at: Option<DateTime<Utc>>,
}
async fn grant(
    State(state): State<AppState>,
    role: Option<Extension<OperatorRole>>,
    Path(id): Path<String>,
    Json(request): Json<GrantRequest>,
) -> Result<Response, ApiError> {
    admin(role)?;
    let c = controller(&state)?;
    let s = c.get(&id).map_err(api_error)?;
    if s.state != "running" || s.cancelled {
        return Err(api_error(Error::Invalid(
            "grants require an active running session".into(),
        )));
    }
    let grant = c
        .gateway
        .create_grant(&id, &request.preset_id, request.expires_at.or(s.deadline))
        .map_err(|e| api_error(Error::Invalid(e)))?;
    c.persist_grants(&id).map_err(api_error)?;
    c.refresh_grants(&id).await.map_err(api_error)?;
    Ok((StatusCode::CREATED, Json(grant)).into_response())
}
async fn revoke(
    State(state): State<AppState>,
    role: Option<Extension<OperatorRole>>,
    Path((id, grant_id)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    admin(role)?;
    let c = controller(&state)?;
    c.get(&id).map_err(api_error)?;
    if !c.gateway.list_grants(&id).iter().any(|g| g.id == grant_id) {
        return Err(api_error(Error::NotFound));
    }
    c.gateway.revoke_grant(&grant_id);
    c.persist_grants(&id).map_err(api_error)?;
    let _ = c.refresh_grants(&id).await;
    Ok(StatusCode::NO_CONTENT)
}

/// Streaming replay of the guest PTY, authenticated with the same explicit admin
/// identity as every control request. Fetch/SSE keeps bearer tokens out of URLs.
async fn terminal(
    State(state): State<AppState>,
    role: Option<Extension<OperatorRole>>,
    Path(id): Path<String>,
    axum::extract::Query(query): axum::extract::Query<TerminalQuery>,
) -> Result<Response, ApiError> {
    admin(role)?;
    let c = controller(&state)?;
    let session = c.get(&id).map_err(api_error)?;
    if session.request.kind != "interactive" {
        return Err(api_error(Error::Invalid(
            "terminal requires an interactive VM".into(),
        )));
    }
    let console = c.gateway.console();
    console.snapshot(&id, query.after).map_err(console_error)?;
    let stream = async_stream::stream! {
        let mut after = query.after;
        loop {
            match console.snapshot(&id, after) {
                Ok(snapshot) => {
                    after = snapshot.sequence;
                    let done = snapshot.revoked;
                    yield Ok::<_, std::convert::Infallible>(axum::response::sse::Event::default().event("terminal").json_data(snapshot).unwrap());
                    if done { break; }
                },
                Err(_) => break,
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
    };
    Ok(axum::response::Sse::new(stream)
        .keep_alive(axum::response::sse::KeepAlive::default())
        .into_response())
}
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct TerminalQuery {
    #[serde(default)]
    after: u64,
}
fn console_error(status: StatusCode) -> ApiError {
    (
        status,
        Json(serde_json::json!({"error":match status {
            StatusCode::CONFLICT => "another browser is controlling this terminal; disconnect it or wait 30 seconds",
            StatusCode::GONE => "terminal is closed or VM was deleted",
            StatusCode::TOO_MANY_REQUESTS => "terminal input queue is full",
            _ => "terminal unavailable or invalid request",
        }})),
    )
}
async fn terminal_control(
    State(state): State<AppState>,
    role: Option<Extension<OperatorRole>>,
    Path(id): Path<String>,
    Json(input): Json<crate::disposable_console::Control>,
) -> Result<StatusCode, ApiError> {
    admin(role)?;
    let c = controller(&state)?;
    let session = c.get(&id).map_err(api_error)?;
    if session.request.kind != "interactive" || session.state != "running" || session.cancelled {
        return Err(api_error(Error::Invalid(
            "interactive VM must be running".into(),
        )));
    }
    c.gateway
        .console()
        .control(&id, input)
        .map_err(console_error)?;
    Ok(StatusCode::ACCEPTED)
}
