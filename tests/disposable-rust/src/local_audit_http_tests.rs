use crate::{
    disposable::DisposableController,
    disposable_gateway::GatewayStore,
    http::{local_audits, operator_auth::OperatorRole, server::AppState},
    local_audits::LocalAuditService,
};
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    Extension, Router,
};
use tower::ServiceExt;

async fn call(
    app: &Router,
    method: &str,
    path: &str,
    input: Option<serde_json::Value>,
) -> (StatusCode, serde_json::Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(path)
                .header("content-type", "application/json")
                .body(Body::from(input.map(|v| v.to_string()).unwrap_or_default()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), 2 * 1024 * 1024)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null),
    )
}

#[tokio::test]
async fn local_routes_require_explicit_admin_and_report_disabled_service() {
    let app = Router::new()
        .nest("/api/v2/local-audits", local_audits::router())
        .with_state(AppState {
            disposable: None,
            local_audits: None,
        });
    assert_eq!(
        call(&app, "GET", "/api/v2/local-audits", None).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        call(
            &app.clone().layer(Extension(OperatorRole::Operator)),
            "GET",
            "/api/v2/local-audits",
            None
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    let admin = app.layer(Extension(OperatorRole::Admin));
    let (code, body) = call(&admin, "GET", "/api/v2/local-audits", None).await;
    assert_eq!(code, StatusCode::OK);
    assert_eq!(body["enabled"], false);
    let input = serde_json::json!({"repository":"fixture/repo", "github_token":"fixture-key-only-no-live-access"});
    assert_eq!(
        call(&admin, "POST", "/api/v2/local-audits", Some(input))
            .await
            .0,
        StatusCode::SERVICE_UNAVAILABLE
    );
}

#[cfg(unix)]
#[tokio::test]
async fn actual_routes_save_edit_rotate_and_delete_host_credentials_without_echo() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().unwrap();
    let runtime = tmp.path().join("runtime.sh");
    std::fs::write(&runtime, "#!/bin/sh\nprintf '{}'").unwrap();
    std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700)).unwrap();
    let presets = serde_json::from_value(serde_json::json!([{
        "id":"studio", "kind":"model", "model_name":"fixture",
        "base_url":"http://192.168.1.80:8080/v1", "path_prefixes":["/v1/chat/completions"],
        "methods":["POST"], "allow_private":true
    }]))
    .unwrap();
    let controller = DisposableController::open(
        tmp.path().join("vm"),
        runtime,
        GatewayStore::new(presets).unwrap(),
    )
    .await
    .unwrap();
    let host_root = tmp.path().join("audits");
    let service = LocalAuditService::open(
        host_root.clone(),
        tmp.path().join("worker.py"),
        controller.clone(),
    )
    .unwrap();
    let app = Router::new()
        .nest("/api/v2/local-audits", local_audits::router())
        .with_state(AppState {
            disposable: Some(controller),
            local_audits: Some(service),
        })
        .layer(Extension(OperatorRole::Admin));
    let mut input = serde_json::json!({"repository":"fixture/repo", "enabled":false,
        "github_token":"fixture-key-only-no-live-access", "schedule":{"weekday":1,"start_time":"01:00","end_time":"06:00","timezone":"America/Detroit"}});
    let (code, created) = call(&app, "POST", "/api/v2/local-audits", Some(input.clone())).await;
    assert_eq!(code, StatusCode::CREATED, "{created}");
    assert_eq!(created["credential_configured"], true);
    assert!(created.get("github_token").is_none());
    assert!(!created.to_string().contains("fixture-key"));
    let id = created["id"].as_str().unwrap();
    let keys: Vec<_> = std::fs::read_dir(host_root.join("credentials"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    assert_eq!(keys.len(), 1);
    assert_eq!(
        std::fs::metadata(&keys[0]).unwrap().permissions().mode() & 0o777,
        0o600
    );
    input["github_token"] = serde_json::Value::Null;
    input["schedule"]["weekday"] = 2.into();
    assert_eq!(
        call(
            &app,
            "PUT",
            &format!("/api/v2/local-audits/{id}"),
            Some(input.clone())
        )
        .await
        .0,
        StatusCode::OK
    );
    assert!(keys[0].exists());
    input["github_token"] = "another-fixture-key-no-live-access".into();
    assert_eq!(
        call(
            &app,
            "PUT",
            &format!("/api/v2/local-audits/{id}"),
            Some(input)
        )
        .await
        .0,
        StatusCode::OK
    );
    assert!(!keys[0].exists());
    let (_, snapshot) = call(&app, "GET", "/api/v2/local-audits", None).await;
    assert!(!snapshot.to_string().contains("fixture-key"));
    assert_eq!(
        call(&app, "DELETE", &format!("/api/v2/local-audits/{id}"), None)
            .await
            .0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        std::fs::read_dir(host_root.join("credentials"))
            .unwrap()
            .count(),
        0
    );
}
