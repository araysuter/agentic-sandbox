#[path = "../../../management/src/disposable_gateway.rs"]
pub mod disposable_gateway;

#[path = "../../../management/src/disposable.rs"]
pub mod disposable;

// Minimal dependency doubles for the HTTP handler seam only. The router and
// handler implementation below is the production source; full management auth
// middleware/workspace compilation remains a separate check.
pub mod http;

#[cfg(test)]
mod http_contracts {
    use super::http::{disposable, operator_auth::OperatorRole, server::AppState};
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        Extension, Router,
    };
    use tower::ServiceExt;

    #[tokio::test]
    async fn production_router_requires_explicit_admin_and_has_canonical_root() {
        let router = Router::new()
            .nest("/api/v2/disposable-sessions", disposable::router())
            .with_state(AppState { disposable: None });
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v2/disposable-sessions")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let response = router
            .clone()
            .layer(Extension(OperatorRole::Operator))
            .oneshot(
                Request::builder()
                    .uri("/api/v2/disposable-sessions/presets")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let response = router
            .layer(Extension(OperatorRole::Admin))
            .oneshot(
                Request::builder()
                    .uri("/api/v2/disposable-sessions")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}

#[cfg(all(test, unix))]
mod http_lifecycle {
    use super::{
        disposable::DisposableController,
        disposable_gateway::GatewayStore,
        http::{disposable, operator_auth::OperatorRole, server::AppState},
    };
    use axum::{
        body::{to_bytes, Body},
        http::{Request, StatusCode},
        Extension, Router,
    };
    use std::{os::unix::fs::PermissionsExt, sync::Arc};
    use tower::ServiceExt;

    async fn call(
        app: &Router,
        method: &str,
        path: &str,
        value: Option<serde_json::Value>,
    ) -> (StatusCode, serde_json::Value) {
        let req = Request::builder()
            .method(method)
            .uri(path)
            .header("content-type", "application/json")
            .body(Body::from(value.map(|v| v.to_string()).unwrap_or_default()))
            .unwrap();
        let response = app.clone().oneshot(req).await.unwrap();
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 2 * 1024 * 1024)
            .await
            .unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
        )
    }

    #[tokio::test]
    async fn actual_http_create_busy_mcp_revoke_prompt_and_cleanup() {
        let tmp = tempfile::tempdir().unwrap();
        let script = tmp.path().join("fixture-runtime.sh");
        std::fs::write(&script, "#!/bin/sh\ncase \"$1\" in\ncheck|start|message|grants|logs|collect) printf '{}';;\nstatus) printf '{\"state\":\"running\"}';;\nstop) printf '{\"contained\":true}';;\n*) exit 1;;\nesac\n").unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
        let presets = serde_json::from_value(serde_json::json!([
            {"id":"studio", "kind":"model", "base_url":"http://192.168.1.80:8080/v1", "path_prefixes":["/v1/chat/completions"], "methods":["POST"], "allow_private":true, "model_name":"fixture-model"},
            {"id":"fixture-mcp", "kind":"mcp", "base_url":"http://192.168.1.81:8080/mcp", "path_prefixes":["/mcp"], "methods":["POST","GET","DELETE"], "allow_private":true}
        ])).unwrap();
        let controller = DisposableController::open(
            tmp.path().join("state"),
            script,
            GatewayStore::new(presets).unwrap(),
        )
        .await
        .unwrap();
        let app = Router::new()
            .nest("/api/v2/disposable-sessions", disposable::router())
            .with_state(AppState {
                disposable: Some(Arc::clone(&controller)),
            })
            .layer(Extension(OperatorRole::Admin));
        let root = "/api/v2/disposable-sessions";
        let request =
            serde_json::json!({"kind":"interactive", "duration_seconds":600, "model_id":"studio"});
        let (code, created) = call(&app, "POST", root, Some(request.clone())).await;
        assert_eq!(code, StatusCode::ACCEPTED, "{created}");
        let id = created["id"].as_str().unwrap();
        let path = format!("{root}/{id}");
        assert_eq!(
            call(&app, "POST", root, Some(request)).await.0,
            StatusCode::CONFLICT
        );
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                if controller.get(id).unwrap().state == "running" {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        let (code, grant) = call(
            &app,
            "POST",
            &format!("{path}/grants"),
            Some(serde_json::json!({"preset_id":"fixture-mcp"})),
        )
        .await;
        assert_eq!(code, StatusCode::CREATED, "{grant}");
        assert!(controller
            .gateway
            .list_grants(id)
            .iter()
            .any(|g| g.kind == "mcp"));
        assert_eq!(
            call(
                &app,
                "DELETE",
                &format!("{path}/grants/{}", grant["id"].as_str().unwrap()),
                None
            )
            .await
            .0,
            StatusCode::NO_CONTENT
        );
        assert!(!controller
            .gateway
            .list_grants(id)
            .iter()
            .any(|g| g.kind == "mcp"));
        assert_eq!(
            call(
                &app,
                "POST",
                &format!("{path}/messages"),
                Some(serde_json::json!({"prompt":"Inspect the fixture workspace"}))
            )
            .await
            .0,
            StatusCode::ACCEPTED
        );
        assert_eq!(call(&app, "DELETE", &path, None).await.0, StatusCode::OK);
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                if controller.get(id).unwrap().terminal() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(controller.get(id).unwrap().state, "cancelled");
        assert!(controller.gateway.guest_capability(id).is_none());
    }
}

#[cfg(test)]
mod record_contracts {
    #[test]
    fn persisted_session_request_roundtrips_host_profile() {
        let mut request: crate::disposable::CreateRequest =
            serde_json::from_value(serde_json::json!({"kind":"interactive"})).unwrap();
        request.audit_profile.test_commands =
            vec![vec!["python3".into(), "-m".into(), "pytest".into()]];
        let stored = serde_json::to_value(&request).unwrap();
        let restored: crate::disposable::CreateRequest = serde_json::from_value(stored).unwrap();
        assert_eq!(
            restored.audit_profile.test_commands,
            request.audit_profile.test_commands
        );
    }
}
