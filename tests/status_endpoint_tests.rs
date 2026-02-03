use axum::{
    body::Body,
    http::{Request, StatusCode},
    routing::get,
    Router,
};
use acip_sidecar::{policy_store, routes, state};
use serde_json::Value;
use std::sync::Arc;
use tower::ServiceExt;

fn app() -> Router {
    let mut policies = std::collections::BTreeMap::new();
    policies.insert(
        "default".to_string(),
        acip_sidecar::model_policy::PolicyConfig::default(),
    );

    let st = Arc::new(state::AppState {
        policy: state::Policy {
            head: 1,
            tail: 2,
            full_if_lte: 3,
        },
        normalize: state::NormalizeSettings::from_config(None),
        http: reqwest::Client::new(),
        secrets: Arc::new(acip_sidecar::secrets::EnvStore),
        policies: policy_store::PolicyStore::from_file(policy_store::PoliciesFile { policies }),
        reputation: Arc::new(acip_sidecar::reputation::InMemoryReputationStore::new()),
    });

    Router::new()
        .route(
            "/v1/acip/status",
            get(acip_sidecar::status::get_status),
        )
        .route("/v1/acip/policies", get(routes::list_policies))
        .with_state(st)
}

#[tokio::test]
async fn status_endpoint_returns_ok_and_policy_values() {
    std::env::set_var("ACIP_SENTRY_MODE", "stub");

    let app = app();
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/v1/acip/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(&body.to_bytes()).unwrap();

    assert_eq!(v["ok"], true);
    assert_eq!(v["policy"]["head"], 1);
    assert_eq!(v["policy"]["tail"], 2);
    assert_eq!(v["policy"]["full_if_lte"], 3);
    assert!(v["policies"].as_array().unwrap().len() >= 1);
}
