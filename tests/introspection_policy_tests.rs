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

fn app_with_policies(names: &[&str]) -> Router {
    let mut policies = std::collections::BTreeMap::new();
    // Always include default.
    policies.insert(
        "default".to_string(),
        acip_sidecar::model_policy::PolicyConfig::default(),
    );
    for n in names {
        policies.insert(
            n.to_string(),
            acip_sidecar::model_policy::PolicyConfig::default(),
        );
    }

    let store = policy_store::PolicyStore::from_file(policy_store::PoliciesFile { policies });

    let st = Arc::new(state::AppState {
        policy: state::Policy {
            head: 4000,
            tail: 4000,
            full_if_lte: 9000,
        },
        normalize: state::NormalizeSettings::from_config(None),
        http: reqwest::Client::new(),
        secrets: Arc::new(acip_sidecar::secrets::EnvStore),
        policies: store,
        reputation: Arc::new(acip_sidecar::reputation::InMemoryReputationStore::new()),
    });

    Router::new()
        .route("/v1/acip/schema", get(routes::get_schema))
        .route("/v1/acip/policies", get(routes::list_policies))
        .route("/v1/acip/policy", get(routes::get_policy))
        .with_state(st)
}

#[tokio::test]
async fn schema_endpoint_returns_json_schema() {
    let app = app_with_policies(&[]);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/v1/acip/schema")
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

    assert_eq!(v["title"], "AcipDecision");
    assert_eq!(v["type"], "object");
    assert!(v["properties"].is_object());
}

#[tokio::test]
async fn policies_endpoint_lists_policies_sorted() {
    let app = app_with_policies(&["b", "a"]);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/v1/acip/policies")
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

    let arr = v["policies"].as_array().unwrap();
    let names: Vec<String> = arr
        .iter()
        .map(|x| x.as_str().unwrap().to_string())
        .collect();
    assert_eq!(names, vec!["a", "b", "default"]);
}

#[tokio::test]
async fn get_policy_defaults_to_default() {
    let app = app_with_policies(&[]);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/v1/acip/policy")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn unknown_policy_returns_400() {
    let app = app_with_policies(&[]);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/v1/acip/policy")
                .header("X-ACIP-Policy", "nope")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(&body.to_bytes()).unwrap();
    assert_eq!(v["error"], "unknown policy");
    assert!(v["extra"]["available"]
        .as_array()
        .unwrap()
        .contains(&Value::String("default".into())));
}
