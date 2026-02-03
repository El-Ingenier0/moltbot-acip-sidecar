use axum::{body::Body, http::Request, http::StatusCode, Router};
use acip_sidecar::{policy_store, secrets, state};
use std::sync::Arc;
use tower::ServiceExt;

fn app() -> Router {
    let mut policies = std::collections::BTreeMap::new();
    policies.insert(
        "default".to_string(),
        acip_sidecar::model_policy::PolicyConfig::default(),
    );
    policies.insert(
        "strict".to_string(),
        acip_sidecar::model_policy::PolicyConfig::default(),
    );

    let st = Arc::new(state::AppState {
        policy: state::Policy {
            head: 4,
            tail: 4,
            full_if_lte: 6,
        },
        normalize: state::NormalizeSettings::from_config(None),
        http: reqwest::Client::new(),
        secrets: Arc::new(secrets::EnvStore),
        policies: policy_store::PolicyStore::from_file(policy_store::PoliciesFile { policies }),
        reputation: Arc::new(acip_sidecar::reputation::InMemoryReputationStore::new()),
    });

    // Reuse the ingest handler from main.rs logic isn't possible here, so we just verify
    // the policy selection helper behavior via /v1/acip/policy.
    // (Full ingest gating is covered indirectly in the binary.)
    Router::new()
        .route(
            "/v1/acip/policy",
            axum::routing::get(acip_sidecar::routes::get_policy),
        )
        .with_state(st)
}

#[tokio::test]
async fn unknown_policy_header_returns_400() {
    let app = app();
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
}

#[tokio::test]
async fn known_policy_header_returns_200() {
    let app = app();
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/v1/acip/policy")
                .header("X-ACIP-Policy", "strict")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
}
