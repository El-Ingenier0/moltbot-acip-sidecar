use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
};
use acip_sidecar::{app, policy_store, reputation, secrets, state};
use std::sync::Arc;
use tower::ServiceExt;

fn app_with_token(token: Option<String>) -> Router {
    let mut policies = std::collections::BTreeMap::new();
    policies.insert(
        "default".to_string(),
        acip_sidecar::model_policy::PolicyConfig::default(),
    );

    let st = Arc::new(state::AppState {
        policy: state::Policy {
            head: 4000,
            tail: 4000,
            full_if_lte: 9000,
        },
        normalize: state::NormalizeSettings::from_config(None),
        http: reqwest::Client::new(),
        secrets: Arc::new(secrets::EnvStore),
        policies: policy_store::PolicyStore::from_file(policy_store::PoliciesFile { policies }),
        reputation: Arc::new(reputation::InMemoryReputationStore::new()),
    });

    app::build_router(st, token, Router::new())
}

#[tokio::test]
async fn health_is_unprotected() {
    let app = app_with_token(Some("secret".into()));
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn protected_denies_without_token() {
    let app = app_with_token(Some("secret".into()));
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/v1/acip/schema")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn protected_allows_with_token() {
    let app = app_with_token(Some("secret".into()));
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/v1/acip/schema")
                .header("X-ACIP-Token", "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}
