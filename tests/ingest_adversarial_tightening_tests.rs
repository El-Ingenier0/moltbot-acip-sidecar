use axum::{
    body::Body,
    http::{Request, StatusCode},
    routing::post,
    Router,
};
use acip_sidecar::{app, ingest, policy_store, reputation, secrets, state};
use serde_json::Value;
use std::sync::Arc;
use tower::ServiceExt;

fn router_with_state(policy: state::Policy, normalize: state::NormalizeSettings) -> Router {
    let mut policies = std::collections::BTreeMap::new();
    policies.insert(
        "default".to_string(),
        acip_sidecar::model_policy::PolicyConfig::default(),
    );

    let st = Arc::new(state::AppState {
        policy,
        normalize,
        http: reqwest::Client::new(),
        secrets: Arc::new(secrets::EnvStore),
        policies: policy_store::PolicyStore::from_file(policy_store::PoliciesFile { policies }),
        reputation: Arc::new(reputation::InMemoryReputationStore::new()),
    });

    let extra = Router::new().route("/v1/acip/ingest_source", post(ingest::ingest_source));
    app::build_router(st, None, extra)
}

async fn post_ingest(app: Router, body: Value) -> (StatusCode, Value) {
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/acip/ingest_source")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    let status = resp.status();
    let bytes = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    (status, v)
}

#[tokio::test]
async fn adversarial_tightening_reduces_window_for_markup() {
    std::env::set_var("ACIP_SENTRY_MODE", "stub");

    let policy = state::Policy {
        head: 1000,
        tail: 1000,
        full_if_lte: 2200,
    };
    let normalize = state::NormalizeSettings {
        max_input_chars: 400,
        window_head_chars: 200,
        window_tail_chars: 200,
        adversarial_threshold: 1,
        adversarial_tighten_factor: 0.5,
    };

    let app = router_with_state(policy, normalize);
    let body = serde_json::json!({
        "source_id": "m1",
        "source_type": "html",
        "content_type": "text/html",
        "text": format!(
            "<html><body><script>alert(1)</script><div onclick=\"x()\">x</div>{}</body></html>",
            "a".repeat(3000)
        )
    });

    let (status, v) = post_ingest(app, body).await;
    assert_eq!(status, StatusCode::OK);

    // Truncation policy (head/tail/full_if_lte) should NOT change; this tightening only affects
    // markup normalization window sizes.
    assert_eq!(v["policy"]["head"], 1000);
    assert_eq!(v["policy"]["tail"], 1000);
    assert_eq!(v["policy"]["full_if_lte"], 2200);

    // Evidence of tightening should appear in normalization steps.
    let steps = v["normalization_steps"].as_array().unwrap();
    let joined = steps
        .iter()
        .filter_map(|x| x.as_str())
        .collect::<Vec<_>>()
        .join("|");
    assert!(joined.contains("adversarial_tighten"));
}

#[tokio::test]
async fn non_markup_does_not_tighten_windows() {
    std::env::set_var("ACIP_SENTRY_MODE", "stub");

    let policy = state::Policy {
        head: 1000,
        tail: 1000,
        full_if_lte: 2200,
    };
    let normalize = state::NormalizeSettings {
        max_input_chars: 400,
        window_head_chars: 200,
        window_tail_chars: 200,
        adversarial_threshold: 1,
        adversarial_tighten_factor: 0.5,
    };

    let app = router_with_state(policy, normalize);
    let body = serde_json::json!({
        "source_id": "m2",
        "source_type": "other",
        "content_type": "text/plain",
        "text": format!(
            "hello <script>alert(1)</script> {}",
            "a".repeat(3000)
        )
    });

    let (status, v) = post_ingest(app, body).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["policy"]["head"], 1000);
    assert_eq!(v["policy"]["tail"], 1000);
    assert_eq!(v["policy"]["full_if_lte"], 2200);
}
