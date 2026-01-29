use axum::{
    body::Body,
    http::{Request, StatusCode},
    routing::post,
    Router,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use moltbot_acip_sidecar::{app, ingest, policy_store, reputation, secrets, state};
use serde_json::Value;
use std::{fs, os::unix::fs::PermissionsExt, sync::Arc};
use tower::ServiceExt;

use serial_test::serial;

fn init_env() {
    std::env::set_var("ACIP_SENTRY_MODE", "stub");
    std::env::set_var("ACIP_REP_HALFLIFE_BASE_DAYS", "9999");
    std::env::set_var("ACIP_REP_HALFLIFE_K", "0");
    std::env::set_var("ACIP_REP_MED", "20");
    std::env::set_var("ACIP_REP_HIGH", "50");
    std::env::set_var("ACIP_REP_BAD", "150");
    std::env::set_var("ACIP_EXTRACTOR_TIMEOUT_SECS", "180");
    std::env::set_var("ACIP_EXTRACTOR_BIN", env!("CARGO_BIN_EXE_acip-extract"));
}

fn router() -> Router {
    let mut policies = std::collections::BTreeMap::new();
    policies.insert(
        "default".to_string(),
        moltbot_acip_sidecar::model_policy::PolicyConfig::default(),
    );

    let st = Arc::new(state::AppState {
        policy: state::Policy {
            head: 4000,
            tail: 4000,
            full_if_lte: 9000,
        },
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

    let v: Value = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(_) => Value::String(String::from_utf8_lossy(&bytes).to_string()),
    };
    (status, v)
}

fn fixture_pdf_b64() -> String {
    let pdf = include_bytes!("fixtures/acip_known_text.pdf");
    B64.encode(pdf)
}

#[tokio::test]
#[serial]
async fn extractor_missing_binary_returns_400() {
    init_env();

    std::env::set_var("ACIP_EXTRACTOR_BIN", "/definitely-not-a-real-binary");

    let app = router();
    let (status, v) = post_ingest(
        app,
        serde_json::json!({
            "source_id": "missing-extractor",
            "source_type": "pdf",
            "content_type": "application/pdf",
            "bytes_b64": fixture_pdf_b64()
        }),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let s = v.as_str().unwrap_or("");
    assert!(s.contains("extract_failed") || s.contains("spawn"));
}

#[tokio::test]
#[serial]
async fn extractor_nonzero_exit_returns_400() {
    init_env();

    std::env::set_var("ACIP_EXTRACTOR_BIN", "/bin/false");

    let app = router();
    let (status, v) = post_ingest(
        app,
        serde_json::json!({
            "source_id": "false-extractor",
            "source_type": "pdf",
            "content_type": "application/pdf",
            "bytes_b64": fixture_pdf_b64()
        }),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let s = v.as_str().unwrap_or("");
    assert!(s.contains("acip-extract failed") || s.contains("extract_failed"));
}

#[tokio::test]
#[serial]
async fn extractor_timeout_returns_408() {
    init_env();

    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join("sleepy.sh");
    fs::write(
        &script,
        "#!/bin/sh\n# sleep longer than the test timeout\nsleep 2\necho '{\"ok\":true,\"kind\":\"pdf\",\"text\":\"x\",\"warnings\":[],\"stats\":{\"text_chars\":1,\"ocr_used\":false,\"ocr_chars\":0}}'\n",
    )
    .unwrap();
    let mut perms = fs::metadata(&script).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&script, perms).unwrap();

    std::env::set_var("ACIP_EXTRACTOR_BIN", script);
    std::env::set_var("ACIP_EXTRACTOR_TIMEOUT_SECS", "1");

    let app = router();
    let (status, v) = post_ingest(
        app,
        serde_json::json!({
            "source_id": "timeout-extractor",
            "source_type": "pdf",
            "content_type": "application/pdf",
            "bytes_b64": fixture_pdf_b64()
        }),
    )
    .await;

    assert_eq!(status, StatusCode::REQUEST_TIMEOUT);
    let s = v.as_str().unwrap_or("");
    assert!(s.contains("extract_timeout"));
}
