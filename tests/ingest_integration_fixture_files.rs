use axum::{
    body::Body,
    http::{Request, StatusCode},
    routing::post,
    Router,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use moltbot_acip_sidecar::{app, ingest, policy_store, reputation, secrets, state};
use serde_json::Value;
use std::{
    process::Command,
    sync::{Arc, Once},
};
use tower::ServiceExt;

static INIT: Once = Once::new();

fn init_env() {
    INIT.call_once(|| {
        // Avoid real model calls.
        std::env::set_var("ACIP_SENTRY_MODE", "stub");
        std::env::set_var("ACIP_REP_HALFLIFE_BASE_DAYS", "9999");
        std::env::set_var("ACIP_REP_HALFLIFE_K", "0");
        std::env::set_var("ACIP_REP_MED", "20");
        std::env::set_var("ACIP_REP_HIGH", "50");
        std::env::set_var("ACIP_REP_BAD", "150");
        std::env::set_var("ACIP_EXTRACTOR_BIN", env!("CARGO_BIN_EXE_acip-extract"));
    });
}

fn have_bin(name: &str) -> bool {
    Command::new("sh")
        .arg("-lc")
        .arg(format!("command -v {name} >/dev/null 2>&1"))
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
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

#[tokio::test]
async fn extracts_known_text_pdf() {
    init_env();

    if !(have_bin("pdftotext") && have_bin("pdftoppm")) {
        // Environment doesn't have Poppler; skip.
        return;
    }

    // The helper must be available on PATH; cargo test sets it up for workspace binaries.
    let pdf = include_bytes!("fixtures/acip_known_text.pdf");
    let b64 = B64.encode(pdf);

    let app = router();
    let (status, v) = post_ingest(
        app,
        serde_json::json!({
            "source_id": "fixture-text-pdf",
            "source_type": "pdf",
            "content_type": "application/pdf",
            "bytes_b64": b64
        }),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["normalized"], true);

    // Should have fenced content containing the known phrase.
    let fenced = v["fenced_content"].as_str().unwrap_or("");
    assert!(fenced.contains("ACIP FIXTURE TEXT"));
}

#[tokio::test]
async fn scanned_pdf_triggers_ocr_path() {
    init_env();

    if !(have_bin("pdftotext") && have_bin("pdftoppm")) {
        return;
    }

    let pdf = include_bytes!("fixtures/acip_scanned.pdf");
    let b64 = B64.encode(pdf);

    let app = router();
    let (status, v) = post_ingest(
        app,
        serde_json::json!({
            "source_id": "fixture-scan-pdf",
            "source_type": "pdf",
            "content_type": "application/pdf",
            "bytes_b64": b64
        }),
    )
    .await;

    assert_eq!(status, StatusCode::OK);

    // We can't guarantee tesseract exists in every test env, but we can assert we attempted the OCR fallback.
    let steps = v["normalization_steps"].as_array().unwrap();
    assert!(steps.iter().any(|x| x
        .as_str()
        .unwrap_or("")
        .contains("pdf_text_layer_missing_or_small")));

    if have_bin("tesseract") {
        let fenced = v["fenced_content"].as_str().unwrap_or("");
        // OCR output can vary by tesseract version; assert we actually included an OCR section.
        assert!(fenced.contains("--- OCR ---"), "fenced_content={fenced}");
    }
}

#[tokio::test]
async fn extracts_known_svg_text_and_flags_xml_tokens() {
    init_env();

    let svg = include_bytes!("fixtures/acip_known.svg");
    let b64 = B64.encode(svg);

    let app = router();
    let (status, v) = post_ingest(
        app,
        serde_json::json!({
            "source_id": "fixture-svg",
            "source_type": "html",
            "content_type": "image/svg+xml",
            "bytes_b64": b64
        }),
    )
    .await;

    assert_eq!(status, StatusCode::OK);

    let fenced = v["fenced_content"].as_str().unwrap_or("");
    assert!(fenced.contains("ACIP SVG FIXTURE"));

    // Not in audit mode, so the xml_scan indicators won't appear, but helper warnings are in normalization_steps.
    let steps = v["normalization_steps"].as_array().unwrap();
    assert!(steps
        .iter()
        .any(|x| x.as_str().unwrap_or("") == "sandbox_extract"));
}
