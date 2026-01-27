use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use clap::Parser;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{net::SocketAddr, sync::Arc};
use tracing::{error, info};

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    /// Bind host (default: 127.0.0.1)
    #[arg(long, default_value = "127.0.0.1")]
    host: String,

    /// Bind port (default: 18795)
    #[arg(long, default_value_t = 18795)]
    port: u16,

    /// Max chars for head/tail policy head
    #[arg(long, default_value_t = 4000)]
    head: usize,

    /// Max chars for head/tail policy tail
    #[arg(long, default_value_t = 4000)]
    tail: usize,

    /// If total <= this, include whole text (default: 9000)
    #[arg(long, default_value_t = 9000)]
    full_if_lte: usize,
}

#[derive(Clone)]
struct AppState {
    policy: Policy,
}

#[derive(Clone, Debug)]
struct Policy {
    head: usize,
    tail: usize,
    full_if_lte: usize,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
enum SourceType {
    Html,
    Pdf,
    Tweet,
    File,
    Clipboard,
    Other,
}

#[derive(Deserialize, Debug)]
struct IngestRequest {
    source_id: String,
    source_type: SourceType,
    content_type: String,

    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    turn_id: Option<String>,

    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    bytes_b64: Option<String>,
}

#[derive(Serialize, Debug)]
struct DigestInfo {
    sha256: String,
    length: usize,
}

#[derive(Serialize, Debug)]
struct PolicyInfo {
    head: usize,
    tail: usize,
    full_if_lte: usize,
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "snake_case")]
enum RiskLevel {
    Low,
    Medium,
    High,
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "snake_case")]
enum Action {
    Allow,
    Sanitize,
    Block,
    NeedsReview,
}

#[derive(Serialize, Debug)]
struct IngestResponse {
    digest: DigestInfo,
    truncated: bool,
    policy: PolicyInfo,

    tools_allowed: bool,
    risk_level: RiskLevel,
    action: Action,

    fenced_content: String,
    reasons: Vec<String>,
    detected_patterns: Vec<String>,
}

fn fence_external(s: &str) -> String {
    format!("```external\n{}\n```", s)
}

fn apply_head_tail(policy: &Policy, text: &str) -> (String, bool) {
    let len = text.chars().count();
    if len <= policy.full_if_lte {
        return (text.to_string(), false);
    }
    let head: String = text.chars().take(policy.head).collect();
    let tail: String = text
        .chars()
        .rev()
        .take(policy.tail)
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    let combined = format!("{}\n\n[...TRUNCATED...]\n\n{}", head, tail);
    (combined, true)
}

async fn health() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

async fn ingest_source(
    State(state): State<Arc<AppState>>,
    Json(req): Json<IngestRequest>,
) -> impl IntoResponse {
    // v0.1 behavior:
    // - Accept text or base64 bytes
    // - If bytes, decode and best-effort treat as UTF-8 (PDF extraction to be added)
    // - Apply deterministic truncation
    // - Return fenced content
    // - Default allow tools (real sentry model calls come later)

    let mut raw = None;

    if let Some(t) = req.text {
        raw = Some(t);
    } else if let Some(b64) = req.bytes_b64 {
        match B64.decode(b64.as_bytes()) {
            Ok(bytes) => match String::from_utf8(bytes) {
                Ok(s) => raw = Some(s),
                Err(e) => {
                    error!("bytes_b64 not valid utf8: {e}");
                    return (StatusCode::BAD_REQUEST, "bytes_b64 must be UTF-8 for v0.1")
                        .into_response();
                }
            },
            Err(e) => {
                error!("base64 decode failed: {e}");
                return (StatusCode::BAD_REQUEST, "invalid base64").into_response();
            }
        }
    }

    let Some(raw) = raw else {
        return (StatusCode::BAD_REQUEST, "must provide text or bytes_b64").into_response();
    };

    let mut hasher = Sha256::new();
    hasher.update(raw.as_bytes());
    let sha = hex::encode(hasher.finalize());

    let (trunc_text, truncated) = apply_head_tail(&state.policy, &raw);

    // TODO(v0.2): run L1 (Gemini Flash) -> strict JSON; fallback L2 (Haiku)
    let tools_allowed = true;
    let risk_level = RiskLevel::Low;
    let action = Action::Allow;

    let resp = IngestResponse {
        digest: DigestInfo {
            sha256: sha,
            length: raw.chars().count(),
        },
        truncated,
        policy: PolicyInfo {
            head: state.policy.head,
            tail: state.policy.tail,
            full_if_lte: state.policy.full_if_lte,
        },
        tools_allowed,
        risk_level,
        action,
        fenced_content: fence_external(&trunc_text),
        reasons: vec!["v0.1 passthrough (no model sentry yet)".to_string()],
        detected_patterns: vec![],
    };

    (StatusCode::OK, Json(resp)).into_response()
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args = Args::parse();

    let state = Arc::new(AppState {
        policy: Policy {
            head: args.head,
            tail: args.tail,
            full_if_lte: args.full_if_lte,
        },
    });

    let app = Router::new()
        .route("/health", get(health))
        .route("/v1/acip/ingest_source", post(ingest_source))
        .with_state(state);

    let addr: SocketAddr = format!("{}:{}", args.host, args.port).parse()?;
    info!("listening on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
