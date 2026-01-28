use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::post,
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use clap::Parser;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::Duration;
use std::{net::SocketAddr, path::PathBuf, sync::Arc};
use tracing::{error, info, warn};

use moltbot_acip_sidecar::{
    app, config, introspection, model_policy, policy_store, routes, secrets, sentry, state,
};

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    /// Bind host (default: 127.0.0.1)
    #[arg(long)]
    host: Option<String>,

    /// Bind port (default: 18795)
    #[arg(long)]
    port: Option<u16>,

    /// Max chars for head/tail policy head
    #[arg(long)]
    head: Option<usize>,

    /// Max chars for head/tail policy tail
    #[arg(long)]
    tail: Option<usize>,

    /// If total <= this, include whole text (default: 9000)
    #[arg(long)]
    full_if_lte: Option<usize>,

    /// Optional secrets env file (must be private: parent 700-ish, file 600-ish).
    ///
    /// If set, secrets are resolved from: secrets file → process env.
    /// Recommended system path: `/etc/acip/secrets.env`
    #[arg(long)]
    secrets_file: Option<PathBuf>,

    /// Policies JSON file (non-secret). Used with X-ACIP-Policy selection.
    /// Recommended system path: `/etc/acip/policies.json`
    #[arg(long)]
    policies_file: Option<PathBuf>,

    /// Config TOML file (default: /etc/acip/config.toml)
    #[arg(long)]
    config: Option<PathBuf>,
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

// RiskLevel/Action types live in sentry module now.

#[derive(Serialize, Debug)]
struct IngestResponse {
    digest: DigestInfo,
    truncated: bool,
    policy: PolicyInfo,

    /// Length of the original decoded input (before any normalization).
    original_length_chars: usize,
    /// Length of the model-facing text (after normalization, before truncation).
    model_length_chars: usize,

    tools_allowed: bool,
    risk_level: sentry::RiskLevel,
    action: sentry::Action,

    fenced_content: String,
    reasons: Vec<String>,
    detected_patterns: Vec<String>,
}

fn fence_external(s: &str) -> String {
    format!("```external\n{}\n```", s)
}

fn apply_head_tail(policy: &state::Policy, text: &str) -> (String, bool) {
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

#[cfg(unix)]
fn username_from_uid(uid: libc::uid_t) -> anyhow::Result<String> {
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    let mut buf = vec![0u8; 1024];

    loop {
        let err = unsafe {
            libc::getpwuid_r(
                uid,
                &mut pwd,
                buf.as_mut_ptr() as *mut libc::c_char,
                buf.len(),
                &mut result,
            )
        };
        if err == 0 {
            if result.is_null() {
                anyhow::bail!("no passwd entry for uid {}", uid);
            }
            let name = unsafe { std::ffi::CStr::from_ptr(pwd.pw_name) }
                .to_string_lossy()
                .into_owned();
            return Ok(name);
        }
        if err == libc::ERANGE {
            buf.resize(buf.len() * 2, 0);
            continue;
        }
        anyhow::bail!(
            "getpwuid_r failed for uid {}: {}",
            uid,
            std::io::Error::from_raw_os_error(err)
        );
    }
}

#[cfg(unix)]
fn groupname_from_gid(gid: libc::gid_t) -> anyhow::Result<String> {
    let mut grp: libc::group = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::group = std::ptr::null_mut();
    let mut buf = vec![0u8; 1024];

    loop {
        let err = unsafe {
            libc::getgrgid_r(
                gid,
                &mut grp,
                buf.as_mut_ptr() as *mut libc::c_char,
                buf.len(),
                &mut result,
            )
        };
        if err == 0 {
            if result.is_null() {
                anyhow::bail!("no group entry for gid {}", gid);
            }
            let name = unsafe { std::ffi::CStr::from_ptr(grp.gr_name) }
                .to_string_lossy()
                .into_owned();
            return Ok(name);
        }
        if err == libc::ERANGE {
            buf.resize(buf.len() * 2, 0);
            continue;
        }
        anyhow::bail!(
            "getgrgid_r failed for gid {}: {}",
            gid,
            std::io::Error::from_raw_os_error(err)
        );
    }
}

async fn ingest_source(
    State(state): State<Arc<state::AppState>>,
    headers: HeaderMap,
    Json(req): Json<IngestRequest>,
) -> impl IntoResponse {
    // Multi-policy selection (v0.1): validate policy selection early.
    // Unknown policy -> 400 (fail loud).
    let policy_name = routes::policy_name_from_headers(&headers);
    if state.policies.require(&policy_name).is_err() {
        let mut names = state.policies.list();
        names.sort();
        return introspection::json_error(
            StatusCode::BAD_REQUEST,
            "unknown policy",
            serde_json::json!({"requested": policy_name, "available": names}),
        )
        .into_response();
    }

    // v0.1 behavior:
    // - Accept text or base64 bytes
    // - If bytes, decode and best-effort treat as UTF-8 (PDF extraction to be added)
    // - Apply deterministic truncation
    // - Return fenced content
    // - Default allow tools (real sentry model calls come later)

    let IngestRequest {
        source_id,
        source_type,
        content_type,
        url,
        title,
        turn_id,
        text,
        bytes_b64,
    } = req;

    // Basic DoS protection: cap base64 payload size before decoding.
    // (There is also an HTTP body limit at the router layer.)
    const MAX_BYTES_B64_CHARS: usize = 1_500_000; // ~1.1MB decoded

    let mut raw = None;

    if let Some(t) = text {
        raw = Some(t);
    } else if let Some(b64) = bytes_b64 {
        if b64.len() > MAX_BYTES_B64_CHARS {
            return (StatusCode::PAYLOAD_TOO_LARGE, "bytes_b64 too large").into_response();
        }
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

    // Normalization pipeline: keep `raw` for audit/digest, but generate separate model-facing text.
    let model_text = raw.clone();

    let original_length_chars = raw.chars().count();
    let model_length_chars = model_text.chars().count();

    let (trunc_text, truncated) = apply_head_tail(&state.policy, &model_text);

    // v0.2: run sentry enforcement.
    let policy_name = routes::policy_name_from_headers(&headers);
    let policy = match state.policies.require(&policy_name) {
        Ok(p) => p,
        Err(_) => {
            let mut names = state.policies.list();
            names.sort();
            return introspection::json_error(
                StatusCode::BAD_REQUEST,
                "unknown policy",
                serde_json::json!({"requested": policy_name, "available": names}),
            )
            .into_response();
        }
    };

    // Sentry mode:
    // - live (default): call configured L1/L2 models
    // - stub: skip model calls and fail safely (tools_allowed=false) while still returning fenced content
    let mode = std::env::var("ACIP_SENTRY_MODE").unwrap_or_else(|_| "live".to_string());
    if mode.trim().eq_ignore_ascii_case("stub") {
        let mut d = sentry::Decision::fail_closed(
            fence_external(&trunc_text),
            vec!["sentry disabled (ACIP_SENTRY_MODE=stub)".to_string()],
        );
        // In stub mode we still allow content to be appended, but never allow tools.
        d.risk_level = sentry::RiskLevel::Medium;
        d.action = sentry::Action::Allow;
        let resp = IngestResponse {
            digest: DigestInfo {
                sha256: sha.clone(),
                length: original_length_chars,
            },
            truncated,
            policy: PolicyInfo {
                head: state.policy.head,
                tail: state.policy.tail,
                full_if_lte: state.policy.full_if_lte,
            },
            original_length_chars,
            model_length_chars,
            tools_allowed: d.tools_allowed,
            risk_level: d.risk_level,
            action: d.action,
            fenced_content: d.fenced_content,
            reasons: d.reasons,
            detected_patterns: d.detected_patterns,
        };

        return (StatusCode::OK, Json(resp)).into_response();
    }

    let http = state.http.clone();

    let l1: Box<dyn sentry::ModelClient> = match policy.l1.provider {
        model_policy::Provider::Gemini => Box::new(sentry::GeminiClient::new(
            http.clone(),
            state.secrets.clone(),
        )),
        model_policy::Provider::Anthropic => Box::new(sentry::AnthropicClient::new(
            http.clone(),
            state.secrets.clone(),
        )),
    };
    let l2: Box<dyn sentry::ModelClient> = match policy.l2.provider {
        model_policy::Provider::Gemini => Box::new(sentry::GeminiClient::new(
            http.clone(),
            state.secrets.clone(),
        )),
        model_policy::Provider::Anthropic => Box::new(sentry::AnthropicClient::new(
            http.clone(),
            state.secrets.clone(),
        )),
    };
    let engine = sentry::DecisionEngine::new(l1, l2);

    let source_meta = serde_json::json!({
        "source_id": source_id,
        "source_type": format!("{:?}", source_type),
        "content_type": content_type,
        "url": url,
        "title": title,
        "turn_id": turn_id,
        "digest_sha256": sha,
        "original_length_chars": original_length_chars,
        "model_length_chars": model_length_chars,
        "truncated": truncated,
    });

    let decision = engine
        .decide(
            &policy_name,
            &policy,
            &source_meta,
            &fence_external(&trunc_text),
            &headers,
        )
        .await;

    let resp = IngestResponse {
        digest: DigestInfo {
            sha256: sha.clone(),
            length: original_length_chars,
        },
        truncated,
        policy: PolicyInfo {
            head: state.policy.head,
            tail: state.policy.tail,
            full_if_lte: state.policy.full_if_lte,
        },
        original_length_chars,
        model_length_chars,
        tools_allowed: decision.tools_allowed,
        risk_level: decision.risk_level,
        action: decision.action,
        fenced_content: decision.fenced_content,
        reasons: decision.reasons,
        detected_patterns: decision.detected_patterns,
    };

    (StatusCode::OK, Json(resp)).into_response()
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    const DEFAULT_HOST: &str = "127.0.0.1";
    const DEFAULT_PORT: u16 = 18795;
    const DEFAULT_HEAD: usize = 4000;
    const DEFAULT_TAIL: usize = 4000;
    const DEFAULT_FULL_IF_LTE: usize = 9000;

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args = Args::parse();
    let config_path = args
        .config
        .unwrap_or_else(|| PathBuf::from("/etc/acip/config.toml"));
    let config = match config::Config::load(&config_path) {
        Ok(cfg) => Some(cfg),
        Err(e) => {
            if let Some(ioe) = e.downcast_ref::<std::io::Error>() {
                if ioe.kind() == std::io::ErrorKind::NotFound {
                    info!(
                        "config file not found at {}; continuing",
                        config_path.display()
                    );
                    None
                } else {
                    return Err(e);
                }
            } else {
                return Err(e);
            }
        }
    };

    let cfg_service = config.as_ref().and_then(|cfg| cfg.service.as_ref());
    let cfg_server = config.as_ref().and_then(|cfg| cfg.server.as_ref());
    let cfg_policy = config.as_ref().and_then(|cfg| cfg.policy.as_ref());
    let cfg_security = config.as_ref().and_then(|cfg| cfg.security.as_ref());

    let _ = cfg_service.and_then(|svc| svc.user.as_ref());
    let _ = cfg_service.and_then(|svc| svc.group.as_ref());
    let _ = cfg_policy.and_then(|policy| policy.policies_file.as_ref());

    let allow_insecure_loopback = cfg_security
        .and_then(|sec| sec.allow_insecure_loopback)
        .unwrap_or(true);
    let require_token_setting = cfg_security
        .and_then(|sec| sec.require_token)
        .unwrap_or(true);
    let token_env = cfg_security
        .and_then(|sec| sec.token_env.as_deref())
        .unwrap_or("ACIP_AUTH_TOKEN");

    let effective_host = if let Some(host) = args.host.clone() {
        host
    } else if let Some(host) = cfg_server.and_then(|server| server.host.clone()) {
        host
    } else {
        DEFAULT_HOST.to_string()
    };

    let ip: std::net::IpAddr = effective_host.parse()?;
    let token_required = (!ip.is_loopback() || !allow_insecure_loopback) && require_token_setting;

    let effective_port = if let Some(port) = args.port {
        port
    } else if let Some(port) = cfg_server.and_then(|server| server.port) {
        port
    } else {
        DEFAULT_PORT
    };

    let effective_head = if let Some(head) = args.head {
        head
    } else if let Some(head) = cfg_policy.and_then(|policy| policy.head) {
        head
    } else {
        DEFAULT_HEAD
    };

    let effective_tail = if let Some(tail) = args.tail {
        tail
    } else if let Some(tail) = cfg_policy.and_then(|policy| policy.tail) {
        tail
    } else {
        DEFAULT_TAIL
    };

    let effective_full_if_lte = if let Some(full_if_lte) = args.full_if_lte {
        full_if_lte
    } else if let Some(full_if_lte) = cfg_policy.and_then(|policy| policy.full_if_lte) {
        full_if_lte
    } else {
        DEFAULT_FULL_IF_LTE
    };

    if let Some(service) = cfg_service {
        let enforce_identity = service.enforce_identity.unwrap_or(true);
        if enforce_identity {
            #[cfg(unix)]
            {
                if service.user.is_some() || service.group.is_some() {
                    let euid = unsafe { libc::geteuid() };
                    let egid = unsafe { libc::getegid() };
                    let current_user = username_from_uid(euid)?;
                    let current_group = groupname_from_gid(egid)?;
                    if let Some(expected) = service.user.as_deref() {
                        if expected != current_user {
                            anyhow::bail!(
                                "service user mismatch: expected {}, running as {} (uid {})",
                                expected,
                                current_user,
                                euid
                            );
                        }
                    }
                    if let Some(expected) = service.group.as_deref() {
                        if expected != current_group {
                            anyhow::bail!(
                                "service group mismatch: expected {}, running as {} (gid {})",
                                expected,
                                current_group,
                                egid
                            );
                        }
                    }
                }
            }
        }
    }

    // Secrets: secrets file (optional) + env fallback.
    let secrets: Arc<dyn secrets::SecretStore> = if let Some(path) = &args.secrets_file {
        match secrets::EnvFileStore::load(path) {
            Ok(file_store) => Arc::new(secrets::CompositeStore::new(vec![
                Box::new(file_store),
                Box::new(secrets::EnvStore),
            ])),
            Err(e) => {
                // Fail closed: if a secrets file path is provided but unsafe/unreadable, refuse to start.
                return Err(e);
            }
        }
    } else {
        Arc::new(secrets::EnvStore)
    };

    let token_opt = if token_required {
        match secrets.get(token_env) {
            Some(token) if !token.trim().is_empty() => Some(token),
            _ => {
                anyhow::bail!(
                    "auth token required but missing or empty in secrets store ({})",
                    token_env
                );
            }
        }
    } else {
        None
    };
    if token_opt.is_some() {
        info!("auth token required");
    }

    let http = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(30))
        .build()?;

    // Policy store: load from policies.json when provided, otherwise fall back
    // to env-configured single 'default' policy.

    let effective_policies_file: Option<PathBuf> = args.policies_file.clone().or_else(|| {
        cfg_policy
            .and_then(|pol| pol.policies_file.as_ref())
            .map(PathBuf::from)
    });

    let policies = if let Some(policies_path) = &effective_policies_file {
        let pf = policy_store::PoliciesFile::load(policies_path)?;
        policy_store::PolicyStore::from_file(pf)
    } else {
        // Back-compat: derive the default policy from env.
        let mut mp = model_policy::PolicyConfig::default();

        if let Some(p) = secrets.get("ACIP_L1_PROVIDER") {
            if let Some(parsed) = model_policy::Provider::parse(&p) {
                mp.l1.provider = parsed;
            } else {
                warn!("Unknown ACIP_L1_PROVIDER={}; using default", p);
            }
        }
        if let Some(m) = secrets.get("ACIP_L1_MODEL") {
            mp.l1.model = m;
        }

        if let Some(p) = secrets.get("ACIP_L2_PROVIDER") {
            if let Some(parsed) = model_policy::Provider::parse(&p) {
                mp.l2.provider = parsed;
            } else {
                warn!("Unknown ACIP_L2_PROVIDER={}; using default", p);
            }
        }
        if let Some(m) = secrets.get("ACIP_L2_MODEL") {
            mp.l2.model = m;
        }

        info!(
            "model policy: L1={:?}/{}; L2={:?}/{}",
            mp.l1.provider, mp.l1.model, mp.l2.provider, mp.l2.model
        );

        policy_store::PolicyStore::default_from_env(
            mp.l1.provider.clone(),
            mp.l1.model.clone(),
            mp.l2.provider.clone(),
            mp.l2.model.clone(),
        )
    };

    // For v0.1 we don't *use* the provider keys yet, but we can warn early.
    if secrets.get("GEMINI_API_KEY").is_none() {
        warn!("GEMINI_API_KEY not set (ok for v0.1; required for Gemini L1 model calls)");
    }
    if secrets.get("ANTHROPIC_API_KEY").is_none() {
        warn!("ANTHROPIC_API_KEY not set (ok for v0.1; required for Anthropic L2 fallback)");
    }

    let state = Arc::new(state::AppState {
        policy: state::Policy {
            head: effective_head,
            tail: effective_tail,
            full_if_lte: effective_full_if_lte,
        },
        http,
        secrets,
        policies,
    });

    // Apply token auth and body size limits to protected routes.
    let extra_protected = Router::new().route("/v1/acip/ingest_source", post(ingest_source));
    let app = app::build_router(state, token_opt.clone(), extra_protected);

    let addr: SocketAddr = format!("{}:{}", effective_host, effective_port).parse()?;
    info!("listening on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
mod ingest_response_tests {
    use super::*;

    #[test]
    fn ingest_response_includes_original_and_model_lengths() {
        let resp = IngestResponse {
            digest: DigestInfo {
                sha256: "x".to_string(),
                length: 10,
            },
            truncated: false,
            policy: PolicyInfo {
                head: 1,
                tail: 1,
                full_if_lte: 3,
            },
            original_length_chars: 10,
            model_length_chars: 9,
            tools_allowed: false,
            risk_level: sentry::RiskLevel::Low,
            action: sentry::Action::Allow,
            fenced_content: "```external\nhello\n```".to_string(),
            reasons: vec![],
            detected_patterns: vec![],
        };

        let v = serde_json::to_value(resp).unwrap();
        assert!(v.get("original_length_chars").is_some());
        assert!(v.get("model_length_chars").is_some());
    }
}
