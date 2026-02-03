use async_trait::async_trait;
use axum::http::HeaderMap;
use acip_sidecar::model_policy::{PolicyConfig, Provider};
use acip_sidecar::sentry::{
    parse_and_validate_decision, Action, DecisionEngine, ModelClient, RiskLevel,
};
use serial_test::serial;
use serde_json::json;

enum FakeOut {
    Ok(String),
    Err(String),
}

struct FakeClient {
    out: FakeOut,
}

struct EnvGuard {
    key: String,
    prev: Option<String>,
}

impl EnvGuard {
    fn set(key: &str, value: Option<&str>) -> Self {
        let prev = std::env::var(key).ok();
        match value {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
        Self {
            key: key.to_string(),
            prev,
        }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        match self.prev.as_deref() {
            Some(v) => std::env::set_var(&self.key, v),
            None => std::env::remove_var(&self.key),
        }
    }
}

#[async_trait]
impl ModelClient for FakeClient {
    async fn generate(
        &self,
        _model: &str,
        _prompt: &str,
        _headers: &HeaderMap,
    ) -> anyhow::Result<String> {
        match &self.out {
            FakeOut::Ok(s) => Ok(s.clone()),
            FakeOut::Err(e) => Err(anyhow::anyhow!(e.clone())),
        }
    }
}

fn policy() -> PolicyConfig {
    PolicyConfig {
        l1: acip_sidecar::model_policy::ModelRef {
            provider: Provider::Gemini,
            model: "gemini-2.0-flash".to_string(),
        },
        l2: acip_sidecar::model_policy::ModelRef {
            provider: Provider::Anthropic,
            model: "claude-3-5-haiku-latest".to_string(),
        },
    }
}

fn valid_decision_json() -> String {
    json!({
        "tools_allowed": true,
        "risk_level": "low",
        "action": "allow",
        "fenced_content": "```external\nhello\n```",
        "reasons": ["ok"],
        "detected_patterns": []
    })
    .to_string()
}

#[tokio::test]
async fn l1_valid_decision_used() {
    let good = valid_decision_json();

    let engine = DecisionEngine::new(
        Box::new(FakeClient {
            out: FakeOut::Ok(good),
        }),
        Box::new(FakeClient {
            out: FakeOut::Ok("{}".into()),
        }),
    );

    let d = engine
        .decide(
            "default",
            &policy(),
            &json!({"source_id":"x"}),
            "```external\nhello\n```",
            &HeaderMap::new(),
        )
        .await;

    assert!(d.tools_allowed);
    assert!(matches!(d.risk_level, RiskLevel::Low));
    assert!(matches!(d.action, Action::Allow));
}

#[tokio::test]
async fn l1_invalid_falls_back_to_l2() {
    let l1 = "not json".to_string();
    let l2 = json!({
        "tools_allowed": false,
        "risk_level": "high",
        "action": "needs_review",
        "fenced_content": "```external\nX\n```",
        "reasons": ["nope"],
        "detected_patterns": ["pii?"]
    })
    .to_string();

    let engine = DecisionEngine::new(
        Box::new(FakeClient {
            out: FakeOut::Ok(l1),
        }),
        Box::new(FakeClient {
            out: FakeOut::Ok(l2),
        }),
    );

    let d = engine
        .decide(
            "default",
            &policy(),
            &json!({"source_id":"x"}),
            "```external\nX\n```",
            &HeaderMap::new(),
        )
        .await;

    assert!(!d.tools_allowed);
    assert!(matches!(d.action, Action::NeedsReview));
}

#[tokio::test]
async fn double_failure_fails_closed() {
    let engine = DecisionEngine::new(
        Box::new(FakeClient {
            out: FakeOut::Err("l1 down".into()),
        }),
        Box::new(FakeClient {
            out: FakeOut::Err("l2 down".into()),
        }),
    );

    let fenced = "```external\nZ\n```";
    let d = engine
        .decide(
            "default",
            &policy(),
            &json!({"source_id":"x"}),
            fenced,
            &HeaderMap::new(),
        )
        .await;

    assert!(!d.tools_allowed);
    assert!(matches!(d.risk_level, RiskLevel::High));
    assert!(matches!(d.action, Action::NeedsReview));
    assert_eq!(d.fenced_content, fenced);
}

#[test]
fn parse_validates_against_schema() {
    // Missing required keys should fail schema validation.
    let bad = "{}";
    assert!(parse_and_validate_decision(bad).is_err());

    let good = valid_decision_json();
    let d = parse_and_validate_decision(&good).unwrap();
    assert!(d.tools_allowed);
}

#[test]
#[serial]
fn strict_accepts_pure_json_with_whitespace() {
    let _guard = EnvGuard::set("ACIP_SENTRY_JSON_STRICT", Some("1"));
    let good = valid_decision_json();
    let wrapped = format!("\n  {good}  \n");
    assert!(parse_and_validate_decision(&wrapped).is_ok());
}

#[test]
#[serial]
fn strict_rejects_prefix_suffix_text() {
    let _guard = EnvGuard::set("ACIP_SENTRY_JSON_STRICT", Some("1"));
    let good = valid_decision_json();
    let wrapped = format!("prefix {good} suffix");
    assert!(parse_and_validate_decision(&wrapped).is_err());
}

#[test]
#[serial]
fn default_tolerant_accepts_prefix_suffix() {
    let _guard = EnvGuard::set("ACIP_SENTRY_JSON_STRICT", None);
    let good = valid_decision_json();
    let wrapped = format!("prefix {good} suffix");
    let d = parse_and_validate_decision(&wrapped).unwrap();
    assert!(d.tools_allowed);
}
