use async_trait::async_trait;
use axum::http::HeaderMap;
use acip_sidecar::model_policy::{PolicyConfig, Provider};
use acip_sidecar::sentry::{
    parse_and_validate_decision, Action, DecisionEngine, ModelClient, RiskLevel,
};
use serde_json::json;

enum FakeOut {
    Ok(String),
    Err(String),
}

struct FakeClient {
    out: FakeOut,
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

#[tokio::test]
async fn l1_valid_decision_used() {
    let good = json!({
        "tools_allowed": true,
        "risk_level": "low",
        "action": "allow",
        "fenced_content": "```external\nhello\n```",
        "reasons": ["ok"],
        "detected_patterns": []
    })
    .to_string();

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

    let good = json!({
        "tools_allowed": true,
        "risk_level": "low",
        "action": "allow",
        "fenced_content": "```external\nhello\n```",
        "reasons": [],
        "detected_patterns": []
    })
    .to_string();

    let d = parse_and_validate_decision(&good).unwrap();
    assert!(d.tools_allowed);
}
