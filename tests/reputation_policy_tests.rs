use acip_sidecar::reputation::ReputationRecord;
use acip_sidecar::reputation_policy::{apply_reputation, ReputationThresholds};
use acip_sidecar::sentry::{Action, Decision, RiskLevel};

fn base_decision(tools_allowed: bool) -> Decision {
    Decision {
        tools_allowed,
        risk_level: RiskLevel::Low,
        action: Action::Allow,
        fenced_content: "```external\nX\n```".to_string(),
        reasons: vec![],
        detected_patterns: vec![],
    }
}

#[test]
fn reputation_bumps_risk() {
    let rec = ReputationRecord {
        key: "host:evil.com".to_string(),
        risk_score: 25,
        suspected_attack_count: 1,
        last_seen_unix: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        ..Default::default()
    };

    let t = ReputationThresholds {
        medium_score: 20,
        high_score: 50,
        bad_actor_score: 150,
        half_life_base_days: 2.0,
        half_life_k: 0.5,
    };

    let out = apply_reputation(base_decision(false), false, &[rec], &t);
    assert!(matches!(
        out.risk_level,
        RiskLevel::Medium | RiskLevel::High
    ));
}

#[test]
fn explicit_tool_auth_overrides_until_bad_actor_cutoff() {
    let rec = ReputationRecord {
        key: "host:sketchy.com".to_string(),
        risk_score: 80,
        suspected_attack_count: 2,
        last_seen_unix: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        ..Default::default()
    };

    let t = ReputationThresholds {
        medium_score: 20,
        high_score: 50,
        bad_actor_score: 150,
        half_life_base_days: 2.0,
        half_life_k: 0.5,
    };

    // Model wants tools, caller authorizes tools.
    let out = apply_reputation(base_decision(true), true, &[rec], &t);
    assert!(out.tools_allowed);
    assert!(matches!(out.risk_level, RiskLevel::High));
    assert!(matches!(out.action, Action::NeedsReview));
}

#[test]
fn bad_actor_cutoff_always_caps_tools() {
    let rec = ReputationRecord {
        key: "host:evil.com".to_string(),
        risk_score: 200,
        suspected_attack_count: 5,
        last_seen_unix: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        ..Default::default()
    };

    let t = ReputationThresholds {
        medium_score: 20,
        high_score: 50,
        bad_actor_score: 150,
        half_life_base_days: 2.0,
        half_life_k: 0.5,
    };

    let out = apply_reputation(base_decision(true), true, &[rec], &t);
    assert!(!out.tools_allowed);
    assert!(matches!(out.risk_level, RiskLevel::High));
    assert!(matches!(out.action, Action::NeedsReview));
}
