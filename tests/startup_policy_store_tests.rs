use acip_sidecar::startup;
use std::sync::Arc;

#[test]
fn build_policy_store_uses_file_when_provided() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("policies.json");

    std::fs::write(
        &path,
        r#"{
  "policies": {
    "default": {
      "l1": {"provider":"gemini","model":"gemini-1.5-flash"},
      "l2": {"provider":"anthropic","model":"claude-3-5-sonnet"}
    },
    "strict": {
      "l1": {"provider":"gemini","model":"gemini-1.5-flash"},
      "l2": {"provider":"anthropic","model":"claude-3-5-sonnet"}
    }
  }
}
"#,
    )
    .unwrap();

    let secrets = Arc::new(acip_sidecar::secrets::EnvStore)
        as Arc<dyn acip_sidecar::secrets::SecretStore>;

    let store = startup::build_policy_store(&secrets, Some(path)).unwrap();
    assert!(store.get("default").is_some());
    assert!(store.get("strict").is_some());
}

#[test]
fn build_policy_store_falls_back_to_env_defaults() {
    // Ensure env-derived values are used.
    std::env::set_var("ACIP_L1_PROVIDER", "gemini");
    std::env::set_var("ACIP_L1_MODEL", "gemini-1.5-flash");
    std::env::set_var("ACIP_L2_PROVIDER", "anthropic");
    std::env::set_var("ACIP_L2_MODEL", "claude-3-5-sonnet");

    let secrets = Arc::new(acip_sidecar::secrets::EnvStore)
        as Arc<dyn acip_sidecar::secrets::SecretStore>;

    let store = startup::build_policy_store(&secrets, None).unwrap();
    let p = store.get("default").unwrap();

    assert!(matches!(
        p.l1.provider,
        acip_sidecar::model_policy::Provider::Gemini
    ));
    assert_eq!(p.l1.model, "gemini-1.5-flash");
    assert!(matches!(
        p.l2.provider,
        acip_sidecar::model_policy::Provider::Anthropic
    ));
    assert_eq!(p.l2.model, "claude-3-5-sonnet");
}
