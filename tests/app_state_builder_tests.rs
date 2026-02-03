use acip_sidecar::{app_state_builder, policy_store, reputation, secrets, state};
use std::sync::Arc;

#[test]
fn build_http_client_works() {
    let _ = app_state_builder::build_http_client().unwrap();
}

#[test]
fn build_app_state_wires_fields() {
    let http = app_state_builder::build_http_client().unwrap();

    let mut policies = std::collections::BTreeMap::new();
    policies.insert(
        "default".to_string(),
        acip_sidecar::model_policy::PolicyConfig::default(),
    );

    let st = app_state_builder::build_app_state(
        state::Policy {
            head: 1,
            tail: 2,
            full_if_lte: 3,
        },
        state::NormalizeSettings::from_config(None),
        http,
        Arc::new(secrets::EnvStore),
        policy_store::PolicyStore::from_file(policy_store::PoliciesFile { policies }),
        Arc::new(reputation::InMemoryReputationStore::new()),
    );

    assert_eq!(st.policy.head, 1);
    assert_eq!(st.policy.tail, 2);
    assert_eq!(st.policy.full_if_lte, 3);
    assert!(st.policies.require("default").is_ok());
}
