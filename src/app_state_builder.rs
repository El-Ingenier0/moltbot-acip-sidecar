use crate::{secrets, state};
use anyhow::Result;
use reqwest::Client;
use std::{sync::Arc, time::Duration};

/// Build a reqwest client with sane defaults for ACIP.
pub fn build_http_client() -> Result<Client> {
    Ok(Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(30))
        .build()?)
}

/// Build the shared AppState.
///
/// This is a small helper to keep `main.rs` focused on config/CLI parsing and server wiring.
pub fn build_app_state(
    policy: state::Policy,
    normalize: state::NormalizeSettings,
    http: Client,
    secrets: Arc<dyn secrets::SecretStore>,
    policies: crate::policy_store::PolicyStore,
    reputation: Arc<dyn crate::reputation::ReputationStore>,
) -> Arc<state::AppState> {
    Arc::new(state::AppState {
        policy,
        normalize,
        http,
        secrets,
        policies,
        reputation,
    })
}
