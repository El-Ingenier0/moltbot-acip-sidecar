use crate::{config, policy_store::PolicyStore, secrets};
use reqwest::Client;
use std::sync::Arc;

#[derive(Clone, Debug)]
pub struct Policy {
    pub head: usize,
    pub tail: usize,
    pub full_if_lte: usize,
}

#[derive(Clone, Debug)]
pub struct NormalizeSettings {
    pub max_input_chars: usize,
    pub window_head_chars: usize,
    pub window_tail_chars: usize,
}

impl NormalizeSettings {
    pub fn from_config(cfg: Option<&config::NormalizeConfig>) -> Self {
        let mut max_input_chars = cfg
            .map(|c| c.max_input_chars)
            .unwrap_or(config::DEFAULT_NORMALIZE_MAX_INPUT_CHARS);
        let mut window_head_chars = cfg
            .map(|c| c.window_head_chars)
            .unwrap_or(config::DEFAULT_NORMALIZE_WINDOW_HEAD_CHARS);
        let mut window_tail_chars = cfg
            .map(|c| c.window_tail_chars)
            .unwrap_or(config::DEFAULT_NORMALIZE_WINDOW_TAIL_CHARS);

        if let Some(v) = env_usize("ACIP_NORMALIZE_MAX_INPUT_CHARS") {
            max_input_chars = v;
        }
        if let Some(v) = env_usize("ACIP_NORMALIZE_WINDOW_HEAD_CHARS") {
            window_head_chars = v;
        }
        if let Some(v) = env_usize("ACIP_NORMALIZE_WINDOW_TAIL_CHARS") {
            window_tail_chars = v;
        }

        Self {
            max_input_chars,
            window_head_chars,
            window_tail_chars,
        }
    }
}

#[derive(Clone)]
pub struct AppState {
    pub policy: Policy,
    pub normalize: NormalizeSettings,
    pub http: Client,
    pub secrets: Arc<dyn secrets::SecretStore>,
    pub policies: PolicyStore,
    pub reputation: Arc<dyn crate::reputation::ReputationStore>,
}

fn env_usize(key: &str) -> Option<usize> {
    std::env::var(key)
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
}
