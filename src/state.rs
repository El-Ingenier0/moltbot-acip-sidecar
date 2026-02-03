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

    pub adversarial_threshold: u8,
    pub adversarial_tighten_factor: f64,
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
        let mut adversarial_threshold = cfg
            .map(|c| c.adversarial_threshold)
            .unwrap_or(config::DEFAULT_NORMALIZE_ADVERSARIAL_THRESHOLD);
        let mut adversarial_tighten_factor = cfg
            .map(|c| c.adversarial_tighten_factor)
            .unwrap_or(config::DEFAULT_NORMALIZE_ADVERSARIAL_TIGHTEN_FACTOR);

        if let Some(v) = env_usize("ACIP_NORMALIZE_MAX_INPUT_CHARS") {
            max_input_chars = v;
        }
        if let Some(v) = env_usize("ACIP_NORMALIZE_WINDOW_HEAD_CHARS") {
            window_head_chars = v;
        }
        if let Some(v) = env_usize("ACIP_NORMALIZE_WINDOW_TAIL_CHARS") {
            window_tail_chars = v;
        }

        if let Some(v) = env_u8("ACIP_NORMALIZE_ADVERSARIAL_THRESHOLD") {
            adversarial_threshold = v;
        }
        if let Some(v) = env_f64("ACIP_NORMALIZE_ADVERSARIAL_TIGHTEN_FACTOR") {
            adversarial_tighten_factor = v;
        }

        // Defensive clamp for factor.
        if !(0.0..=1.0).contains(&adversarial_tighten_factor) {
            adversarial_tighten_factor = config::DEFAULT_NORMALIZE_ADVERSARIAL_TIGHTEN_FACTOR;
        }

        Self {
            max_input_chars,
            window_head_chars,
            window_tail_chars,
            adversarial_threshold,
            adversarial_tighten_factor,
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

fn env_u8(key: &str) -> Option<u8> {
    std::env::var(key)
        .ok()
        .and_then(|v| v.trim().parse::<u8>().ok())
}

fn env_f64(key: &str) -> Option<f64> {
    std::env::var(key)
        .ok()
        .and_then(|v| v.trim().parse::<f64>().ok())
}
