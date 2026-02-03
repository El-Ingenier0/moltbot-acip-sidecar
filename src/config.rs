use anyhow::Result;
use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub service: Option<ServiceConfig>,
    pub server: Option<ServerConfig>,
    pub policy: Option<PolicyConfig>,
    pub security: Option<SecurityConfig>,
    pub normalize: Option<NormalizeConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServiceConfig {
    pub user: Option<String>,
    pub group: Option<String>,
    pub enforce_identity: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub host: Option<String>,
    pub port: Option<u16>,
    /// Optional Unix domain socket path (Linux/macOS). If set, the server binds this socket
    /// instead of TCP host:port.
    pub unix_socket: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PolicyConfig {
    pub policies_file: Option<String>,
    pub head: Option<usize>,
    pub tail: Option<usize>,
    pub full_if_lte: Option<usize>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SecurityConfig {
    pub allow_insecure_loopback: Option<bool>,
    pub require_token: Option<bool>,
    pub token_env: Option<String>,
}

pub const DEFAULT_NORMALIZE_MAX_INPUT_CHARS: usize = 400_000;
pub const DEFAULT_NORMALIZE_WINDOW_HEAD_CHARS: usize = 200_000;
pub const DEFAULT_NORMALIZE_WINDOW_TAIL_CHARS: usize = 200_000;

pub const DEFAULT_NORMALIZE_ADVERSARIAL_THRESHOLD: u8 = 3;
pub const DEFAULT_NORMALIZE_ADVERSARIAL_TIGHTEN_FACTOR: f64 = 0.5;

fn default_normalize_max_input_chars() -> usize {
    DEFAULT_NORMALIZE_MAX_INPUT_CHARS
}

fn default_normalize_window_head_chars() -> usize {
    DEFAULT_NORMALIZE_WINDOW_HEAD_CHARS
}

fn default_normalize_window_tail_chars() -> usize {
    DEFAULT_NORMALIZE_WINDOW_TAIL_CHARS
}

fn default_normalize_adversarial_threshold() -> u8 {
    DEFAULT_NORMALIZE_ADVERSARIAL_THRESHOLD
}

fn default_normalize_adversarial_tighten_factor() -> f64 {
    DEFAULT_NORMALIZE_ADVERSARIAL_TIGHTEN_FACTOR
}

#[derive(Debug, Clone, Deserialize)]
pub struct NormalizeConfig {
    #[serde(default = "default_normalize_max_input_chars")]
    pub max_input_chars: usize,
    #[serde(default = "default_normalize_window_head_chars")]
    pub window_head_chars: usize,
    #[serde(default = "default_normalize_window_tail_chars")]
    pub window_tail_chars: usize,

    /// Heuristic threshold for treating markup as adversarial.
    #[serde(default = "default_normalize_adversarial_threshold")]
    pub adversarial_threshold: u8,

    /// Factor to tighten caps when adversarial markup is detected.
    #[serde(default = "default_normalize_adversarial_tighten_factor")]
    pub adversarial_tighten_factor: f64,
}

impl Config {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let raw = std::fs::read_to_string(path.as_ref())?;
        let cfg: Self = toml::from_str(&raw)?;
        Ok(cfg)
    }
}
