use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Provider {
    Gemini,
    Anthropic,
}

impl Provider {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_lowercase().as_str() {
            "gemini" | "google" => Some(Self::Gemini),
            "anthropic" | "claude" => Some(Self::Anthropic),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelRef {
    pub provider: Provider,
    pub model: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    /// L1: cheap-first model
    pub l1: ModelRef,
    /// L2: fallback model
    pub l2: ModelRef,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            l1: ModelRef {
                provider: Provider::Gemini,
                model: "gemini-2.0-flash".to_string(),
            },
            l2: ModelRef {
                provider: Provider::Anthropic,
                model: "claude-3-5-haiku-latest".to_string(),
            },
        }
    }
}
