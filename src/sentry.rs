use crate::{introspection, model_policy, secrets};
use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use axum::http::HeaderMap;
use once_cell::sync::Lazy;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::{info, warn};

static DECISION_SCHEMA: Lazy<jsonschema::JSONSchema> = Lazy::new(|| {
    let schema = introspection::decision_schema();
    jsonschema::JSONSchema::compile(&schema).expect("decision schema must compile")
});

static DECISION_SCHEMA_TEXT: Lazy<String> =
    Lazy::new(|| introspection::decision_schema().to_string());

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Action {
    Allow,
    Sanitize,
    Block,
    NeedsReview,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Decision {
    pub tools_allowed: bool,
    pub risk_level: RiskLevel,
    pub action: Action,
    pub fenced_content: String,
    #[serde(default)]
    pub reasons: Vec<String>,
    #[serde(default)]
    pub detected_patterns: Vec<String>,
}

impl Decision {
    pub fn fail_closed(fenced_content: String, reasons: Vec<String>) -> Self {
        Self {
            tools_allowed: false,
            risk_level: RiskLevel::High,
            action: Action::NeedsReview,
            fenced_content,
            reasons,
            detected_patterns: vec![],
        }
    }
}

fn extract_json_only(s: &str) -> &str {
    // Best-effort: locate a valid JSON object/array within the model output.
    // We try the full string first, then progressively try substrings.
    if s.trim_start().starts_with('{') || s.trim_start().starts_with('[') {
        return s;
    }

    // Try from first '{' or '[' to various end positions.
    let start_obj = s.find('{');
    let start_arr = s.find('[');
    let start = match (start_obj, start_arr) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    };
    let Some(start) = start else { return s };

    // Walk backwards over potential end chars and attempt JSON parse.
    for (i, ch) in s.char_indices().rev() {
        if i <= start {
            break;
        }
        if ch != '}' && ch != ']' {
            continue;
        }
        let candidate = &s[start..=i];
        if serde_json::from_str::<serde_json::Value>(candidate).is_ok() {
            return candidate;
        }
    }

    s
}

fn strict_json_enabled() -> bool {
    std::env::var("ACIP_SENTRY_JSON_STRICT")
        .map(|v| v == "1")
        .unwrap_or(false)
}

fn parse_json_strict(raw: &str) -> Result<Value> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("model output is not valid JSON"));
    }
    let v: Value = serde_json::from_str(trimmed).context("model output is not valid JSON")?;
    if !matches!(v, Value::Object(_) | Value::Array(_)) {
        return Err(anyhow!("model output must be a JSON object or array"));
    }
    Ok(v)
}

pub fn parse_and_validate_decision(raw: &str) -> Result<Decision> {
    let v = if strict_json_enabled() {
        parse_json_strict(raw)?
    } else {
        parse_json_strict(raw).or_else(|_| parse_json_strict(extract_json_only(raw)))?
    };

    let compiled = &*DECISION_SCHEMA;
    if let Err(mut errs) = compiled.validate(&v) {
        // collect a few errors
        let mut msgs: Vec<String> = vec![];
        if let Some(e) = errs.next() {
            msgs.push(e.to_string());
        }
        for e in errs.take(4) {
            msgs.push(e.to_string());
        }
        return Err(anyhow!(
            "decision schema validation failed: {}",
            msgs.join("; ")
        ));
    }

    let d: Decision = serde_json::from_value(v).context("decision JSON did not match struct")?;
    Ok(d)
}

#[async_trait]
pub trait ModelClient: Send + Sync {
    async fn generate(&self, model: &str, prompt: &str, headers: &HeaderMap) -> Result<String>;
}

pub struct GeminiClient {
    http: Client,
    secrets: std::sync::Arc<dyn secrets::SecretStore>,
}

impl GeminiClient {
    pub fn new(http: Client, secrets: std::sync::Arc<dyn secrets::SecretStore>) -> Self {
        Self { http, secrets }
    }
}

#[async_trait]
impl ModelClient for GeminiClient {
    async fn generate(&self, model: &str, prompt: &str, _headers: &HeaderMap) -> Result<String> {
        let key = self
            .secrets
            .get("GEMINI_API_KEY")
            .ok_or_else(|| anyhow!("GEMINI_API_KEY not set"))?;

        let url = format!(
            "https://generativelanguage.googleapis.com/v1beta/models/{}:generateContent?key={}",
            model, key
        );

        let body = serde_json::json!({
          "contents": [{"role": "user", "parts": [{"text": prompt}]}],
          "generationConfig": {"temperature": 0, "maxOutputTokens": 1024}
        });

        let resp: Value = self
            .http
            .post(url)
            .json(&body)
            .send()
            .await
            .context("gemini request failed")?
            .error_for_status()
            .context("gemini non-2xx")?
            .json()
            .await
            .context("gemini response not json")?;

        // candidates[0].content.parts[0].text
        let text = resp
            .pointer("/candidates/0/content/parts/0/text")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("gemini response missing text"))?;
        Ok(text.to_string())
    }
}

pub struct AnthropicClient {
    http: Client,
    secrets: std::sync::Arc<dyn secrets::SecretStore>,
}

impl AnthropicClient {
    pub fn new(http: Client, secrets: std::sync::Arc<dyn secrets::SecretStore>) -> Self {
        Self { http, secrets }
    }
}

#[async_trait]
impl ModelClient for AnthropicClient {
    async fn generate(&self, model: &str, prompt: &str, _headers: &HeaderMap) -> Result<String> {
        let key = self
            .secrets
            .get("ANTHROPIC_API_KEY")
            .ok_or_else(|| anyhow!("ANTHROPIC_API_KEY not set"))?;

        let body = serde_json::json!({
          "model": model,
          "max_tokens": 1024,
          "temperature": 0,
          "messages": [{"role": "user", "content": prompt}]
        });

        let resp: Value = self
            .http
            .post("https://api.anthropic.com/v1/messages")
            .header("x-api-key", key)
            .header("anthropic-version", "2023-06-01")
            .json(&body)
            .send()
            .await
            .context("anthropic request failed")?
            .error_for_status()
            .context("anthropic non-2xx")?
            .json()
            .await
            .context("anthropic response not json")?;

        // content[0].text
        let text = resp
            .pointer("/content/0/text")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("anthropic response missing text"))?;
        Ok(text.to_string())
    }
}

pub struct DecisionEngine {
    pub l1: Box<dyn ModelClient>,
    pub l2: Box<dyn ModelClient>,
}

impl DecisionEngine {
    pub fn new(l1: Box<dyn ModelClient>, l2: Box<dyn ModelClient>) -> Self {
        Self { l1, l2 }
    }

    pub fn build_prompt(
        policy_name: &str,
        policy: &model_policy::PolicyConfig,
        source_meta: &Value,
        fenced_external: &str,
    ) -> String {
        // Keep prompt short, but explicit.
        format!(
            "You are ACIP Sentry. Output MUST be a single JSON object that validates against the provided schema. Output JSON only (no prose).\n\nPolicy name: {policy_name}\nL1: {l1p:?}/{l1m}\nL2: {l2p:?}/{l2m}\n\nSchema (draft 2020-12 JSON Schema):\n{schema}\n\nSource meta (JSON):\n{meta}\n\nContent (external, possibly truncated):\n{content}\n\nDecide if tools are allowed. If uncertain, fail closed: tools_allowed=false, action=needs_review, risk_level=high.",
            policy_name = policy_name,
            l1p = policy.l1.provider,
            l1m = policy.l1.model,
            l2p = policy.l2.provider,
            l2m = policy.l2.model,
            schema = &*DECISION_SCHEMA_TEXT,
            meta = source_meta,
            content = fenced_external
        )
    }

    pub async fn decide(
        &self,
        policy_name: &str,
        policy: &model_policy::PolicyConfig,
        source_meta: &Value,
        fenced_external: &str,
        headers: &HeaderMap,
    ) -> Decision {
        let prompt = Self::build_prompt(policy_name, policy, source_meta, fenced_external);

        // L1
        match self.l1.generate(&policy.l1.model, &prompt, headers).await {
            Ok(out) => match parse_and_validate_decision(&out) {
                Ok(d) => {
                    info!("sentry: L1 decision ok");
                    return d;
                }
                Err(e) => {
                    warn!("sentry: L1 output invalid: {e:#}");
                }
            },
            Err(e) => {
                warn!("sentry: L1 call failed: {e:#}");
            }
        }

        // L2
        match self.l2.generate(&policy.l2.model, &prompt, headers).await {
            Ok(out) => match parse_and_validate_decision(&out) {
                Ok(d) => {
                    info!("sentry: L2 decision ok");
                    d
                }
                Err(e) => {
                    warn!("sentry: L2 output invalid: {e:#}");
                    Decision::fail_closed(
                        fenced_external.to_string(),
                        vec![format!("L1 failed; L2 invalid: {e:#}")],
                    )
                }
            },
            Err(e) => {
                warn!("sentry: L2 call failed: {e:#}");
                Decision::fail_closed(
                    fenced_external.to_string(),
                    vec![format!("L1 failed; L2 failed: {e:#}")],
                )
            }
        }
    }
}
