use crate::model_policy::{PolicyConfig, Provider};
use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fs, path::Path};

/// On-disk policy configuration.
///
/// Policies are intentionally *non-secret*. Secrets live in `/etc/acip/secrets.env`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoliciesFile {
    pub policies: BTreeMap<String, PolicyConfig>,
}

impl PoliciesFile {
    pub fn load(path: &Path) -> Result<Self> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("failed reading policies file: {}", path.display()))?;
        let pf: PoliciesFile = serde_json::from_str(&raw)
            .with_context(|| format!("invalid JSON in policies file: {}", path.display()))?;
        if !pf.policies.contains_key("default") {
            return Err(anyhow!("policies file must include a 'default' policy"));
        }
        Ok(pf)
    }
}

/// In-memory policy store.
#[derive(Debug, Clone)]
pub struct PolicyStore {
    policies: BTreeMap<String, PolicyConfig>,
}

impl PolicyStore {
    pub fn from_file(pf: PoliciesFile) -> Self {
        Self {
            policies: pf.policies,
        }
    }

    pub fn default_from_env(
        l1_provider: Provider,
        l1_model: String,
        l2_provider: Provider,
        l2_model: String,
    ) -> Self {
        let mut policies = BTreeMap::new();
        policies.insert(
            "default".to_string(),
            PolicyConfig {
                l1: crate::model_policy::ModelRef {
                    provider: l1_provider,
                    model: l1_model,
                },
                l2: crate::model_policy::ModelRef {
                    provider: l2_provider,
                    model: l2_model,
                },
            },
        );
        Self { policies }
    }

    pub fn list(&self) -> Vec<String> {
        self.policies.keys().cloned().collect()
    }

    pub fn get(&self, name: &str) -> Option<&PolicyConfig> {
        self.policies.get(name)
    }

    /// Require a policy to exist; returns a cloned PolicyConfig.
    pub fn require(&self, name: &str) -> Result<PolicyConfig> {
        self.get(name)
            .cloned()
            .ok_or_else(|| anyhow!("unknown policy: {name}"))
    }
}
