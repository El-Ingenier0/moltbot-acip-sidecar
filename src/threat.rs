use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum AttackType {
    PromptInjection,
    ToolCoercion,
    DataExfiltration,
    CredentialTheft,
    Jailbreak,
    SocialEngineering,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ThreatAssessment {
    #[serde(default)]
    pub attack_types: Vec<AttackType>,
    #[serde(default)]
    pub indicators: Vec<String>,
    pub threat_score: u8,
}

impl ThreatAssessment {
    pub fn none() -> Self {
        Self {
            attack_types: vec![],
            indicators: vec![],
            threat_score: 0,
        }
    }

    pub fn add(&mut self, ty: AttackType, indicator: impl Into<String>, score: u8) {
        self.attack_types.push(ty);
        self.indicators.push(indicator.into());
        self.threat_score = self.threat_score.saturating_add(score);
    }

    pub fn normalize(&mut self) {
        self.attack_types.sort();
        self.attack_types.dedup();
        self.indicators.sort();
        self.indicators.dedup();
    }
}

pub fn assess(text: &str) -> ThreatAssessment {
    let mut a = ThreatAssessment::none();
    let lower = text.to_lowercase();

    // Prompt injection / tool coercion patterns
    let pi_phrases = [
        "ignore previous",
        "ignore all previous",
        "disregard above",
        "system prompt",
        "developer message",
        "follow these instructions",
        "you must",
        "do not follow",
        "tool",
        "function call",
        "call the tool",
    ];
    for p in pi_phrases {
        if lower.contains(p) {
            a.add(
                AttackType::PromptInjection,
                format!("contains_phrase:{p}"),
                8,
            );
        }
    }

    // Exfil / credential theft signals
    let cred_phrases = [
        "api key",
        "secret",
        "token",
        "password",
        "private key",
        "ssh key",
        "wallet seed",
        "mnemonic",
    ];
    for p in cred_phrases {
        if lower.contains(p) {
            a.add(
                AttackType::CredentialTheft,
                format!("mentions_sensitive:{p}"),
                10,
            );
        }
    }

    let exfil_phrases = [
        "send to",
        "exfiltrate",
        "upload",
        "pastebin",
        "webhook",
        "http://",
        "https://",
    ];
    for p in exfil_phrases {
        if lower.contains(p) {
            a.add(
                AttackType::DataExfiltration,
                format!("mentions_exfil:{p}"),
                6,
            );
        }
    }

    // Jailbreak-ish language
    let jailbreak_phrases = [
        "jailbreak",
        "dan mode",
        "no restrictions",
        "bypass",
        "override",
        "you are free",
    ];
    for p in jailbreak_phrases {
        if lower.contains(p) {
            a.add(AttackType::Jailbreak, format!("mentions:{p}"), 8);
        }
    }

    // Social engineering
    let se_phrases = [
        "urgent",
        "immediately",
        "asap",
        "do this now",
        "time sensitive",
        "do not tell",
    ];
    for p in se_phrases {
        if lower.contains(p) {
            a.add(
                AttackType::SocialEngineering,
                format!("social_pressure:{p}"),
                4,
            );
        }
    }

    // Tool coercion: requesting tool usage explicitly
    let tool_phrases = [
        "run curl",
        "execute",
        "shell",
        "terminal",
        "powershell",
        "cmd.exe",
    ];
    for p in tool_phrases {
        if lower.contains(p) {
            a.add(AttackType::ToolCoercion, format!("tool_request:{p}"), 10);
        }
    }

    a.normalize();
    a
}
