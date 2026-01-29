use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ReputationRecord {
    pub key: String,
    pub seen_count: u64,
    pub suspected_attack_count: u64,
    pub last_seen_unix: u64,
    #[serde(default)]
    pub last_attack_types: Vec<String>,
    pub risk_score: u64,
}

#[derive(Debug, Clone)]
pub struct Observation {
    pub source_id: String,
    pub host: Option<String>,
    pub threat_score: u8,
    pub attack_types: Vec<String>,
    pub now_unix: u64,
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub trait ReputationStore: Send + Sync {
    fn get(&self, key: &str) -> Option<ReputationRecord>;
    fn record(&self, obs: Observation) -> Vec<ReputationRecord>;
}

#[derive(Default)]
pub struct InMemoryReputationStore {
    inner: Mutex<HashMap<String, ReputationRecord>>,
}

impl InMemoryReputationStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn upsert_locked(map: &mut HashMap<String, ReputationRecord>, key: String, obs: &Observation) {
        let rec = map.entry(key.clone()).or_insert_with(|| ReputationRecord {
            key,
            ..Default::default()
        });

        rec.seen_count += 1;
        rec.last_seen_unix = obs.now_unix;

        if obs.threat_score > 0 {
            rec.suspected_attack_count += 1;
            rec.last_attack_types = obs.attack_types.clone();
            // Simple scoring: accumulate threat_score as risk.
            rec.risk_score = rec.risk_score.saturating_add(obs.threat_score as u64);
        }
    }

    fn record_inner(&self, obs: Observation) -> Vec<ReputationRecord> {
        let mut out: Vec<ReputationRecord> = vec![];
        let mut map = self.inner.lock().unwrap();

        let src_key = format!("source_id:{}", obs.source_id);
        Self::upsert_locked(&mut map, src_key.clone(), &obs);
        out.push(map.get(&src_key).cloned().unwrap());

        if let Some(host) = &obs.host {
            let host_key = format!("host:{}", host);
            Self::upsert_locked(&mut map, host_key.clone(), &obs);
            out.push(map.get(&host_key).cloned().unwrap());
        }

        out
    }
}

impl ReputationStore for InMemoryReputationStore {
    fn get(&self, key: &str) -> Option<ReputationRecord> {
        self.inner.lock().unwrap().get(key).cloned()
    }

    fn record(&self, obs: Observation) -> Vec<ReputationRecord> {
        self.record_inner(obs)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct JsonStoreFile {
    #[serde(default)]
    records: HashMap<String, ReputationRecord>,
}

pub struct JsonFileReputationStore {
    path: PathBuf,
    inner: Mutex<HashMap<String, ReputationRecord>>,
}

impl JsonFileReputationStore {
    pub fn load_or_create(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let map = if path.exists() {
            let raw = fs::read_to_string(&path)?;
            let parsed: JsonStoreFile = serde_json::from_str(&raw)?;
            parsed.records
        } else {
            HashMap::new()
        };

        Ok(Self {
            path,
            inner: Mutex::new(map),
        })
    }

    pub fn default_path() -> PathBuf {
        // Best-effort default. Operators can override via env/config.
        PathBuf::from("/var/lib/acip/reputation.json")
    }

    fn persist(&self, map: &HashMap<String, ReputationRecord>) -> anyhow::Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let file = JsonStoreFile {
            records: map.clone(),
        };
        let raw = serde_json::to_string_pretty(&file)?;
        fs::write(&self.path, raw)?;
        Ok(())
    }
}

impl ReputationStore for JsonFileReputationStore {
    fn get(&self, key: &str) -> Option<ReputationRecord> {
        self.inner.lock().unwrap().get(key).cloned()
    }

    fn record(&self, mut obs: Observation) -> Vec<ReputationRecord> {
        if obs.now_unix == 0 {
            obs.now_unix = now_unix();
        }

        let mut out: Vec<ReputationRecord> = vec![];
        let mut map = self.inner.lock().unwrap();

        let src_key = format!("source_id:{}", obs.source_id);
        InMemoryReputationStore::upsert_locked(&mut map, src_key.clone(), &obs);
        out.push(map.get(&src_key).cloned().unwrap());

        if let Some(host) = &obs.host {
            let host_key = format!("host:{}", host);
            InMemoryReputationStore::upsert_locked(&mut map, host_key.clone(), &obs);
            out.push(map.get(&host_key).cloned().unwrap());
        }

        // Persist best-effort.
        let _ = self.persist(&map);
        out
    }
}

/// Helper for building an observation from request metadata.
pub fn observation(
    source_id: String,
    host: Option<String>,
    threat_score: u8,
    attack_types: Vec<String>,
) -> Observation {
    Observation {
        source_id,
        host,
        threat_score,
        attack_types,
        now_unix: now_unix(),
    }
}
