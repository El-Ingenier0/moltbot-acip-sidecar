use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs,
    io::Write,
    path::{Path, PathBuf},
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

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
            match serde_json::from_str::<JsonStoreFile>(&raw) {
                Ok(parsed) => parsed.records,
                Err(err) => {
                    let quarantine = quarantine_path(&path);
                    if let Err(quarantine_err) = quarantine_corrupt_file(&path, &quarantine) {
                        tracing::warn!(
                            error = %quarantine_err,
                            quarantine_path = %quarantine.display(),
                            "Failed to quarantine corrupt reputation file"
                        );
                    } else {
                        tracing::warn!(
                            error = %err,
                            quarantine_path = %quarantine.display(),
                            "Quarantined corrupt reputation file after JSON parse failure"
                        );
                    }
                    HashMap::new()
                }
            }
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
        let parent = self.path.parent().unwrap_or_else(|| Path::new("."));
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
        let file = JsonStoreFile {
            records: map.clone(),
        };
        let raw = serde_json::to_string_pretty(&file)?;
        let temp_path = temp_path_for(&self.path, parent);
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            options.mode(0o600);
        }

        let mut temp_file = options.open(&temp_path)?;
        #[cfg(unix)]
        {
            let _ = temp_file.set_permissions(fs::Permissions::from_mode(0o600));
        }
        temp_file.write_all(raw.as_bytes())?;
        if let Err(err) = temp_file.sync_all() {
            tracing::warn!(
                error = %err,
                path = %temp_path.display(),
                "Failed to fsync reputation temp file"
            );
        }
        drop(temp_file);

        if let Err(err) = fs::rename(&temp_path, &self.path) {
            let _ = fs::remove_file(&temp_path);
            return Err(err.into());
        }

        fsync_dir_best_effort(parent);
        Ok(())
    }
}

fn quarantine_corrupt_file(path: &Path, quarantine: &Path) -> anyhow::Result<()> {
    if let Err(rename_err) = fs::rename(path, quarantine) {
        tracing::warn!(
            error = %rename_err,
            source_path = %path.display(),
            quarantine_path = %quarantine.display(),
            "Rename failed while quarantining corrupt reputation file; attempting copy+remove"
        );
        fs::copy(path, quarantine)?;
        fs::remove_file(path)?;
    }
    Ok(())
}

fn fsync_dir_best_effort(path: &Path) {
    match fs::File::open(path) {
        Ok(dir) => {
            if let Err(err) = dir.sync_all() {
                tracing::warn!(
                    error = %err,
                    path = %path.display(),
                    "Failed to fsync reputation directory"
                );
            }
        }
        Err(err) => {
            tracing::warn!(
                error = %err,
                path = %path.display(),
                "Failed to open reputation directory for fsync"
            );
        }
    }
}

fn quarantine_path(path: &Path) -> PathBuf {
    let ts = now_unix();
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("reputation.json");
    path.with_file_name(format!("{}.corrupt.{}", file_name, ts))
}

fn temp_path_for(path: &Path, parent: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("reputation.json");
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let pid = std::process::id();
    parent.join(format!(".{}.tmp.{}.{}", file_name, pid, nanos))
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
