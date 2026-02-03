use acip_sidecar::reputation::{JsonFileReputationStore, ReputationStore};
use std::fs;

#[test]
fn json_file_store_persists_across_reload() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("rep.json");

    // First run: record an observation.
    {
        let store = JsonFileReputationStore::load_or_create(&path).unwrap();
        let recs = store.record(acip_sidecar::reputation::observation(
            "source-a".to_string(),
            Some("example.com".to_string()),
            10,
            vec!["PromptInjection".to_string()],
        ));
        assert!(!recs.is_empty());
    }

    // Reload: record should still be there and counts should have progressed.
    {
        let store = JsonFileReputationStore::load_or_create(&path).unwrap();

        let src = store.get("source_id:source-a").unwrap();
        assert!(src.seen_count >= 1);
        assert!(src.risk_score >= 10);

        let host = store.get("host:example.com").unwrap();
        assert!(host.seen_count >= 1);
        assert!(host.risk_score >= 10);
    }
}

#[test]
fn json_file_store_quarantines_corrupt_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("rep.json");

    fs::write(&path, "{this is not valid json").unwrap();

    let store = JsonFileReputationStore::load_or_create(&path).unwrap();
    assert!(store.get("source_id:missing").is_none());
    assert!(!path.exists());

    let mut quarantined = None;
    for entry in fs::read_dir(dir.path()).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with("rep.json.corrupt.") {
            quarantined = Some(entry.path());
            break;
        }
    }
    assert!(quarantined.is_some());
}
