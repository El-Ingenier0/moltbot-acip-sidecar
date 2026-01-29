use moltbot_acip_sidecar::reputation::{JsonFileReputationStore, ReputationStore};

#[test]
fn json_file_store_persists_across_reload() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("rep.json");

    // First run: record an observation.
    {
        let store = JsonFileReputationStore::load_or_create(&path).unwrap();
        let recs = store.record(moltbot_acip_sidecar::reputation::observation(
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
