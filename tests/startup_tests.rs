use acip_sidecar::startup;
use std::{fs, os::unix::fs::PermissionsExt};

#[test]
fn secrets_store_falls_back_to_env() {
    std::env::set_var("ACIP_TEST_SECRET", "hello");
    let secrets = startup::build_secrets_store(None).unwrap();
    assert_eq!(secrets.get("ACIP_TEST_SECRET").unwrap(), "hello");
}

#[test]
fn secrets_store_reads_file_when_provided() {
    let dir = tempfile::tempdir().unwrap();
    let dpath = dir.path();

    let secrets_path = dpath.join("secrets.env");
    fs::write(&secrets_path, "ACIP_AUTH_TOKEN=abc\n").unwrap();

    let mut perms = fs::metadata(&secrets_path).unwrap().permissions();
    perms.set_mode(0o600);
    fs::set_permissions(&secrets_path, perms).unwrap();

    let mut dperms = fs::metadata(dpath).unwrap().permissions();
    dperms.set_mode(0o700);
    fs::set_permissions(dpath, dperms).unwrap();

    let secrets = startup::build_secrets_store(Some(secrets_path)).unwrap();
    assert_eq!(secrets.get("ACIP_AUTH_TOKEN").unwrap(), "abc");
}

#[test]
fn resolve_token_errors_when_required_and_missing() {
    let secrets = startup::build_secrets_store(None).unwrap();
    let err = startup::resolve_token(true, &secrets, "ACIP_MISSING_TOKEN")
        .err()
        .unwrap();
    assert!(format!("{err:#}").contains("auth token required"));
}
