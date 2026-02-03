use acip_sidecar::config;
use std::io::Write;

#[test]
fn config_load_parses_toml() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");

    let mut f = std::fs::File::create(&path).unwrap();
    write!(
        f,
        "{}",
        r#"
[server]
host = "127.0.0.1"
port = 18795

[security]
allow_insecure_loopback = true
require_token = true
token_env = "ACIP_AUTH_TOKEN"

[policy]
head = 4000
tail = 4000
full_if_lte = 9000
"#
    )
    .unwrap();

    let cfg = config::Config::load(&path).unwrap();
    assert_eq!(cfg.server.unwrap().host.unwrap(), "127.0.0.1");
    assert_eq!(cfg.security.unwrap().token_env.unwrap(), "ACIP_AUTH_TOKEN");
    assert_eq!(cfg.policy.unwrap().full_if_lte.unwrap(), 9000);
}

#[test]
fn config_load_missing_file_errors() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("missing.toml");
    let err = config::Config::load(&path).err().unwrap();
    let s = format!("{err:#}");
    assert!(s.to_lowercase().contains("no such") || s.to_lowercase().contains("not found"));
}
