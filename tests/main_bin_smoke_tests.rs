use predicates::prelude::*;
use std::{fs, os::unix::fs::PermissionsExt, process::Command};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_moltbot-acip-sidecar")
}

#[test]
fn binary_help_works() {
    let out = Command::new(bin()).arg("--help").output().unwrap();
    assert!(out.status.success());
}

#[test]
fn missing_config_file_is_not_fatal_up_to_start() {
    // We can't let it serve indefinitely in a test; start it and then kill it.
    let mut child = Command::new(bin())
        .args(["--config", "/definitely/not/here/config.toml"])
        .args(["--host", "127.0.0.1"]) // loopback -> token not required by default
        .args(["--port", "0"]) // ephemeral
        .env("RUST_LOG", "info")
        .spawn()
        .unwrap();

    std::thread::sleep(std::time::Duration::from_millis(300));
    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn requires_token_on_non_loopback_when_config_says_so() {
    let dir = tempfile::tempdir().unwrap();

    let cfg_path = dir.path().join("config.toml");
    fs::write(
        &cfg_path,
        r#"
[server]
host = "0.0.0.0"
port = 0

[security]
allow_insecure_loopback = false
require_token = true
token_env = "ACIP_AUTH_TOKEN"
"#,
    )
    .unwrap();

    let secrets_path = dir.path().join("secrets.env");
    fs::write(&secrets_path, "GEMINI_API_KEY=x\n").unwrap();

    let mut perms = fs::metadata(&secrets_path).unwrap().permissions();
    perms.set_mode(0o600);
    fs::set_permissions(&secrets_path, perms).unwrap();

    let mut dperms = fs::metadata(dir.path()).unwrap().permissions();
    dperms.set_mode(0o700);
    fs::set_permissions(dir.path(), dperms).unwrap();

    let out = Command::new(bin())
        .args(["--config", cfg_path.to_str().unwrap()])
        .args(["--secrets-file", secrets_path.to_str().unwrap()])
        .output()
        .unwrap();

    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(predicate::str::contains("auth token required").eval(&stderr));
}
