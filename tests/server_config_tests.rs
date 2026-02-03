use acip_sidecar::{config, server_config};
use std::path::PathBuf;

#[test]
fn token_required_on_non_loopback() {
    let required = server_config::compute_token_required("0.0.0.0", true, true).unwrap();
    assert!(required);
}

#[test]
fn token_not_required_on_loopback_when_allowed() {
    let required = server_config::compute_token_required("127.0.0.1", true, true).unwrap();
    assert!(!required);
}

#[test]
fn token_required_on_loopback_when_insecure_loopback_disallowed() {
    let required = server_config::compute_token_required("127.0.0.1", false, true).unwrap();
    assert!(required);
}

#[test]
fn cli_overrides_config() {
    let cfg = config::Config {
        service: None,
        server: Some(config::ServerConfig {
            host: Some("127.0.0.1".to_string()),
            port: Some(1111),
            unix_socket: None,
        }),
        policy: Some(config::PolicyConfig {
            policies_file: Some("/etc/acip/policies.json".to_string()),
            head: Some(1),
            tail: Some(2),
            full_if_lte: Some(3),
        }),
        security: None,
        normalize: None,
    };

    let cli = server_config::CliOverrides {
        host: Some("0.0.0.0".to_string()),
        port: Some(2222),
        unix_socket: None,
        head: Some(10),
        tail: Some(20),
        full_if_lte: Some(30),
        policies_file: Some(PathBuf::from("/tmp/policies.json")),
    };

    let eff = server_config::effective_settings(&cli, Some(&cfg));
    assert_eq!(eff.host, "0.0.0.0");
    assert_eq!(eff.port, 2222);
    assert_eq!(eff.head, 10);
    assert_eq!(eff.tail, 20);
    assert_eq!(eff.full_if_lte, 30);
    assert_eq!(eff.policies_file, Some(PathBuf::from("/tmp/policies.json")));
}
