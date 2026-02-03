use acip_sidecar::{config, server_config};

#[test]
fn token_env_defaults_when_missing() {
    let cfg = config::Config {
        service: None,
        server: None,
        policy: None,
        security: None,
        normalize: None,
    };
    assert_eq!(server_config::token_env(Some(&cfg)), "ACIP_AUTH_TOKEN");
    assert_eq!(server_config::token_env(None), "ACIP_AUTH_TOKEN");
}

#[test]
fn allow_insecure_loopback_defaults_true() {
    let cfg = config::Config {
        service: None,
        server: None,
        policy: None,
        security: None,
        normalize: None,
    };
    assert!(server_config::allow_insecure_loopback(Some(&cfg)));
    assert!(server_config::allow_insecure_loopback(None));
}

#[test]
fn require_token_setting_defaults_true() {
    let cfg = config::Config {
        service: None,
        server: None,
        policy: None,
        security: None,
        normalize: None,
    };
    assert!(server_config::require_token_setting(Some(&cfg)));
    assert!(server_config::require_token_setting(None));
}

#[test]
fn effective_settings_defaults_when_no_cli_or_config() {
    let cli = server_config::CliOverrides::default();
    let eff = server_config::effective_settings(&cli, None);

    assert_eq!(eff.host, server_config::DEFAULT_HOST);
    assert_eq!(eff.port, server_config::DEFAULT_PORT);
    assert_eq!(eff.head, server_config::DEFAULT_HEAD);
    assert_eq!(eff.tail, server_config::DEFAULT_TAIL);
    assert_eq!(eff.full_if_lte, server_config::DEFAULT_FULL_IF_LTE);
    assert!(eff.policies_file.is_none());
}

#[test]
fn token_required_false_when_require_token_setting_false() {
    // Even on non-loopback, if require_token_setting is false, don't require token.
    let required = server_config::compute_token_required("0.0.0.0", true, false).unwrap();
    assert!(!required);
}
