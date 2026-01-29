use crate::config;
use std::{net::IpAddr, path::PathBuf};

pub const DEFAULT_HOST: &str = "127.0.0.1";
pub const DEFAULT_PORT: u16 = 18795;
pub const DEFAULT_HEAD: usize = 4000;
pub const DEFAULT_TAIL: usize = 4000;
pub const DEFAULT_FULL_IF_LTE: usize = 9000;

#[derive(Debug, Clone, Default)]
pub struct CliOverrides {
    pub host: Option<String>,
    pub port: Option<u16>,
    pub head: Option<usize>,
    pub tail: Option<usize>,
    pub full_if_lte: Option<usize>,
    pub policies_file: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct EffectiveSettings {
    pub host: String,
    pub port: u16,
    pub head: usize,
    pub tail: usize,
    pub full_if_lte: usize,
    pub policies_file: Option<PathBuf>,
}

pub fn compute_token_required(
    host: &str,
    allow_insecure_loopback: bool,
    require_token_setting: bool,
) -> anyhow::Result<bool> {
    let ip: IpAddr = host.parse()?;
    Ok((!ip.is_loopback() || !allow_insecure_loopback) && require_token_setting)
}

pub fn effective_settings(cli: &CliOverrides, cfg: Option<&config::Config>) -> EffectiveSettings {
    let cfg_server = cfg.and_then(|c| c.server.as_ref());
    let cfg_policy = cfg.and_then(|c| c.policy.as_ref());

    let host = cli
        .host
        .clone()
        .or_else(|| cfg_server.and_then(|s| s.host.clone()))
        .unwrap_or_else(|| DEFAULT_HOST.to_string());

    let port = cli
        .port
        .or_else(|| cfg_server.and_then(|s| s.port))
        .unwrap_or(DEFAULT_PORT);

    let head = cli
        .head
        .or_else(|| cfg_policy.and_then(|p| p.head))
        .unwrap_or(DEFAULT_HEAD);

    let tail = cli
        .tail
        .or_else(|| cfg_policy.and_then(|p| p.tail))
        .unwrap_or(DEFAULT_TAIL);

    let full_if_lte = cli
        .full_if_lte
        .or_else(|| cfg_policy.and_then(|p| p.full_if_lte))
        .unwrap_or(DEFAULT_FULL_IF_LTE);

    let policies_file: Option<PathBuf> = cli.policies_file.clone().or_else(|| {
        cfg_policy
            .and_then(|p| p.policies_file.as_ref())
            .map(PathBuf::from)
    });

    EffectiveSettings {
        host,
        port,
        head,
        tail,
        full_if_lte,
        policies_file,
    }
}

pub fn token_env(cfg: Option<&config::Config>) -> String {
    cfg.and_then(|c| c.security.as_ref())
        .and_then(|s| s.token_env.clone())
        .unwrap_or_else(|| "ACIP_AUTH_TOKEN".to_string())
}

pub fn allow_insecure_loopback(cfg: Option<&config::Config>) -> bool {
    cfg.and_then(|c| c.security.as_ref())
        .and_then(|s| s.allow_insecure_loopback)
        .unwrap_or(true)
}

pub fn require_token_setting(cfg: Option<&config::Config>) -> bool {
    cfg.and_then(|c| c.security.as_ref())
        .and_then(|s| s.require_token)
        .unwrap_or(true)
}
