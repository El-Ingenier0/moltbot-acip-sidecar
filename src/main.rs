use axum::{routing::post, Router};
use clap::Parser;
use std::{net::SocketAddr, path::PathBuf, sync::Arc};
use tracing::{info, warn};

use acip_sidecar::{
    app, app_state_builder, config, reputation, server_config, startup, state,
};

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    /// Bind host (default: 127.0.0.1)
    #[arg(long)]
    host: Option<String>,

    /// Bind port (default: 18795)
    #[arg(long)]
    port: Option<u16>,

    /// Optional Unix socket path. If set, binds this socket instead of TCP host:port.
    #[arg(long)]
    unix_socket: Option<PathBuf>,

    /// Max chars for head/tail policy head
    #[arg(long)]
    head: Option<usize>,

    /// Max chars for head/tail policy tail
    #[arg(long)]
    tail: Option<usize>,

    /// If total <= this, include whole text (default: 9000)
    #[arg(long)]
    full_if_lte: Option<usize>,

    /// Optional secrets env file (must be private: parent 700-ish, file 600-ish).
    ///
    /// If set, secrets are resolved from: secrets file → process env.
    /// Recommended system path: `/etc/acip/secrets.env`
    #[arg(long)]
    secrets_file: Option<PathBuf>,

    /// Policies JSON file (non-secret). Used with X-ACIP-Policy selection.
    /// Recommended system path: `/etc/acip/policies.json`
    #[arg(long)]
    policies_file: Option<PathBuf>,

    /// Config TOML file (default: /etc/acip/config.toml)
    #[arg(long)]
    config: Option<PathBuf>,
}

mod ingest {
    pub use acip_sidecar::ingest::*;
}

#[cfg(unix)]
fn username_from_uid(uid: libc::uid_t) -> anyhow::Result<String> {
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    let mut buf = vec![0u8; 1024];

    loop {
        let err = unsafe {
            libc::getpwuid_r(
                uid,
                &mut pwd,
                buf.as_mut_ptr() as *mut libc::c_char,
                buf.len(),
                &mut result,
            )
        };
        if err == 0 {
            if result.is_null() {
                anyhow::bail!("no passwd entry for uid {}", uid);
            }
            let name = unsafe { std::ffi::CStr::from_ptr(pwd.pw_name) }
                .to_string_lossy()
                .into_owned();
            return Ok(name);
        }
        if err == libc::ERANGE {
            buf.resize(buf.len() * 2, 0);
            continue;
        }
        anyhow::bail!(
            "getpwuid_r failed for uid {}: {}",
            uid,
            std::io::Error::from_raw_os_error(err)
        );
    }
}

#[cfg(unix)]
fn groupname_from_gid(gid: libc::gid_t) -> anyhow::Result<String> {
    let mut grp: libc::group = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::group = std::ptr::null_mut();
    let mut buf = vec![0u8; 1024];

    loop {
        let err = unsafe {
            libc::getgrgid_r(
                gid,
                &mut grp,
                buf.as_mut_ptr() as *mut libc::c_char,
                buf.len(),
                &mut result,
            )
        };
        if err == 0 {
            if result.is_null() {
                anyhow::bail!("no group entry for gid {}", gid);
            }
            let name = unsafe { std::ffi::CStr::from_ptr(grp.gr_name) }
                .to_string_lossy()
                .into_owned();
            return Ok(name);
        }
        if err == libc::ERANGE {
            buf.resize(buf.len() * 2, 0);
            continue;
        }
        anyhow::bail!(
            "getgrgid_r failed for gid {}: {}",
            gid,
            std::io::Error::from_raw_os_error(err)
        );
    }
}

#[cfg(unix)]
fn uid_from_username(name: &str) -> anyhow::Result<libc::uid_t> {
    let cname = std::ffi::CString::new(name)?;
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    let mut buf = vec![0u8; 1024];

    loop {
        let err = unsafe {
            libc::getpwnam_r(
                cname.as_ptr(),
                &mut pwd,
                buf.as_mut_ptr() as *mut libc::c_char,
                buf.len(),
                &mut result,
            )
        };
        if err == 0 {
            if result.is_null() {
                anyhow::bail!("no passwd entry for user {}", name);
            }
            return Ok(pwd.pw_uid);
        }
        if err == libc::ERANGE {
            buf.resize(buf.len() * 2, 0);
            continue;
        }
        anyhow::bail!(
            "getpwnam_r failed for user {}: {}",
            name,
            std::io::Error::from_raw_os_error(err)
        );
    }
}

#[cfg(unix)]
fn gid_from_groupname(name: &str) -> anyhow::Result<libc::gid_t> {
    let cname = std::ffi::CString::new(name)?;
    let mut grp: libc::group = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::group = std::ptr::null_mut();
    let mut buf = vec![0u8; 1024];

    loop {
        let err = unsafe {
            libc::getgrnam_r(
                cname.as_ptr(),
                &mut grp,
                buf.as_mut_ptr() as *mut libc::c_char,
                buf.len(),
                &mut result,
            )
        };
        if err == 0 {
            if result.is_null() {
                anyhow::bail!("no group entry for group {}", name);
            }
            return Ok(grp.gr_gid);
        }
        if err == libc::ERANGE {
            buf.resize(buf.len() * 2, 0);
            continue;
        }
        anyhow::bail!(
            "getgrnam_r failed for group {}: {}",
            name,
            std::io::Error::from_raw_os_error(err)
        );
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args = Args::parse();
    let config_path = args
        .config
        .unwrap_or_else(|| PathBuf::from("/etc/acip/config.toml"));
    let config = match config::Config::load(&config_path) {
        Ok(cfg) => Some(cfg),
        Err(e) => {
            if let Some(ioe) = e.downcast_ref::<std::io::Error>() {
                if ioe.kind() == std::io::ErrorKind::NotFound {
                    info!(
                        "config file not found at {}; continuing",
                        config_path.display()
                    );
                    None
                } else {
                    return Err(e);
                }
            } else {
                return Err(e);
            }
        }
    };

    let cfg_service = config.as_ref().and_then(|cfg| cfg.service.as_ref());

    let cli = server_config::CliOverrides {
        host: args.host.clone(),
        port: args.port,
        unix_socket: args.unix_socket.clone(),
        head: args.head,
        tail: args.tail,
        full_if_lte: args.full_if_lte,
        policies_file: args.policies_file.clone(),
    };

    let eff = server_config::effective_settings(&cli, config.as_ref());

    let allow_insecure_loopback =
        acip_sidecar::server_config::allow_insecure_loopback(config.as_ref());
    let require_token_setting =
        acip_sidecar::server_config::require_token_setting(config.as_ref());
    let token_env = server_config::token_env(config.as_ref());

    let token_required = if eff.unix_socket.is_some() {
        // Treat Unix sockets like loopback: allow insecure loopback disables token requirement.
        (!allow_insecure_loopback) && require_token_setting
    } else {
        server_config::compute_token_required(
            &eff.host,
            allow_insecure_loopback,
            require_token_setting,
        )?
    };

    let effective_host = eff.host;
    let effective_port = eff.port;
    let effective_unix_socket = eff.unix_socket;
    let effective_head = eff.head;
    let effective_tail = eff.tail;
    let effective_full_if_lte = eff.full_if_lte;

    if let Some(service) = cfg_service {
        let enforce_identity = service.enforce_identity.unwrap_or(true);
        if enforce_identity {
            #[cfg(unix)]
            {
                // If configured, we can *either* verify identity (non-root) or
                // drop privileges (root) before serving.
                let desired_user = service.user.as_deref();
                let desired_group = service.group.as_deref();

                if desired_user.is_some() || desired_group.is_some() {
                    let euid = unsafe { libc::geteuid() };
                    let egid = unsafe { libc::getegid() };
                    let current_user = username_from_uid(euid)?;
                    let current_group = groupname_from_gid(egid)?;

                    // If already running as the desired identity, we're good.
                    let user_ok = desired_user.map(|u| u == current_user).unwrap_or(true);
                    let group_ok = desired_group.map(|g| g == current_group).unwrap_or(true);

                    if user_ok && group_ok {
                        info!("running as configured identity {}:{}", current_user, current_group);
                    } else if euid == 0 {
                        // Root: drop privileges.
                        let target_user = desired_user.unwrap_or("acip_user");
                        let target_group = desired_group.unwrap_or("acip_user");

                        let target_uid = uid_from_username(target_user)?;
                        let target_gid = gid_from_groupname(target_group)?;

                        // Set group first.
                        unsafe {
                            if libc::setgid(target_gid) != 0 {
                                anyhow::bail!(
                                    "setgid({}) failed: {}",
                                    target_gid,
                                    std::io::Error::last_os_error()
                                );
                            }
                            // Set supplementary groups.
                            let cuser = std::ffi::CString::new(target_user)?;
                            if libc::initgroups(cuser.as_ptr(), target_gid) != 0 {
                                anyhow::bail!(
                                    "initgroups({}) failed: {}",
                                    target_user,
                                    std::io::Error::last_os_error()
                                );
                            }
                            if libc::setuid(target_uid) != 0 {
                                anyhow::bail!(
                                    "setuid({}) failed: {}",
                                    target_uid,
                                    std::io::Error::last_os_error()
                                );
                            }
                        }

                        let new_uid = unsafe { libc::geteuid() };
                        let new_gid = unsafe { libc::getegid() };
                        let new_user = username_from_uid(new_uid)?;
                        let new_group = groupname_from_gid(new_gid)?;

                        if desired_user.is_some() && new_user != target_user {
                            anyhow::bail!("priv drop mismatch: expected user {target_user}, got {new_user}");
                        }
                        if desired_group.is_some() && new_group != target_group {
                            anyhow::bail!(
                                "priv drop mismatch: expected group {target_group}, got {new_group}"
                            );
                        }

                        info!("dropped privileges to {}:{}", new_user, new_group);
                    } else {
                        // Non-root and mismatch: fail closed.
                        anyhow::bail!(
                            "service identity mismatch: expected {:?}:{:?}, running as {}:{} (uid {}, gid {})",
                            desired_user,
                            desired_group,
                            current_user,
                            current_group,
                            euid,
                            egid
                        );
                    }
                }
            }
        }
    }

    // Secrets: secrets file (optional) + env fallback.
    let secrets = startup::build_secrets_store(args.secrets_file.clone())?;

    let token_opt = startup::resolve_token(token_required, &secrets, &token_env)?;
    if token_opt.is_some() {
        info!("auth token required");
    }

    // Reputation store: pluggable backend behind a stable interface.
    let reputation: std::sync::Arc<dyn reputation::ReputationStore> = {
        let store = std::env::var("ACIP_REPUTATION_STORE").unwrap_or_else(|_| "memory".to_string());
        if let Some(path) = store.strip_prefix("file:") {
            std::sync::Arc::new(reputation::JsonFileReputationStore::load_or_create(path)?)
        } else {
            std::sync::Arc::new(reputation::InMemoryReputationStore::new())
        }
    };

    let http = app_state_builder::build_http_client()?;

    // Policy store: load from policies.json when provided, otherwise fall back
    // to env-configured single 'default' policy.

    let effective_policies_file: Option<PathBuf> = eff.policies_file.clone();

    let policies = startup::build_policy_store(&secrets, effective_policies_file.clone())?;

    // For v0.1 we don't *use* the provider keys yet, but we can warn early.
    if secrets.get("GEMINI_API_KEY").is_none() {
        warn!("GEMINI_API_KEY not set (ok for v0.1; required for Gemini L1 model calls)");
    }
    if secrets.get("ANTHROPIC_API_KEY").is_none() {
        warn!("ANTHROPIC_API_KEY not set (ok for v0.1; required for Anthropic L2 fallback)");
    }

    let state = app_state_builder::build_app_state(
        state::Policy {
            head: effective_head,
            tail: effective_tail,
            full_if_lte: effective_full_if_lte,
        },
        http,
        secrets,
        policies,
        reputation,
    );

    // Apply token auth and body size limits to protected routes.
    let extra_protected =
        Router::new().route("/v1/acip/ingest_source", post(crate::ingest::ingest_source));
    let app = app::build_router(state, token_opt.clone(), extra_protected);

    if let Some(sock_path) = effective_unix_socket {
        #[cfg(unix)]
        {
            // Ensure parent exists.
            if let Some(parent) = sock_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            // Remove any stale socket.
            if sock_path.exists() {
                let _ = std::fs::remove_file(&sock_path);
            }

            info!("listening on unix:{}", sock_path.display());

            let listener = tokio::net::UnixListener::bind(&sock_path)?;

            // Best-effort permissions: owner rw, group rw.
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&sock_path, std::fs::Permissions::from_mode(0o660));

            // axum::serve only supports TcpListener; for unix sockets we accept manually.
            use hyper_util::rt::{TokioExecutor, TokioIo};
            use hyper_util::server::conn::auto::Builder as ConnBuilder;

            loop {
                let (stream, _addr) = listener.accept().await?;
                let io = TokioIo::new(stream);

                // Convert hyper::Request<Incoming> -> axum::Request<axum::body::Body>
                // so we can reuse the Router service.
                let app_clone = app.clone();
                let svc = hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                    let app2 = app_clone.clone();
                    async move {
                        use tower::ServiceExt;
                        let req2 = req.map(axum::body::Body::new);
                        let resp = app2.oneshot(req2).await;
                        match resp {
                            Ok(r) => Ok::<_, std::convert::Infallible>(r),
                            Err(e) => match e {},
                        }
                    }
                });

                tokio::spawn(async move {
                    let mut builder = ConnBuilder::new(TokioExecutor::new());
                    builder.http1().keep_alive(true);
                    if let Err(err) = builder.serve_connection(io, svc).await {
                        tracing::debug!("unix conn error: {err}");
                    }
                });
            }
        }
        #[cfg(not(unix))]
        {
            anyhow::bail!("unix socket requested but platform is not unix");
        }
    }

    let addr: SocketAddr = format!("{}:{}", effective_host, effective_port).parse()?;
    info!("listening on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
