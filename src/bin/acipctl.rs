use acip_sidecar::config;
use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use clap::{Parser, Subcommand};
use serde_json::Value;
use std::{
    fs,
    io::{self, Read},
    path::PathBuf,
};

/// acipctl — configure and exercise a running ACIP Sidecar.
///
/// Designed to work even when the sidecar runs in Docker: this tool can
/// generate/validate config files and can call the sidecar HTTP API.
#[derive(Debug, Parser)]
#[command(name = "acipctl")]
#[command(version)]
struct Cli {
    /// Base URL for the sidecar (used by commands that call the HTTP API)
    #[arg(long, default_value = "http://127.0.0.1:18795")]
    url: String,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Print or validate configuration
    Config {
        #[command(subcommand)]
        cmd: ConfigCmd,
    },

    /// GET /health
    Health,

    /// Ingest a local file via /v1/acip/ingest_source
    IngestFile {
        /// Source id for audit/dedup
        #[arg(long)]
        source_id: String,

        /// Source type (pdf|html|file|other)
        #[arg(long, default_value = "file")]
        source_type: String,

        /// Content-Type (e.g., application/pdf)
        #[arg(long, default_value = "application/octet-stream")]
        content_type: String,

        /// Path to file
        path: PathBuf,

        /// If set, authorizes tools (otherwise tools are hard-gated)
        #[arg(long, default_value_t = false)]
        allow_tools: bool,

        /// Optional policy name to use (header X-ACIP-Policy)
        #[arg(long)]
        policy: Option<String>,
    },

    /// Ingest raw text (reads stdin) via /v1/acip/ingest_source
    IngestText {
        #[arg(long)]
        source_id: String,
        #[arg(long, default_value = "clipboard")]
        source_type: String,
        #[arg(long, default_value = "text/plain")]
        content_type: String,
        #[arg(long, default_value_t = false)]
        allow_tools: bool,
        #[arg(long)]
        policy: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum ConfigCmd {
    /// Print a config example to stdout
    Example,

    /// Validate a config file (loads and parses TOML)
    Validate {
        #[arg(long)]
        path: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.cmd {
        Cmd::Config { cmd } => match cmd {
            ConfigCmd::Example => {
                let ex = include_str!("../../config.example.toml");
                print!("{ex}");
            }
            ConfigCmd::Validate { path } => {
                let _ = config::Config::load(&path).with_context(|| format!("load {path:?}"))?;
                eprintln!("OK: {path:?}");
            }
        },

        Cmd::Health => {
            let u = format!("{}/health", cli.url.trim_end_matches('/'));
            let txt = reqwest::blocking::get(&u)
                .with_context(|| format!("GET {u}"))?
                .text()
                .context("read response")?;
            println!("{txt}");
        }

        Cmd::IngestFile {
            source_id,
            source_type,
            content_type,
            path,
            allow_tools,
            policy,
        } => {
            let bytes = fs::read(&path).with_context(|| format!("read {path:?}"))?;
            ingest_bytes(
                &cli.url,
                &source_id,
                &source_type,
                &content_type,
                &bytes,
                allow_tools,
                policy.as_deref(),
            )?;
        }

        Cmd::IngestText {
            source_id,
            source_type,
            content_type,
            allow_tools,
            policy,
        } => {
            let mut s = String::new();
            io::stdin().read_to_string(&mut s).context("read stdin")?;

            // Send as text field; sidecar also accepts bytes_b64.
            let u = format!("{}/v1/acip/ingest_source", cli.url.trim_end_matches('/'));
            let mut req = reqwest::blocking::Client::new().post(&u);
            if allow_tools {
                req = req.header("X-ACIP-Allow-Tools", "true");
            }
            if let Some(p) = policy {
                req = req.header("X-ACIP-Policy", p);
            }

            let body = serde_json::json!({
              "source_id": source_id,
              "source_type": source_type,
              "content_type": content_type,
              "text": s
            });

            let resp = req.json(&body).send().with_context(|| format!("POST {u}"))?;
            let status = resp.status();
            let v: Value = resp.json().context("parse json")?;
            println!("{}", serde_json::to_string_pretty(&v).unwrap_or_else(|_| v.to_string()));
            if !status.is_success() {
                anyhow::bail!("request failed: {status}");
            }
        }
    }

    Ok(())
}

fn ingest_bytes(
    base_url: &str,
    source_id: &str,
    source_type: &str,
    content_type: &str,
    bytes: &[u8],
    allow_tools: bool,
    policy: Option<&str>,
) -> Result<()> {
    let u = format!("{}/v1/acip/ingest_source", base_url.trim_end_matches('/'));

    let mut req = reqwest::blocking::Client::new().post(&u);
    if allow_tools {
        req = req.header("X-ACIP-Allow-Tools", "true");
    }
    if let Some(p) = policy {
        req = req.header("X-ACIP-Policy", p);
    }

    let b64 = B64.encode(bytes);
    let body = serde_json::json!({
      "source_id": source_id,
      "source_type": source_type,
      "content_type": content_type,
      "bytes_b64": b64
    });

    let resp = req.json(&body).send().with_context(|| format!("POST {u}"))?;
    let status = resp.status();
    let v: Value = resp.json().context("parse json")?;
    println!("{}", serde_json::to_string_pretty(&v).unwrap_or_else(|_| v.to_string()));
    if !status.is_success() {
        anyhow::bail!("request failed: {status}");
    }
    Ok(())
}
