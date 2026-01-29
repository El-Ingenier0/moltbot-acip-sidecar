use anyhow::{Context, Result};
use moltbot_acip_sidecar::extract::{self, ExtractRequest};
use std::io::{Read, Write};

fn main() -> Result<()> {
    // Protocol: first line is JSON request; remaining bytes are payload.
    let mut stdin = std::io::stdin();
    let mut buf: Vec<u8> = vec![];
    stdin.read_to_end(&mut buf).context("read stdin")?;

    let Some(pos) = buf.iter().position(|b| *b == b'\n') else {
        anyhow::bail!("missing request header line");
    };

    let header = &buf[..pos];
    let payload = &buf[pos + 1..];

    let req: ExtractRequest = serde_json::from_slice(header).context("parse request json")?;
    let resp = extract::extract(&req, payload).context("extract")?;
    let out = serde_json::to_vec(&resp).context("serialize response")?;
    std::io::stdout().write_all(&out).context("write stdout")?;
    Ok(())
}
