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

    // Hidden debug mode used by tests: verify seccomp denied network syscalls.
    if std::env::var("ACIP_EXTRACTOR_SELFTEST_NET")
        .ok()
        .is_some_and(|v| v.trim() == "1")
    {
        #[cfg(target_os = "linux")]
        unsafe {
            let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
            if fd == -1 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EPERM) {
                    eprintln!("seccomp_network_denied");
                    std::process::exit(13);
                }
                anyhow::bail!("socket_failed: {err}");
            }
            libc::close(fd);
        }

        // If we managed to create a socket, seccomp isn't active.
        anyhow::bail!("seccomp_network_not_denied");
    }

    let resp = extract::extract(&req, payload).context("extract")?;
    let out = serde_json::to_vec(&resp).context("serialize response")?;
    std::io::stdout().write_all(&out).context("write stdout")?;
    Ok(())
}
