use anyhow::{Context, Result};
use acip_sidecar::extract::{self, ExtractRequest, ExtractResponse, ExtractStats};
use std::{
    fs::OpenOptions,
    io::{Read, Write},
};

fn write_response(out_path: Option<&str>, payload: &[u8]) -> Result<()> {
    if let Some(path) = out_path {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
            .with_context(|| format!("open {path}"))?;
        file.write_all(payload).context("write ACIP_EXTRACTOR_OUT")?;
    } else {
        std::io::stdout().write_all(payload).context("write stdout")?;
    }
    Ok(())
}

fn write_diag(err_path: Option<&str>, err: &anyhow::Error) {
    let msg = err.to_string();
    if let Some(path) = err_path {
        if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
            let _ = writeln!(file, "{msg}");
        }
    } else {
        eprintln!("{msg}");
    }
}

fn run(out_path: Option<&str>) -> Result<()> {
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
        {
            unsafe {
                let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
                if fd == -1 {
                    let err = std::io::Error::last_os_error();
                    if err.raw_os_error() == Some(libc::EPERM) {
                        anyhow::bail!("seccomp_network_denied");
                    }
                    anyhow::bail!("socket_failed: {err}");
                }
                libc::close(fd);
            }

            // If we managed to create a socket, seccomp isn't active.
            anyhow::bail!("seccomp_network_not_denied");
        }

        #[cfg(not(target_os = "linux"))]
        {
            anyhow::bail!("seccomp_unavailable");
        }
    }

    if std::env::var("ACIP_EXTRACTOR_SELFTEST_LARGE")
        .ok()
        .is_some_and(|v| v.trim() == "1")
    {
        const SELFTEST_LARGE_CHARS: usize = 7_000_000;
        let text = "x".repeat(SELFTEST_LARGE_CHARS);
        let resp = ExtractResponse {
            ok: true,
            kind: req.kind.clone(),
            text,
            warnings: Vec::new(),
            stats: ExtractStats {
                pages: None,
                text_chars: SELFTEST_LARGE_CHARS,
                ocr_used: false,
                ocr_chars: 0,
            },
        };
        let out = serde_json::to_vec(&resp).context("serialize response")?;
        write_response(out_path, &out)?;
        return Ok(());
    }

    let resp = extract::extract(&req, payload).context("extract")?;
    let out = serde_json::to_vec(&resp).context("serialize response")?;
    write_response(out_path, &out)?;
    Ok(())
}

fn main() -> Result<()> {
    let out_path = std::env::var("ACIP_EXTRACTOR_OUT").ok();
    let err_path = std::env::var("ACIP_EXTRACTOR_ERR").ok();

    let result = run(out_path.as_deref());
    if let Err(ref err) = result {
        write_diag(err_path.as_deref(), err);
    }
    result
}
