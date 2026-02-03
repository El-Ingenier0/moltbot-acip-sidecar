use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::Path,
    process::{Command, Stdio},
    time::Duration,
};
use tempfile::{tempdir, Builder};
use wait_timeout::ChildExt;

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

#[cfg(target_os = "linux")]
mod seccomp {
    use std::{ffi::c_void, io};

    // Minimal libseccomp FFI (we only need default-allow + syscall deny rules + load).
    type ScmpFilterCtx = *mut c_void;

    #[link(name = "seccomp")]
    extern "C" {
        fn seccomp_init(def_action: u32) -> ScmpFilterCtx;
        fn seccomp_rule_add(ctx: ScmpFilterCtx, action: u32, syscall: i32, arg_cnt: u32) -> i32;
        fn seccomp_load(ctx: ScmpFilterCtx) -> i32;
        fn seccomp_release(ctx: ScmpFilterCtx);
    }

    const SCMP_ACT_ALLOW: u32 = 0x7fff0000;
    const SCMP_ACT_ERRNO: u32 = 0x00050000;

    fn scmp_act_errno(errno: i32) -> u32 {
        SCMP_ACT_ERRNO | ((errno as u32) & 0x0000ffff)
    }

    pub fn install_network_deny() -> io::Result<()> {
        unsafe {
            let ctx = seccomp_init(SCMP_ACT_ALLOW);
            if ctx.is_null() {
                return Err(io::Error::other("seccomp_init returned null"));
            }

            let deny = scmp_act_errno(libc::EPERM);
            let syscalls: &[(i32, &str)] = &[
                (libc::SYS_socket as i32, "socket"),
                (libc::SYS_connect as i32, "connect"),
                (libc::SYS_accept as i32, "accept"),
                (libc::SYS_accept4 as i32, "accept4"),
                (libc::SYS_bind as i32, "bind"),
                (libc::SYS_listen as i32, "listen"),
                (libc::SYS_sendto as i32, "sendto"),
                (libc::SYS_recvfrom as i32, "recvfrom"),
                (libc::SYS_sendmsg as i32, "sendmsg"),
                (libc::SYS_recvmsg as i32, "recvmsg"),
                (libc::SYS_getsockopt as i32, "getsockopt"),
                (libc::SYS_setsockopt as i32, "setsockopt"),
                (libc::SYS_shutdown as i32, "shutdown"),
                (libc::SYS_socketpair as i32, "socketpair"),
                (libc::SYS_getpeername as i32, "getpeername"),
                (libc::SYS_getsockname as i32, "getsockname"),
            ];

            for (num, name) in syscalls {
                let rc = seccomp_rule_add(ctx, deny, *num, 0);
                if rc != 0 {
                    seccomp_release(ctx);
                    return Err(io::Error::other(format!(
                        "seccomp_rule_add failed for {name} (rc={rc})"
                    )));
                }
            }

            let rc = seccomp_load(ctx);
            if rc != 0 {
                seccomp_release(ctx);
                return Err(io::Error::other(format!("seccomp_load failed (rc={rc})")));
            }

            seccomp_release(ctx);
            Ok(())
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtractKind {
    Pdf,
    Svg,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractRequest {
    pub kind: ExtractKind,
    #[serde(default)]
    pub content_type: Option<String>,

    /// Generous defaults (Linux-only v1):
    #[serde(default)]
    pub max_pages: Option<u32>,
    #[serde(default)]
    pub dpi: Option<u32>,
    #[serde(default)]
    pub max_output_chars: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractResponse {
    pub ok: bool,
    pub kind: ExtractKind,
    pub text: String,
    #[serde(default)]
    pub warnings: Vec<String>,
    pub stats: ExtractStats,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ExtractStats {
    #[serde(default)]
    pub pages: Option<u32>,
    pub text_chars: usize,
    pub ocr_used: bool,
    pub ocr_chars: usize,
}

fn truncate_chars(mut s: String, max_chars: usize) -> (String, bool) {
    let len = s.chars().count();
    if len <= max_chars {
        return (s, false);
    }
    let head: String = s.chars().take(max_chars).collect();
    s.clear();
    (head, true)
}

pub fn extract_pdf_hybrid(req: &ExtractRequest, bytes: &[u8]) -> Result<ExtractResponse> {
    let max_pages = req.max_pages.unwrap_or(100);
    let dpi = req.dpi.unwrap_or(250);
    let max_output_chars = req.max_output_chars.unwrap_or(2_000_000);

    let dir = tempdir().context("create tempdir")?;
    let pdf_path = dir.path().join("input.pdf");
    std::fs::write(&pdf_path, bytes).context("write pdf")?;

    // 1) Text-layer extraction via poppler pdftotext.
    let pdftotext = Command::new("pdftotext")
        .arg("-layout")
        .arg(pdf_path.as_os_str())
        .arg("-")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .context("run pdftotext")?;

    let mut warnings: Vec<String> = vec![];

    if !pdftotext.status.success() {
        warnings.push("pdftotext_failed".to_string());
    }

    let mut text_primary = String::from_utf8_lossy(&pdftotext.stdout).to_string();
    // Some PDFs yield NULs; strip them.
    text_primary = text_primary.replace('\0', "");

    // Heuristic: if text is too small, do OCR.
    let primary_chars = text_primary.chars().count();
    let needs_ocr = primary_chars < 500;

    let mut ocr_text = String::new();
    if needs_ocr {
        warnings.push("pdf_text_layer_missing_or_small".to_string());

        // 2) Render pages to PNG via pdftoppm.
        let prefix = dir.path().join("page");
        let status = Command::new("pdftoppm")
            .arg("-f")
            .arg("1")
            .arg("-l")
            .arg(format!("{max_pages}"))
            .arg("-r")
            .arg(format!("{dpi}"))
            .arg("-png")
            .arg(pdf_path.as_os_str())
            .arg(prefix.as_os_str())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .status()
            .context("run pdftoppm")?;

        if !status.success() {
            warnings.push("pdftoppm_failed".to_string());
        } else {
            // OCR each page image.
            // Files are like page-1.png, page-2.png, ...
            let mut entries: Vec<_> = std::fs::read_dir(dir.path())
                .context("read tempdir")?
                .filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| {
                    p.file_name()
                        .and_then(|n| n.to_str())
                        .map(|n| n.starts_with("page-") && n.ends_with(".png"))
                        .unwrap_or(false)
                })
                .collect();
            entries.sort();

            for img in entries {
                // tesseract <image> stdout -l eng --dpi <dpi>
                let out = match Command::new("tesseract")
                    .arg(img.as_os_str())
                    .arg("stdout")
                    .arg("-l")
                    .arg("eng")
                    .arg("--dpi")
                    .arg(format!("{dpi}"))
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .output()
                {
                    Ok(o) => o,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        warnings.push("tesseract_not_installed".to_string());
                        break;
                    }
                    Err(e) => return Err(e).context("run tesseract"),
                };

                if !out.status.success() {
                    warnings.push("tesseract_failed".to_string());
                    continue;
                }

                let s = String::from_utf8_lossy(&out.stdout);
                if !s.trim().is_empty() {
                    ocr_text.push_str(&s);
                    ocr_text.push('\n');
                }
            }
        }
    }

    let mut combined = if needs_ocr {
        format!(
            "{}\n\n--- OCR ---\n\n{}",
            text_primary.trim_end(),
            ocr_text.trim_end()
        )
    } else {
        text_primary
    };

    let (trunc, did_trunc) = truncate_chars(std::mem::take(&mut combined), max_output_chars);
    if did_trunc {
        warnings.push("output_truncated".to_string());
    }

    Ok(ExtractResponse {
        ok: true,
        kind: ExtractKind::Pdf,
        text: trunc,
        warnings,
        stats: ExtractStats {
            pages: None,
            text_chars: primary_chars,
            ocr_used: needs_ocr,
            ocr_chars: ocr_text.chars().count(),
        },
    })
}

pub fn extract_svg_text(req: &ExtractRequest, bytes: &[u8]) -> Result<ExtractResponse> {
    let max_output_chars = req.max_output_chars.unwrap_or(500_000);
    let raw0 = String::from_utf8(bytes.to_vec()).map_err(|_| anyhow!("svg must be utf-8"))?;

    // Use existing xml scan + text-node extraction logic. (Sandboxing will be the safety boundary.)
    let scan = crate::xml_scan::scan(&raw0);

    // Best-effort: strip DOCTYPE/ENTITY blocks so the XML parser can still extract text.
    // We keep scan warnings so we don't lose the signal.
    let mut raw = raw0.clone();
    if scan.has_doctype || scan.has_entity {
        if let Some(start) = raw.to_lowercase().find("<!doctype") {
            if let Some(end) = raw[start..].find("]>") {
                let end = start + end + 2;
                raw.replace_range(start..end, "");
            }
        }
        // Drop any remaining ENTITY decls.
        while let Some(pos) = raw.to_lowercase().find("<!entity") {
            if let Some(end) = raw[pos..].find('>') {
                raw.replace_range(pos..(pos + end + 1), "");
            } else {
                break;
            }
        }
        raw = raw.replace("&xxe;", "");
    }

    let mut warnings: Vec<String> = vec![];
    if scan.severity > 0 {
        warnings.push(format!("xml_scan_severity:{}", scan.severity));
        for m in scan.matches {
            warnings.push(format!("xml_scan:{}", m));
        }
    }

    // Extract text nodes while skipping script/style.
    let Ok(doc) = roxmltree::Document::parse(&raw) else {
        return Ok(ExtractResponse {
            ok: false,
            kind: ExtractKind::Svg,
            text: String::new(),
            warnings: vec!["svg_parse_failed".to_string()],
            stats: ExtractStats {
                pages: None,
                text_chars: 0,
                ocr_used: false,
                ocr_chars: 0,
            },
        });
    };

    let mut parts: Vec<String> = vec![];
    for node in doc.descendants() {
        if !node.is_text() {
            continue;
        }
        let mut skip = false;
        for a in node.ancestors() {
            if a.has_tag_name("script") || a.has_tag_name("style") {
                skip = true;
                break;
            }
        }
        if skip {
            continue;
        }
        let txt = node.text().unwrap_or("").trim();
        if !txt.is_empty() {
            parts.push(txt.to_string());
        }
    }

    let out = parts.join("\n");
    let (text, did_trunc) = truncate_chars(out, max_output_chars);
    if did_trunc {
        warnings.push("output_truncated".to_string());
    }

    Ok(ExtractResponse {
        ok: true,
        kind: ExtractKind::Svg,
        text: text.clone(),
        warnings,
        stats: ExtractStats {
            pages: None,
            text_chars: text.chars().count(),
            ocr_used: false,
            ocr_chars: 0,
        },
    })
}

pub fn extract(req: &ExtractRequest, bytes: &[u8]) -> Result<ExtractResponse> {
    match req.kind {
        ExtractKind::Pdf => extract_pdf_hybrid(req, bytes),
        ExtractKind::Svg => extract_svg_text(req, bytes),
    }
}

#[derive(thiserror::Error, Debug)]
pub enum ExtractorError {
    #[error("extractor timeout")]
    Timeout,

    #[error("spawn extractor failed: {0}")]
    Spawn(String),

    #[error("extractor io failed: {0}")]
    Io(String),

    #[error("extractor failed (exit={exit_code:?}): {stderr}")]
    NonZeroExit {
        exit_code: Option<i32>,
        stderr: String,
    },

    #[error("extractor output exceeded limit ({bytes} bytes > {max_bytes} bytes)")]
    OutputTooLarge { bytes: u64, max_bytes: u64 },

    #[error("extractor output invalid: {0}")]
    OutputParse(String),
}

fn default_max_output_chars(req: &ExtractRequest) -> usize {
    req.max_output_chars.unwrap_or_else(|| match req.kind {
        ExtractKind::Pdf => 2_000_000,
        ExtractKind::Svg => 500_000,
    })
}

fn output_cap_bytes(req: &ExtractRequest) -> u64 {
    let max_chars = default_max_output_chars(req) as u64;
    let max_bytes = max_chars
        .saturating_mul(4)
        .saturating_add(1_048_576);
    max_bytes.min(33_554_432)
}

fn create_secure_file(path: &Path) -> std::result::Result<(), ExtractorError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        options.mode(0o600);
    }
    options
        .open(path)
        .map_err(|e| ExtractorError::Io(e.to_string()))?;

    #[cfg(not(unix))]
    {
        let _ = fs::set_permissions(path, fs::Permissions::from_readonly(false));
    }

    Ok(())
}

fn read_limited_file(path: &Path, max_bytes: u64) -> std::result::Result<Vec<u8>, ExtractorError> {
    let file = File::open(path).map_err(|e| ExtractorError::OutputParse(e.to_string()))?;
    let mut limited = file.take(max_bytes.saturating_add(1));
    let mut buf = Vec::new();
    limited
        .read_to_end(&mut buf)
        .map_err(|e| ExtractorError::OutputParse(e.to_string()))?;
    if (buf.len() as u64) > max_bytes {
        return Err(ExtractorError::OutputTooLarge {
            bytes: buf.len() as u64,
            max_bytes,
        });
    }
    Ok(buf)
}

/// Spawn the external extractor helper (`acip-extract`) and return its JSON response.
///
/// Linux-only v1 sandboxing (pure Rust):
/// - set rlimits (cpu/as/nofile/core/fsize)
/// - set PR_SET_NO_NEW_PRIVS
/// - set PR_SET_PDEATHSIG=SIGKILL
/// - nice/ionice/umask
/// - kill helper on timeout
pub fn run_helper(
    req: &ExtractRequest,
    bytes: &[u8],
    timeout: Duration,
) -> std::result::Result<ExtractResponse, ExtractorError> {
    let bin = std::env::var("ACIP_EXTRACTOR_BIN").unwrap_or_else(|_| "acip-extract".to_string());

    let tmpdir_env = std::env::var("ACIP_EXTRACTOR_TMPDIR")
        .ok()
        .filter(|v| !v.trim().is_empty());

    let mut builder = Builder::new();
    builder.prefix("acip-extractor-");
    let output_dir = match tmpdir_env.as_deref() {
        Some(base) => builder.tempdir_in(base),
        None => builder.tempdir(),
    }
    .map_err(|e| ExtractorError::Io(e.to_string()))?;

    #[cfg(unix)]
    fs::set_permissions(output_dir.path(), fs::Permissions::from_mode(0o700))
        .map_err(|e| ExtractorError::Io(e.to_string()))?;

    let out_path = output_dir.path().join("out.json");
    let err_path = output_dir.path().join("err.log");
    create_secure_file(&out_path)?;
    create_secure_file(&err_path)?;

    let mut cmd = Command::new(bin);
    cmd.env_clear().env("PATH", "/usr/bin:/bin");

    // Pass through explicit extractor tuning knobs (we env_clear for safety).
    for key in [
        "ACIP_EXTRACTOR_RLIMIT_AS_MB",
        "ACIP_EXTRACTOR_RLIMIT_NOFILE",
        "ACIP_EXTRACTOR_RLIMIT_FSIZE_MB",
        "ACIP_EXTRACTOR_RLIMIT_NPROC",
        "ACIP_EXTRACTOR_NICE",
        "ACIP_EXTRACTOR_SECCOMP",
        // Test-only/debug passthrough.
        "ACIP_EXTRACTOR_SELFTEST_NET",
        "ACIP_EXTRACTOR_SELFTEST_LARGE",
    ] {
        if let Ok(v) = std::env::var(key) {
            if !v.trim().is_empty() {
                cmd.env(key, v);
            }
        }
    }

    if let Some(tmpdir) = tmpdir_env.as_ref() {
        cmd.env("TMPDIR", tmpdir);
    }
    cmd.env("ACIP_EXTRACTOR_OUT", &out_path)
        .env("ACIP_EXTRACTOR_ERR", &err_path);
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    #[cfg(unix)]
    unsafe {
        use std::os::unix::process::CommandExt;

        let timeout_for_child = timeout;
        cmd.pre_exec(move || {
            let cpu_secs = timeout_for_child.as_secs().saturating_add(5).max(1);

            let as_bytes: u64 = std::env::var("ACIP_EXTRACTOR_RLIMIT_AS_MB")
                .ok()
                .and_then(|v| v.trim().parse::<u64>().ok())
                .unwrap_or(2048)
                * 1024
                * 1024;

            let nofile: u64 = std::env::var("ACIP_EXTRACTOR_RLIMIT_NOFILE")
                .ok()
                .and_then(|v| v.trim().parse::<u64>().ok())
                .unwrap_or(64);

            fn setrlim(
                resource: libc::__rlimit_resource_t,
                cur: u64,
                max: u64,
            ) -> std::io::Result<()> {
                let lim = libc::rlimit {
                    rlim_cur: cur as libc::rlim_t,
                    rlim_max: max as libc::rlim_t,
                };
                let rc = unsafe { libc::setrlimit(resource, &lim) };
                if rc != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            }

            // Core sandbox-ish resource limits.
            setrlim(libc::RLIMIT_CPU, cpu_secs, cpu_secs)?;
            setrlim(libc::RLIMIT_AS, as_bytes, as_bytes)?;
            setrlim(libc::RLIMIT_NOFILE, nofile, nofile)?;

            // No core dumps.
            setrlim(libc::RLIMIT_CORE, 0, 0)?;

            // Limit number of processes/threads to mitigate fork bombs.
            // (Tesseract/poppler shouldn't need many.)
            if let Ok(v) = std::env::var("ACIP_EXTRACTOR_RLIMIT_NPROC") {
                if let Ok(nproc) = v.trim().parse::<u64>() {
                    #[cfg(target_os = "linux")]
                    {
                        setrlim(libc::RLIMIT_NPROC, nproc, nproc)?;
                    }
                }
            }

            // Best-effort cap for max file size the helper can create (in bytes).
            // Needed because OCR path writes images to a temp dir.
            let fsize_mb: u64 = std::env::var("ACIP_EXTRACTOR_RLIMIT_FSIZE_MB")
                .ok()
                .and_then(|v| v.trim().parse::<u64>().ok())
                .unwrap_or(512);
            setrlim(
                libc::RLIMIT_FSIZE,
                fsize_mb * 1024 * 1024,
                fsize_mb * 1024 * 1024,
            )?;

            // Best-effort scheduler/IO deprioritization.
            // nice: increase niceness (lower priority)
            let nice_inc: i32 = std::env::var("ACIP_EXTRACTOR_NICE")
                .ok()
                .and_then(|v| v.trim().parse::<i32>().ok())
                .unwrap_or(10);
            let _ = libc::nice(nice_inc);

            // umask: ensure any temp files are private by default.
            libc::umask(0o077);

            // ioprio_set: put into idle IO class when available (Linux).
            #[cfg(target_os = "linux")]
            {
                const IOPRIO_CLASS_IDLE: u64 = 3;
                const IOPRIO_WHO_PROCESS: u64 = 1;
                // ioprio = (class << 13) | data
                let ioprio: u64 = IOPRIO_CLASS_IDLE << 13;
                // syscall(SYS_ioprio_set, which, who, ioprio)
                let _ = libc::syscall(
                    libc::SYS_ioprio_set as libc::c_long,
                    IOPRIO_WHO_PROCESS,
                    0u64,
                    ioprio,
                );
            }

            #[cfg(target_os = "linux")]
            {
                let rc = libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
                if rc != 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }

            // Optional: install a seccomp filter to deny network syscalls. This is opt-in and
            // intentionally default-allow to avoid breaking poppler/tesseract.
            if std::env::var("ACIP_EXTRACTOR_SECCOMP")
                .ok()
                .is_some_and(|v| v.trim() == "1")
            {
                #[cfg(target_os = "linux")]
                {
                    crate::extract::seccomp::install_network_deny()
                        .map_err(|e| std::io::Error::other(format!("seccomp setup failed: {e}")))?;
                }
            }

            #[cfg(target_os = "linux")]
            {
                let rc = libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0);
                if rc != 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }

            Ok(())
        });
    }

    let mut child = cmd
        .spawn()
        .map_err(|e| ExtractorError::Spawn(e.to_string()))?;

    let stdin = child
        .stdin
        .as_mut()
        .ok_or_else(|| ExtractorError::Spawn("missing stdin".to_string()))?;

    let header =
        serde_json::to_string(req).map_err(|e| ExtractorError::OutputParse(e.to_string()))?;
    stdin
        .write_all(header.as_bytes())
        .map_err(|e| ExtractorError::Spawn(e.to_string()))?;
    stdin
        .write_all(b"\n")
        .map_err(|e| ExtractorError::Spawn(e.to_string()))?;
    stdin
        .write_all(bytes)
        .map_err(|e| ExtractorError::Spawn(e.to_string()))?;
    drop(child.stdin.take());

    let Some(status) = child
        .wait_timeout(timeout)
        .map_err(|e| ExtractorError::Spawn(e.to_string()))?
    else {
        let _ = child.kill();
        let _ = child.wait();
        return Err(ExtractorError::Timeout);
    };

    if !status.success() {
        let err = fs::read_to_string(&err_path)
            .unwrap_or_default()
            .trim()
            .to_string();
        return Err(ExtractorError::NonZeroExit {
            exit_code: status.code(),
            stderr: err,
        });
    }

    let max_bytes = output_cap_bytes(req);
    let output = read_limited_file(&out_path, max_bytes)?;
    let resp: ExtractResponse = serde_json::from_slice(&output)
        .map_err(|e| ExtractorError::OutputParse(e.to_string()))?;
    Ok(resp)
}

#[cfg(test)]
mod tests {
    use super::create_secure_file;
    use std::fs;
    use tempfile::tempdir;

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    #[test]
    #[cfg(unix)]
    fn secure_output_files_are_private() {
        let dir = tempdir().expect("tempdir");
        let out_path = dir.path().join("out.json");
        let err_path = dir.path().join("err.log");

        create_secure_file(&out_path).expect("create out file");
        create_secure_file(&err_path).expect("create err file");

        for path in [&out_path, &err_path] {
            let mode = fs::metadata(path)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "path={}", path.display());
        }
    }
}
