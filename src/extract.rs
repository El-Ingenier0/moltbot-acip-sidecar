use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    io::Write,
    process::{Command, Stdio},
    time::Duration,
};
use tempfile::tempdir;

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
                let out = Command::new("tesseract")
                    .arg(img.as_os_str())
                    .arg("stdout")
                    .arg("-l")
                    .arg("eng")
                    .arg("--dpi")
                    .arg(format!("{dpi}"))
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .output()
                    .context("run tesseract")?;

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
    let raw = String::from_utf8(bytes.to_vec()).map_err(|_| anyhow!("svg must be utf-8"))?;

    // Use existing xml scan + text-node extraction logic. (Sandboxing will be the safety boundary.)
    let scan = crate::xml_scan::scan(&raw);

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

/// Spawn the external extractor helper (`acip-extract`) and return its JSON response.
///
/// Linux-only v1: this is a wrapper point where we will add seccomp/namespaces.
pub fn run_helper(
    req: &ExtractRequest,
    bytes: &[u8],
    timeout: Duration,
) -> Result<ExtractResponse> {
    let mut child = Command::new("acip-extract")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("spawn acip-extract")?;

    let stdin = child
        .stdin
        .as_mut()
        .ok_or_else(|| anyhow!("missing stdin"))?;

    // protocol: first line is JSON request, then raw bytes.
    let header = serde_json::to_string(req).context("serialize request")?;
    stdin.write_all(header.as_bytes()).context("write header")?;
    stdin.write_all(b"\n").context("write header newline")?;
    stdin.write_all(bytes).context("write payload")?;

    // Drop stdin to signal EOF.
    drop(child.stdin.take());

    // Wait with a timeout (best-effort). We implement timeout outside via tokio in HTTP handler.
    // Here we just block; caller can place this in spawn_blocking + timeout.
    let out = child.wait_with_output().context("wait acip-extract")?;

    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        return Err(anyhow!("acip-extract failed: {}", err.trim()));
    }

    let resp: ExtractResponse =
        serde_json::from_slice(&out.stdout).context("parse extract json")?;
    // silence unused warning for timeout param until we wire tokio timeout here.
    let _ = timeout;
    Ok(resp)
}
