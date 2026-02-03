use aho_corasick::AhoCorasick;

#[derive(Debug, Clone, Default)]
pub struct HtmlScanResult {
    pub has_scriptish: bool,
    pub has_event_handler: bool,
    pub has_external_ref: bool,
    pub has_data_uri: bool,
    pub has_embed: bool,
    pub has_meta_refresh: bool,
    pub matches: Vec<String>,

    /// Simple heuristic score for "this HTML/SVG is suspicious / potentially dangerous".
    /// This is NOT a security boundary; sandboxing + limits remain the real defense.
    pub severity: u8,
}

static PATTERNS: &[(&str, &str)] = &[
    ("script_tag", "<script"),
    ("javascript_uri", "javascript:"),
    ("onload", "onload="),
    ("onerror", "onerror="),
    ("onclick", "onclick="),
    ("http", "http://"),
    ("https", "https://"),
    ("data_uri", "data:"),
    ("src", "src="),
    ("href", "href="),
    ("xlink_href", "xlink:href="),
    ("iframe_tag", "<iframe"),
    ("object_tag", "<object"),
    ("embed_tag", "<embed"),
    ("meta_refresh", "<meta http-equiv=refresh"),
];

fn matcher() -> AhoCorasick {
    // Case-insensitive, ASCII.
    let pats: Vec<&str> = PATTERNS.iter().map(|(_, p)| *p).collect();
    AhoCorasick::builder()
        .ascii_case_insensitive(true)
        .build(pats)
        .expect("aho-corasick patterns must compile")
}

fn has_generic_on_attr(lower: &[u8]) -> bool {
    if lower.len() < 4 {
        return false;
    }

    let mut i = 0;
    while i + 3 < lower.len() {
        if lower[i] == b'o' && lower[i + 1] == b'n' && lower[i + 2].is_ascii_alphabetic() {
            let mut j = i + 2;
            while j < lower.len() && lower[j].is_ascii_alphabetic() {
                j += 1;
            }
            if j < lower.len() && lower[j] == b'=' {
                return true;
            }
        }
        i += 1;
    }

    false
}

/// Cheap pre-parse scan of HTML/SVG-ish input to flag common red flags.
///
/// This is intentionally shallow: it looks for well-known tokens like `<script` / `onload=`
/// and obvious external references. It should run before any HTML parsing in the sandbox helper.
pub fn scan(input: &str) -> HtmlScanResult {
    let mut out = HtmlScanResult::default();
    if input.is_empty() {
        return out;
    }

    let ac = matcher();
    for m in ac.find_iter(input.as_bytes()) {
        let idx = m.pattern().as_usize();
        let (name, _pat) = PATTERNS[idx];
        out.matches.push(name.to_string());

        match name {
            "script_tag" | "javascript_uri" => out.has_scriptish = true,
            "onload" | "onerror" | "onclick" => out.has_event_handler = true,
            "http" | "https" => out.has_external_ref = true,
            "data_uri" => {
                out.has_data_uri = true;
                out.has_external_ref = true;
            }
            "iframe_tag" | "object_tag" | "embed_tag" => out.has_embed = true,
            "meta_refresh" => out.has_meta_refresh = true,
            _ => {}
        }
    }

    let lower: Vec<u8> = input.as_bytes().iter().map(|b| b.to_ascii_lowercase()).collect();
    if has_generic_on_attr(&lower) {
        out.has_event_handler = true;
        out.matches.push("on_attr".to_string());
    }

    // Deduplicate match names.
    out.matches.sort();
    out.matches.dedup();

    // Severity heuristic.
    // (Sandboxing + rlimits remain the real safety boundary.)
    let mut sev: u8 = 0;
    if out.has_scriptish {
        sev = sev.saturating_add(2);
    }
    if out.has_event_handler {
        sev = sev.saturating_add(2);
    }
    if out.has_embed {
        sev = sev.saturating_add(2);
    }
    if out.has_meta_refresh {
        sev = sev.saturating_add(1);
    }
    if out.has_data_uri {
        sev = sev.saturating_add(1);
    }
    if out.has_external_ref {
        sev = sev.saturating_add(1);
    }
    out.severity = sev;

    out
}
