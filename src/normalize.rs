use html5ever::tendril::TendrilSink;
use html5ever::parse_document;
use markup5ever_rcdom::{Handle, NodeData, RcDom};

pub const DEFAULT_MAX_OUTPUT_CHARS: usize = 200_000;

pub fn html_to_text_html5ever(html: &str) -> String {
    html_to_text_html5ever_with_limit(html, DEFAULT_MAX_OUTPUT_CHARS)
}

pub fn html_to_text_html5ever_with_limit(html: &str, max_chars: usize) -> String {
    if max_chars == 0 {
        return String::new();
    }

    let dom = match parse_document(RcDom::default(), Default::default())
        .from_utf8()
        .read_from(&mut html.as_bytes())
    {
        Ok(dom) => dom,
        Err(_) => return String::new(),
    };

    let mut state = WalkState::new(max_chars);
    walk_dom(&dom.document, &mut state);
    state.finish()
}

struct WalkState {
    out: String,
    max_chars: usize,
    char_count: usize,
    last_space: bool,
    last_newline: bool,
    truncated: bool,
}

impl WalkState {
    fn new(max_chars: usize) -> Self {
        Self {
            out: String::new(),
            max_chars,
            char_count: 0,
            last_space: false,
            last_newline: false,
            truncated: false,
        }
    }

    fn finish(self) -> String {
        self.out.trim().to_string()
    }

    fn push_char(&mut self, ch: char) {
        if self.truncated || self.char_count >= self.max_chars {
            self.truncated = true;
            return;
        }
        self.out.push(ch);
        self.char_count += 1;
        if self.char_count >= self.max_chars {
            self.truncated = true;
        }
    }

    fn push_newline(&mut self) {
        if self.truncated {
            return;
        }
        if self.last_newline || self.out.is_empty() {
            self.last_space = false;
            self.last_newline = true;
            return;
        }
        if self.last_space {
            self.out.pop();
            if self.char_count > 0 {
                self.char_count -= 1;
            }
        }
        self.push_char('\n');
        self.last_newline = true;
        self.last_space = false;
    }

    fn push_text(&mut self, text: &str) {
        if self.truncated {
            return;
        }
        for ch in text.chars() {
            if self.truncated {
                break;
            }
            if ch.is_whitespace() {
                if self.last_newline {
                    continue;
                }
                if !self.last_space {
                    self.push_char(' ');
                    self.last_space = true;
                    self.last_newline = false;
                }
            } else {
                self.push_char(ch);
                self.last_space = false;
                self.last_newline = false;
            }
        }
    }
}

fn walk_dom(handle: &Handle, state: &mut WalkState) {
    if state.truncated {
        return;
    }

    match &handle.data {
        NodeData::Document => {
            for child in handle.children.borrow().iter() {
                if state.truncated {
                    break;
                }
                walk_dom(child, state);
            }
        }
        NodeData::Element { name, .. } => {
            let tag = name.local.as_ref();
            if is_skip_tag(tag) {
                return;
            }
            if tag == "br" {
                state.push_newline();
                return;
            }
            if is_block_tag(tag) {
                state.push_newline();
            }
            for child in handle.children.borrow().iter() {
                if state.truncated {
                    break;
                }
                walk_dom(child, state);
            }
            if is_block_tag(tag) {
                state.push_newline();
            }
        }
        NodeData::Text { contents } => {
            state.push_text(&contents.borrow());
        }
        _ => {
            for child in handle.children.borrow().iter() {
                if state.truncated {
                    break;
                }
                walk_dom(child, state);
            }
        }
    }
}

fn is_skip_tag(tag: &str) -> bool {
    matches!(tag, "script" | "style" | "iframe" | "object" | "embed" | "noscript")
}

fn is_block_tag(tag: &str) -> bool {
    matches!(
        tag,
        "p" | "div" | "li" | "h1" | "h2" | "h3" | "h4" | "h5" | "h6"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn html_normalization_drops_script_and_style() {
        let html = r#"<html><head><style>.x{color:red}</style></head><body><script>IGNORE</script><p>Hello</p></body></html>"#;
        let out = html_to_text_html5ever(html);
        assert!(out.contains("Hello"));
        assert!(!out.contains("IGNORE"));
        assert!(!out.contains("color"));
    }

    #[test]
    fn html_normalization_preserves_visible_text() {
        let html = r#"<div>Hello <span>world</span>!</div>"#;
        let out = html_to_text_html5ever(html);
        assert!(out.contains("Hello"));
        assert!(out.contains("world"));
        assert!(out.contains("!"));
    }

    #[test]
    fn html_normalization_caps_output() {
        let html = format!("<p>{}</p>", "a".repeat(100));
        let out = html_to_text_html5ever_with_limit(&html, 10);
        assert!(out.chars().count() <= 10);
    }
}
