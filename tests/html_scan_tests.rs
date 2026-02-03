use acip_sidecar::html_scan;

#[test]
fn detects_event_handlers_and_scriptish() {
    let s = r#"<div onmouseover="x()">hi</div><script>alert(1)</script><a href="javascript:alert(1)">x</a>"#;
    let r = html_scan::scan(s);
    assert!(r.has_event_handler);
    assert!(r.has_scriptish);
    assert!(r.severity > 0);
    assert!(r.matches.iter().any(|m| m == "on_attr"));
    assert!(r.matches.iter().any(|m| m == "script_tag"));
    assert!(r.matches.iter().any(|m| m == "javascript_uri"));
}
