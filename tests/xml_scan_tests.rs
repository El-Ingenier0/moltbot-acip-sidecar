use acip_sidecar::xml_scan;

#[test]
fn detects_doctype_and_entity() {
    let s = r#"<?xml version="1.0"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd"> 
]>
<svg><text>&xxe;</text></svg>"#;

    let r = xml_scan::scan(s);
    assert!(r.has_doctype);
    assert!(r.has_entity);
    assert!(r.severity >= 3);
    assert!(r.matches.iter().any(|m| m.contains("doctype")));
    assert!(r.matches.iter().any(|m| m.contains("entity")));
}

#[test]
fn detects_scriptish_and_external_refs() {
    let s = r#"<svg xmlns:xlink="http://www.w3.org/1999/xlink">
<script>alert(1)</script>
<a xlink:href="https://evil.com">x</a>
</svg>"#;

    let r = xml_scan::scan(s);
    assert!(r.has_scriptish);
    assert!(r.has_external_ref);
    assert!(r.severity >= 2);
}
