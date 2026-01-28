use moltbot_acip_sidecar::secrets;
use moltbot_acip_sidecar::secrets::SecretStore;
use moltbot_acip_sidecar::state;
use std::fs;
use tempfile::tempdir;

fn apply_head_tail(policy: &state::Policy, text: &str) -> (String, bool) {
    let len = text.chars().count();
    if len <= policy.full_if_lte {
        return (text.to_string(), false);
    }
    let head: String = text.chars().take(policy.head).collect();
    let tail: String = text
        .chars()
        .rev()
        .take(policy.tail)
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    (format!("{}\n\n[...TRUNCATED...]\n\n{}", head, tail), true)
}

#[test]
fn truncation_not_triggered_when_under_threshold() {
    let p = state::Policy {
        head: 4,
        tail: 4,
        full_if_lte: 10,
    };
    let (out, truncated) = apply_head_tail(&p, "hello");
    assert!(!truncated);
    assert_eq!(out, "hello");
}

#[test]
fn truncation_triggered_when_over_threshold() {
    let p = state::Policy {
        head: 4,
        tail: 4,
        full_if_lte: 6,
    };
    let (out, truncated) = apply_head_tail(&p, "abcdefghijklmnop");
    assert!(truncated);
    assert!(out.starts_with("abcd"));
    assert!(out.contains("[...TRUNCATED...]"));
    assert!(out.ends_with("mnop"));
}

#[test]
fn secrets_file_permissions_enforced() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("secrets.env");
    fs::write(&path, "KEY=value\n").unwrap();

    // Make parent dir private and file too-open.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        let err = secrets::EnvFileStore::load(&path).err().expect("expected error");
        let msg = format!("{err:#}");
        assert!(msg.contains("permissions too open"));

        // Now make file private too.
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let store = secrets::EnvFileStore::load(&path).unwrap();
        assert_eq!(store.get("KEY").unwrap(), "value");
    }
}
