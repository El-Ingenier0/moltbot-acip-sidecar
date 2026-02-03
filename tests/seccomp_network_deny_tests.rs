#![cfg(target_os = "linux")]

use acip_sidecar::extract::{run_helper, ExtractKind, ExtractRequest, ExtractorError};
use serial_test::serial;
use std::time::Duration;

#[test]
#[serial]
fn extractor_seccomp_denies_network_syscalls_when_enabled() {
    // Point the parent at the test-built extractor binary.
    std::env::set_var("ACIP_EXTRACTOR_BIN", env!("CARGO_BIN_EXE_acip-extract"));

    // Enable seccomp in the parent pre_exec.
    std::env::set_var("ACIP_EXTRACTOR_SECCOMP", "1");

    // Tell the helper to run the self-test and fail with a marker.
    std::env::set_var("ACIP_EXTRACTOR_SELFTEST_NET", "1");

    let req = ExtractRequest {
        kind: ExtractKind::Svg,
        content_type: None,
        max_pages: None,
        dpi: None,
        max_output_chars: None,
    };

    let err = run_helper(&req, b"<svg></svg>", Duration::from_secs(10))
        .err()
        .expect("expected extractor to fail under selftest");

    match err {
        ExtractorError::NonZeroExit { stderr, .. } => {
            assert!(stderr.contains("seccomp_network_denied"), "stderr={stderr}");
        }
        other => panic!("unexpected error: {other:?}"),
    }

    // Avoid leaking env vars into other integration tests (tests run in parallel).
    std::env::remove_var("ACIP_EXTRACTOR_SECCOMP");
    std::env::remove_var("ACIP_EXTRACTOR_SELFTEST_NET");
}
