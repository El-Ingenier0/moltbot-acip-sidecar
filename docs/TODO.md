# TODOs (Claude code review)

Legend: **P0** = critical, **P1** = high, **P2** = medium, **P3** = low.

## P0 (critical)
- [x] **Fix Rust partial-move bug in `ingest_source`**: current code moves `req.text`/`req.bytes_b64` and later uses `req.*` for `source_meta`. This should be refactored to destructure `IngestRequest` once into locals before selecting `raw`.

## P1 (high)
- [x] **Add request size limits / body limits** for `ingest_source` (prevent DoS via huge JSON / base64 payloads). Consider axum `DefaultBodyLimit` + explicit max bytes for `bytes_b64`.
- [x] **Add timeouts to outbound HTTP model calls** (`reqwest::Client::builder().timeout(...)`, connect/read timeouts). Prevent hangs.
- [x] **Token auth robustness**: treat multiple `X-ACIP-Token` headers / whitespace / non-UTF8 consistently; decide whether to allow bearer format. Consider constant-time compare (minor, but easy).

## P2 (medium)
- [x] **Use config values for `policies_file`** instead of `let _ = ...` placeholder; i.e., make config authoritative default while CLI overrides.
- [ ] **Centralize router construction** (avoid duplication between main/tests; easier future security hardening).
- [x] **Improve JSON extraction** in `sentry::extract_json_only` (current brace-slicing is brittle); consider strict JSON mode or a more robust parser strategy.
- [ ] **Reduce prompt bloat**: `DecisionEngine::build_prompt` includes full schema each call; consider caching schema text or using shorter schema reference.

## P3 (low)
- [ ] **Make `config.example.toml` match actual config schema fully** (document remaining keys as added).
- [ ] **Docs**: explain loopback default behavior and how token requirement changes when `allow_insecure_loopback=false`.
