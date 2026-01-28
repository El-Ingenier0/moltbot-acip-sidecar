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
- [x] **Centralize router construction** (avoid duplication between main/tests; easier future security hardening).
- [x] **Improve JSON extraction** in `sentry::extract_json_only` (current brace-slicing is brittle); consider strict JSON mode or a more robust parser strategy.
- [x] **Reduce prompt bloat**: `DecisionEngine::build_prompt` includes full schema each call; consider caching schema text or using shorter schema reference.

## Security follow-ups (post-MVP)
- [ ] **Safe PDF/SVG ingestion architecture**: if/when we add PDF rendering or SVG parsing, run it in a separate sandboxed process (no network, tight CPU/mem/time limits) to mitigate parser/rendering memory-corruption risk; then treat extracted text as untrusted (prompt-injection).

## MVP+: safer HTML/SVG handling before model exposure
- [x] **Add content normalization pipeline**: keep original raw for digest/audit, but generate a separate `model_text` for sentry decisions.
- [x] **HTML → structured text conversion** (minimally lossy): convert HTML to readable text/markdown-ish while preserving headings/lists/links as best we can.
- [x] **Drop active HTML content**: ensure scripts/styles/iframes don’t make it into model_text; remove obvious JS URLs (e.g. `javascript:`).
- [ ] **SVG input handling**: treat as markup; extract visible text nodes only (no script) into model_text.
- [ ] **Plumb audit metadata**: add response fields indicating `normalized=true`, original/extracted lengths, and a list of removed elements/patterns.
- [ ] **Tests**: add fixtures for HTML with script prompt injection and ensure model_text excludes script content.

## P3 (low)
- [x] **Make `config.example.toml` match actual config schema fully** (document remaining keys as added).
- [x] **Docs**: explain loopback default behavior and how token requirement changes when `allow_insecure_loopback=false`.
