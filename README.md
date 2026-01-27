# moltbot-acip-sidecar

**MoltBot ACIP Sidecar**: an ingestion/sentry sidecar service that enforces the invariant:

> Only *sentry-fenced* content may be appended to the model context, regardless of acquisition method.

This repo is intended to be a small localhost HTTP service (Rust) that:
- accepts external content (HTML/PDF/text) via a single `ingest_source` endpoint
- applies deterministic truncation (head/tail + optional section selection)
- runs a **two-tier** model policy:
  - **L1:** Gemini Flash (cheap-first)
  - **L2:** Anthropic Haiku (fallback when L1 fails / bad JSON / schema violation)
- returns only:
  - `fenced_content` (safe to append)
  - `tools_allowed` (hard gate for tool dispatcher)
  - audit metadata (hashes, lengths, flags)

## Status
This is a scaffold + spec. Rust implementation will land once the toolchain is installed.

## API (draft)
See `docs/api.md`.

## Security
- **Never** commit API keys.
- Sidecar is designed for `127.0.0.1` only by default.
- Treat all inputs as untrusted.
