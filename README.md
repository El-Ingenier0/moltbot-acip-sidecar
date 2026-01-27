# moltbot-acip-sidecar

**MoltBot ACIP Sidecar**: an ingestion/sentry sidecar service that enforces the invariant:

> Only *sentry-fenced* content may be appended to the model context, regardless of acquisition method.

This repo is intended to be a small localhost HTTP service (Rust) that:
- accepts external content (HTML/PDF/text) via a single `ingest_source` endpoint
- applies deterministic truncation (head/tail + optional section selection)
- runs a **two-tier** model policy (configurable):
  - **L1 (cheap-first):** defaults to Gemini Flash (`gemini-2.0-flash`)
  - **L2 (fallback):** defaults to Anthropic Haiku (`claude-3-5-haiku-latest`)
- returns only:
  - `fenced_content` (safe to append)
  - `tools_allowed` (hard gate for tool dispatcher)
  - audit metadata (hashes, lengths, flags)

## Status
- v0.1: running axum server + deterministic truncation + fenced output
- v0.2 (next): model sentry (Gemini Flash L1 → Haiku L2 fallback) + strict JSON schema

## Secrets
For development you can use a local `.env` file (gitignored) *if* it is private:
- parent directory permissions: **700-ish** (no group/other access)
- file permissions: **600-ish** (no group/other access)

Run with:
```bash
cargo run -- --dotenv ./.env
```

Secrets resolution order when `--dotenv` is provided:
1) `.env`
2) process environment

## API (draft)
See `docs/api.md`.

## Security
- **Never** commit API keys.
- Sidecar is designed for `127.0.0.1` only by default.
- Treat all inputs as untrusted.
