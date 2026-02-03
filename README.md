# acip-sidecar

**ACIP Sidecar**: a reusable ingestion/sentry sidecar service that enforces the invariant:

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
- v0.2: model sentry (L1 → L2 fallback) + strict JSON schema + PDF/SVG sandbox extraction

## Secrets
For development you can use a local `.env` file (gitignored) *if* it is private:
- parent directory permissions: **700-ish** (no group/other access)
- file permissions: **600-ish** (no group/other access)

Run with:
```bash
cargo run -- --secrets-file ./.env
```

For system installs, prefer `/etc/acip/secrets.env`.

Secrets resolution order when `--secrets-file` is provided:
1) secrets file
2) process environment

## CLI (configuration + exercise)

`acipctl` is a small companion CLI so the sidecar is fully configurable/usable even when it runs in Docker.

Examples:
```bash
# Print example config
acipctl config example > /etc/acip/config.toml

# Validate config
acipctl config validate --path /etc/acip/config.toml

# Health check
acipctl --url http://127.0.0.1:18795 health

# Ingest a PDF (prints JSON response)
acipctl --url http://127.0.0.1:18795 ingest-file \
  --source-id demo \
  --source-type pdf \
  --content-type application/pdf \
  ./some.pdf
```

## API (draft)
See `docs/api.md`.

## Security
- **Never** commit API keys.
- Sidecar is designed for `127.0.0.1` only by default.
- Treat all inputs as untrusted.

## Loopback security behavior

By default, when binding to loopback (e.g. `127.0.0.1`) the sidecar allows requests without `X-ACIP-Token`.

To force token auth even on loopback, set in `config.toml`:

```toml
[security]
allow_insecure_loopback = false
require_token = true
token_env = "ACIP_AUTH_TOKEN"
```
