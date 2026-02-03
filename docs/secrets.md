# Secrets handling

This is a public project. **No tribal knowledge**: secrets handling must be explicit, documented, and testable.

## Goals
- Support multiple deployment modes (Docker, systemd system, systemd user).
- Keep secrets out of source control.
- Provide a secure baseline (`secrets.env`) and a path to stronger secret managers.

## Supported secret sources

ACIP Sidecar reads secrets (API keys, auth token) from:

1) **Secrets env file** (`--secrets-file`)
   - Recommended system path: `/etc/acip/secrets.env`
   - Must be private (typical: parent dir 700-ish; file 600-ish)

2) **Process environment**
   - Useful for Docker, CI, and wrapper scripts

3) **External secret managers via helper (recommended for production-ish setups)**
   - OpenBao / 1Password / Bitwarden can be used via a small wrapper (`acip-secrets-helper`).
   - The helper fetches secrets and then `exec`s `acip-sidecar` with env vars set.
   - This avoids storing long-lived secrets in files.

> Note: the helper is optional. `secrets.env` remains a first-class supported option.

## Precedence / merge rules

Precedence is **explicit** and deterministic:

- `--secrets-file` values override process environment.
  - Rationale: explicit file is easier to audit and is intentionally opt-in.

When using `acip-secrets-helper`, the helper should set environment variables before exec.
Then the sidecar's normal precedence applies.

Recommended patterns:

### Pattern A (baseline): file only
- systemd runs:
  - `acip-sidecar --config /etc/acip/config.toml --secrets-file /etc/acip/secrets.env`

### Pattern B (preferred): helper + file fallback
- systemd runs:
  - `acip-secrets-helper --config /etc/acip/secrets-helper.toml -- \
     acip-sidecar --config /etc/acip/config.toml --secrets-file /etc/acip/secrets.env`

In Pattern B, the helper provides the primary secrets via env; `secrets.env` acts as an explicit override/fallback.

## Standard env keys

The sidecar recognizes (examples):
- `GEMINI_API_KEY`
- `ANTHROPIC_API_KEY`
- `ACIP_AUTH_TOKEN`

(See `docs/install.md` for an example `secrets.env`.)

## Security notes
- Never commit secrets.
- Avoid printing secrets in logs. If you add new logs, treat secret-bearing structs as sensitive.
- Prefer short-lived credentials from a secret manager when possible.
