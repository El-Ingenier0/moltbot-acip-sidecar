# Installation (Linux / systemd)

This service is intended to run as a small localhost HTTP daemon.

## Paths (convention)

- Config: `/etc/acip/config.toml`
- Secrets: `/etc/acip/secrets.env` (permissions must be private)
- Policies: `/etc/acip/policies.json` (non-secret)

## Prerequisites

- Rust toolchain (for building): `cargo`, `rustc`
- systemd (for service install)
- Optional (only if you want to bind a privileged port <1024 while still running unprivileged): `setcap` (Debian/Ubuntu: `libcap2-bin`)

## Quick install (recommended)

Use the installer script (it will build, install, create config + secrets files if missing, install systemd unit, and start the service).

```bash
git clone https://github.com/El-Ingenier0/acip-sidecar.git
cd acip-sidecar

# Defaults:
#   --port 18795
#   --user acip_user --group acip_user
#   --l1-model gemini-2.0-flash
#   --l2-model claude-3-5-haiku-latest
sudo ./scripts/install.sh
```

Common overrides:

```bash
sudo ./scripts/install.sh \
  --port 18795 \
  --user acip_user --group acip_user \
  --l1-model gemini-2.0-flash \
  --l2-model claude-3-5-haiku-latest
```

Notes:
- On first install, the script will prompt (hidden input) for `GEMINI_API_KEY`, `ANTHROPIC_API_KEY`, and `ACIP_AUTH_TOKEN` and write them to `/etc/acip/secrets.env` (0600).
- If you set `--port < 1024`, the installer will attempt to grant `CAP_NET_BIND_SERVICE` to `/opt/acip/acip-sidecar` via `setcap` so the service can still run as an unprivileged user.

## Manual build

```bash
git clone https://github.com/El-Ingenier0/acip-sidecar.git
cd acip-sidecar
cargo build --release
```

Binary will be at:

- `target/release/acip-sidecar`

## Manual install (if you don't use the installer)

### Create service user/group

```bash
sudo useradd --system --home /nonexistent --shell /usr/sbin/nologin acip_user || true
sudo groupadd --system acip_user || true
sudo usermod -a -G acip_user acip_user || true
```

## Install files

```bash
sudo install -d -m 0755 /opt/acip
sudo install -m 0755 target/release/acip-sidecar /opt/acip/acip-sidecar

sudo install -d -m 0755 /etc/acip
sudo install -m 0644 config.example.toml /etc/acip/config.toml

# Optional policies (non-secret)
# sudo install -m 0644 ./policies.example.json /etc/acip/policies.json
```

### Secrets file

Create `/etc/acip/secrets.env` with mode 600 and owned by root (or the service user).

Example:

```bash
sudo install -m 0600 /dev/null /etc/acip/secrets.env
sudoedit /etc/acip/secrets.env
```

Contents (example):

```bash
# Required for live sentry mode:
GEMINI_API_KEY=...
ANTHROPIC_API_KEY=...

# Auth token for callers (optional, but recommended)
ACIP_AUTH_TOKEN=...
```

## Install systemd unit

> If you used `scripts/install.sh`, this is already done.

Copy the unit template:

```bash
sudo install -m 0644 packaging/acip-sidecar.service /etc/systemd/system/acip-sidecar.service
sudo systemctl daemon-reload
sudo systemctl enable --now acip-sidecar
```

Check logs:

```bash
journalctl -u acip-sidecar -f
```

## Smoke test

Health (TCP):

```bash
curl -sS http://127.0.0.1:18795/health
```

Health (Unix socket):

```bash
# Requires curl built with --unix-socket support
curl --unix-socket /run/acip/acip-sidecar.sock -sS http://localhost/health
```

Ingest (token optional depending on config):

```bash
curl -sS \
  -H 'Content-Type: application/json' \
  -H 'X-ACIP-Token: <token>' \
  -d '{
    "source_id":"demo",
    "source_type":"other",
    "content_type":"text/plain",
    "text":"hello world"
  }' \
  http://127.0.0.1:18795/v1/acip/ingest_source | jq
```

## Extractor overview

For PDF/SVG inputs the sidecar uses an **out-of-process extractor** helper.

Why:
- parsing/rendering complex formats is a large attack surface
- running the extractor out-of-process allows tighter resource limits and (optional) syscall filtering

At a high level:
- sidecar receives bytes (or text)
- for PDF/SVG it invokes `acip-extract` in a sandboxed subprocess
- extracted text is then normalized and evaluated by the sentry policy

## Sandbox/extractor knobs (optional)

These env vars tune the **out-of-process extractor** (PDF/SVG hybrid extraction):

- `ACIP_EXTRACTOR_BIN` (default: `acip-extract`): path to extractor helper
- `ACIP_EXTRACTOR_TIMEOUT_SECS` (default: `180`): wall timeout for extractor
- `ACIP_EXTRACTOR_RLIMIT_AS_MB` (default: `2048`): max address space
- `ACIP_EXTRACTOR_RLIMIT_NOFILE` (default: `64`): max open fds
- `ACIP_EXTRACTOR_RLIMIT_FSIZE_MB` (default: `512`): max file size helper may create
- `ACIP_EXTRACTOR_NICE` (default: `10`): niceness increment
- `ACIP_EXTRACTOR_RLIMIT_NPROC` (optional): cap processes/threads (opt-in; can break some tools)
- `ACIP_EXTRACTOR_TMPDIR` (optional): override temp directory for extractor (OCR writes images here)
- `ACIP_EXTRACTOR_SECCOMP` (optional; Linux): set to `1` to deny network-related syscalls in the extractor helper (default allowlist otherwise). Requires libseccomp (`libseccomp2`, `libseccomp-dev`).

## Notes

- `ACIP_SENTRY_MODE=stub` disables model calls; `tools_allowed` stays false.
- For HTML/SVG inputs, tools are hard-capped off by design.
- Secrets handling is documented in `docs/secrets.md` (supported sources + precedence).
