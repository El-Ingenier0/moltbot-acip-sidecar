# Container runtime (Docker / Podman)

Goal: run `acip-sidecar` with **PDF/SVG extraction enabled** (Poppler + Tesseract) in a container.

## Build

```bash
docker build -t acip-sidecar:latest .
```

Podman:

```bash
podman build -t acip-sidecar:latest .
```

## Run (Docker)

### Minimal `docker run`

Mount your config + secrets:

```bash
docker run --rm \
  -p 127.0.0.1:18795:18795 \
  -v /etc/acip/config.toml:/etc/acip/config.toml:ro \
  -v /etc/acip/secrets.env:/etc/acip/secrets.env:ro \
  -e ACIP_SENTRY_MODE=stub \
  acip-sidecar:latest
```

### Docker Compose (recommended)

If you prefer an interactive generator, use:

```bash
sudo ./scripts/install --mode docker
```

Example `docker-compose.yml` snippet:

```yaml
services:
  acip-sidecar:
    image: acip-sidecar:latest
    ports:
      - "127.0.0.1:18795:18795"
    environment:
      # Set to "live" when you have keys configured.
      - ACIP_SENTRY_MODE=stub

      # NOTE: When using live mode, set model policy explicitly.

      # Model policy (optional). Defaults shown:
      - ACIP_L1_PROVIDER=gemini
      - ACIP_L1_MODEL=gemini-2.0-flash
      - ACIP_L2_PROVIDER=anthropic
      - ACIP_L2_MODEL=claude-3-5-haiku-latest
    volumes:
      - /etc/acip/config.toml:/etc/acip/config.toml:ro
      - /etc/acip/secrets.env:/etc/acip/secrets.env:ro
    # Strong isolation if you can tolerate it (prevents outbound model calls):
    # network_mode: "none"
```

Notes:
- The container defaults to `--config /etc/acip/config.toml` (see Dockerfile CMD).
- For compose-based deployments, `acipctl config set --restart docker-compose` prints the restart command.

### Live vs stub mode (network implications)

- `ACIP_SENTRY_MODE=stub` performs no external model calls. It is compatible with `--network=none`.
- `ACIP_SENTRY_MODE=live` performs external model calls. **Do not use** `--network=none` (or `network_mode: none`) unless you intentionally want all model calls to fail.

Recommendation:
- If you want the strongest isolation but still need live mode, prefer:
  - host firewall rules / egress allowlisting, and/or
  - the extractor's optional seccomp-deny-network mode (`ACIP_EXTRACTOR_SECCOMP=1`) to ensure the extractor helper cannot make network syscalls.

### No-network mode (recommended)

If you want *container-level* no-network (strong and simple):

```bash
docker run --rm --network=none \
  -p 127.0.0.1:18795:18795 \
  -v /etc/acip/config.toml:/etc/acip/config.toml:ro \
  -v /etc/acip/secrets.env:/etc/acip/secrets.env:ro \
  acip-sidecar:latest
```

## Run (Podman, rootless)

```bash
podman run --rm \
  -p 127.0.0.1:18795:18795 \
  -v /etc/acip/config.toml:/etc/acip/config.toml:ro \
  -v /etc/acip/secrets.env:/etc/acip/secrets.env:ro \
  -e ACIP_SENTRY_MODE=stub \
  acip-sidecar:latest
```

No-network:

```bash
podman run --rm --network=none \
  -p 127.0.0.1:18795:18795 \
  -v /etc/acip/config.toml:/etc/acip/config.toml:ro \
  -v /etc/acip/secrets.env:/etc/acip/secrets.env:ro \
  acip-sidecar:latest
```

## Extractor knobs

The image sets:
- `ACIP_EXTRACTOR_BIN=/opt/acip/acip-extract`

You can tune limits via env:
- `ACIP_EXTRACTOR_TIMEOUT_SECS`
- `ACIP_EXTRACTOR_RLIMIT_AS_MB`
- `ACIP_EXTRACTOR_RLIMIT_NOFILE`
- `ACIP_EXTRACTOR_RLIMIT_FSIZE_MB`
- `ACIP_EXTRACTOR_NICE`
- `ACIP_EXTRACTOR_RLIMIT_NPROC` (opt-in)
- `ACIP_EXTRACTOR_TMPDIR` (optional)
- `ACIP_EXTRACTOR_SECCOMP=1` (optional; Linux): deny network syscalls inside the extractor helper (image includes `libseccomp2`)

## Smoke test

```bash
curl -sS http://127.0.0.1:18795/health
```
