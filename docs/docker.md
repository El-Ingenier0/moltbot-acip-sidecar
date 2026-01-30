# Container runtime (Docker / Podman)

Goal: run `moltbot-acip-sidecar` with **PDF/SVG extraction enabled** (Poppler + Tesseract) in a container.

## Build

```bash
docker build -t acip-sidecar:latest .
```

Podman:

```bash
podman build -t acip-sidecar:latest .
```

## Run (Docker)

Mount your config + secrets:

```bash
docker run --rm \
  -p 127.0.0.1:18795:18795 \
  -v /etc/acip/config.toml:/etc/acip/config.toml:ro \
  -v /etc/acip/secrets.env:/etc/acip/secrets.env:ro \
  -e ACIP_SENTRY_MODE=stub \
  acip-sidecar:latest
```

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
