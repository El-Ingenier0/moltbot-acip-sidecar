# Troubleshooting

This service is intentionally small, but it touches a lot of sharp edges (systemd, containers, PDF tooling, sandbox limits).

## Where are the logs?

### systemd (global)

```bash
journalctl -u acip-sidecar -f
```

### systemd (user)

```bash
journalctl --user -u acip-sidecar -f
```

### Docker

```bash
docker logs -f <container>
```

## Quick health checks

### HTTP (TCP)

```bash
curl -sS http://127.0.0.1:18795/health
```

### Unix socket

```bash
curl --unix-socket /run/acip/acip-sidecar.sock -sS http://localhost/health
```

## Common problems

### 1) 401 / unauthorized (token required)

Symptoms:
- Requests to `/v1/acip/ingest_source` fail with 401/403.

Check:
- Are you sending `X-ACIP-Token: ...`?
- Does your `config.toml` require token auth?

See:
- `docs/api.md` (Request headers)
- `README.md` (loopback security behavior)

### 2) Extractor timeout / hangs

Symptoms:
- Requests involving PDFs/SVGs take a long time or fail.
- Logs mention extractor timeout.

Knobs:
- `ACIP_EXTRACTOR_TIMEOUT_SECS`
- `ACIP_EXTRACTOR_RLIMIT_AS_MB`
- `ACIP_EXTRACTOR_RLIMIT_FSIZE_MB`

See:
- `docs/install.md` (Sandbox/extractor knobs)

### 3) “No such file or directory” for unix socket

Symptoms:
- Curl to the unix socket path fails.

Check:
- Does the parent directory exist and is it writable by the service user?
- If using systemd global, prefer `/run/acip/acip-sidecar.sock` and ensure `/run/acip` exists (tmpfiles.d or unit pre-start).

### 4) Docker can’t read /etc/acip/secrets.env

Symptoms:
- Container starts but sidecar fails to read secrets file.

Check:
- Is the file mounted into the container?
- Does it have correct permissions (readable by the container user)?

Note:
- `secrets.env` should be private on host. In Docker, you may prefer injecting env vars through compose instead of bind-mounting the file.

## Reporting issues

When filing issues, include:
- install mode (systemd global/user or docker)
- config snippet (redact secrets)
- relevant logs from startup through failure
