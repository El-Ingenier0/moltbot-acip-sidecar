# acipctl (companion CLI)

`acipctl` is a small companion CLI so the sidecar is usable/configurable even when it runs inside Docker.

## Health check

```bash
acipctl --url http://127.0.0.1:18795 health
```

## Ingest

### File (PDF, HTML, etc.)

```bash
acipctl --url http://127.0.0.1:18795 ingest-file \
  --source-id demo \
  --source-type pdf \
  --content-type application/pdf \
  ./some.pdf
```

### Text via stdin

```bash
echo 'hello world' | acipctl --url http://127.0.0.1:18795 ingest-text \
  --source-id demo \
  --source-type other \
  --content-type text/plain
```

## Config management

`acipctl config` can print examples, validate, show raw TOML, and edit values.

### Print example

```bash
acipctl config example > /etc/acip/config.toml
```

### Validate

```bash
acipctl config validate --path /etc/acip/config.toml
```

### Show raw config

```bash
acipctl config show --path /etc/acip/config.toml
```

### Set / Unset

Key format: dotted paths (e.g. `server.unix_socket`, `policy.head`).

```bash
# Set and restart system service (default)
acipctl config set --path /etc/acip/config.toml server.port 18795

# Set without restarting
acipctl config set --path /etc/acip/config.toml policy.head 4000 --no-restart

# Unset a key
acipctl config unset --path /etc/acip/config.toml server.unix_socket
```

## Restart behavior

By default, `config set/unset` restarts the **systemd global** service.

You can override:

- `--restart system` (default)
- `--restart user` (systemd user service)
- `--restart docker-compose` (prints the compose restart command; does not execute)

Examples:

```bash
# user service
acipctl config set --path ~/.config/acip/config.toml policy.head 4000 --restart user

# docker compose (prints command)
acipctl config set --path ./config.toml policy.head 4000 \
  --restart docker-compose --compose-file docker-compose.yml --compose-service acip-sidecar
```
