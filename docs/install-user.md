# Installation (Linux / systemd --user)

This option installs **ACIP sidecar as a user service** (no root required).

## Trade-offs

- ✅ Easy install (no sudo)
- ✅ Runs under your user account
- ❌ No dedicated service user isolation (the process has your user permissions)
- ✅ You still get the in-process mitigations + extractor rlimits/nice/no_new_privs

## Paths (recommended)

- Binary: `~/.local/bin/moltbot-acip-sidecar`
- Config: `~/.config/acip/config.toml`
- Secrets: `~/.config/acip/secrets.env` (mode 600)
- Policies (optional): `~/.config/acip/policies.json`

## Install

Build:

```bash
cargo build --release
```

Install binary:

```bash
install -d -m 0755 ~/.local/bin
install -m 0755 target/release/moltbot-acip-sidecar ~/.local/bin/moltbot-acip-sidecar
```

Config/secrets:

```bash
install -d -m 0700 ~/.config/acip
install -m 0644 config.example.toml ~/.config/acip/config.toml
install -m 0600 /dev/null ~/.config/acip/secrets.env
$EDITOR ~/.config/acip/secrets.env
```

Systemd user unit:

```bash
mkdir -p ~/.config/systemd/user
cp packaging/moltbot-acip-sidecar.user.service ~/.config/systemd/user/moltbot-acip-sidecar.service
systemctl --user daemon-reload
systemctl --user enable --now moltbot-acip-sidecar
```

Optional (keep running while logged out):

```bash
loginctl enable-linger $USER
```

Logs:

```bash
journalctl --user -u moltbot-acip-sidecar -f
```

## Extractor sandbox knobs (optional)

Same knobs as system install (see `docs/install.md`), typically set via `systemctl --user edit`:

- `ACIP_EXTRACTOR_TIMEOUT_SECS`
- `ACIP_EXTRACTOR_RLIMIT_AS_MB`
- `ACIP_EXTRACTOR_RLIMIT_NOFILE`
- `ACIP_EXTRACTOR_RLIMIT_FSIZE_MB`
- `ACIP_EXTRACTOR_NICE`
- `ACIP_EXTRACTOR_RLIMIT_NPROC` (opt-in)
- `ACIP_EXTRACTOR_TMPDIR` (optional)
- `ACIP_EXTRACTOR_SECCOMP` (optional; Linux): set to `1` to deny network-related syscalls in the extractor helper

## Smoke test

```bash
curl -sS http://127.0.0.1:18795/health
```
