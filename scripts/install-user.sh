#!/usr/bin/env bash
set -euo pipefail

# Best-effort user-mode installer.
# - Builds release binary
# - Installs to ~/.local/bin
# - Writes ~/.config/acip/config.toml if missing
# - Creates ~/.config/acip/secrets.env if missing
# - Installs systemd user unit

PREFIX_BIN="$HOME/.local/bin"
ETC_DIR="$HOME/.config/acip"
UNIT_SRC="packaging/acip-sidecar.user.service"
UNIT_DST="$HOME/.config/systemd/user/acip-sidecar.service"

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Missing required command: $1" >&2
    exit 1
  }
}

main() {
  need_cmd systemctl
  need_cmd install

  if ! command -v cargo >/dev/null 2>&1; then
    echo "cargo not found. Install Rust toolchain first." >&2
    exit 1
  fi

  echo "WARNING: Installing as a *user* service trades away key isolation hardening." 
  echo "- The sidecar and extractor run with your user permissions (no dedicated service user)." 
  echo "- Best isolation/hardening requires the system service install (root) running as user 'acip_user'." 
  echo "Proceeding with user-mode install..."
  echo

  echo "[1/5] Building release binary"
  cargo build --release

  echo "[2/5] Installing binary to ${PREFIX_BIN}"
  install -d -m 0755 "${PREFIX_BIN}"
  install -m 0755 target/release/acip-sidecar "${PREFIX_BIN}/acip-sidecar"

  echo "[3/5] Ensuring ${ETC_DIR} exists"
  install -d -m 0700 "${ETC_DIR}"

  if [[ ! -f "${ETC_DIR}/config.toml" ]]; then
    echo "Writing ${ETC_DIR}/config.toml from config.example.toml"
    install -m 0644 config.example.toml "${ETC_DIR}/config.toml"
  else
    echo "Leaving existing ${ETC_DIR}/config.toml in place"
  fi

  if [[ ! -f "${ETC_DIR}/secrets.env" ]]; then
    echo "Creating empty ${ETC_DIR}/secrets.env (YOU MUST FILL THIS IN)"
    install -m 0600 /dev/null "${ETC_DIR}/secrets.env"
  fi

  echo "[4/5] Installing systemd user unit"
  install -d -m 0755 "$HOME/.config/systemd/user"
  install -m 0644 "${UNIT_SRC}" "${UNIT_DST}"

  systemctl --user daemon-reload

  echo "[5/5] Enabling and starting service"
  systemctl --user enable --now acip-sidecar

  echo "Done. Next steps:"
  echo "- Edit ${ETC_DIR}/secrets.env (API keys + ACIP_AUTH_TOKEN)"
  echo "- Restart: systemctl --user restart acip-sidecar"
  echo "- Logs: journalctl --user -u acip-sidecar -f"
  echo "- Health: curl -sS http://127.0.0.1:18795/health"
  echo "- Optional: keep running after logout: loginctl enable-linger $USER"
}

main "$@"
