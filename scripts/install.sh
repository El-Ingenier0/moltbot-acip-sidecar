#!/usr/bin/env bash
set -euo pipefail

# Best-effort installer for Linux/systemd.
# - Builds release binary
# - Installs to /opt/acip
# - Creates /etc/acip + writes config.toml if missing
# - Installs systemd unit
# - Creates system user/group (acip_user)

APP_USER="acip_user"
APP_GROUP="acip_user"
PREFIX="/opt/acip"
ETC_DIR="/etc/acip"
UNIT_SRC="packaging/acip-sidecar.service"
UNIT_DST="/etc/systemd/system/acip-sidecar.service"

need_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "This installer must be run as root (try: sudo $0)" >&2
    exit 1
  fi
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Missing required command: $1" >&2
    exit 1
  }
}

main() {
  need_root
  need_cmd systemctl
  need_cmd install
  need_cmd id

  if ! command -v cargo >/dev/null 2>&1; then
    echo "cargo not found. Install Rust toolchain first." >&2
    exit 1
  fi

  echo "[1/6] Creating user/group ${APP_USER}:${APP_GROUP} (if needed)"
  getent group "${APP_GROUP}" >/dev/null 2>&1 || groupadd --system "${APP_GROUP}"
  id -u "${APP_USER}" >/dev/null 2>&1 || useradd --system --home /nonexistent --shell /usr/sbin/nologin --gid "${APP_GROUP}" "${APP_USER}"

  echo "[2/6] Building release binary"
  # Build as invoking user might be nicer, but we are root here. If you prefer, build first then run install.
  cargo build --release

  echo "[3/6] Installing binary to ${PREFIX}"
  install -d -m 0755 "${PREFIX}"
  install -m 0755 target/release/acip-sidecar "${PREFIX}/acip-sidecar"

  echo "[4/6] Ensuring ${ETC_DIR} exists"
  install -d -m 0755 "${ETC_DIR}"

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

  echo "[5/6] Installing systemd unit"
  install -m 0644 "${UNIT_SRC}" "${UNIT_DST}"
  systemctl daemon-reload

  echo "[6/6] Enabling and starting service"
  systemctl enable --now acip-sidecar

  echo "Done. Next steps:"
  echo "- Edit ${ETC_DIR}/secrets.env (API keys + ACIP_AUTH_TOKEN)"
  echo "- Restart: systemctl restart acip-sidecar"
  echo "- Logs: journalctl -u acip-sidecar -f"
  echo "- Health: curl -sS http://127.0.0.1:18795/health"
  echo "- Unix socket option: set server.unix_socket=/run/acip/acip-sidecar.sock and restart"
}

main "$@"
