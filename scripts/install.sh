#!/usr/bin/env bash
set -euo pipefail

# Best-effort installer for Linux/systemd.
# - Builds release binary
# - Installs to /opt/acip
# - Creates /etc/acip + writes config.toml if missing
# - Installs systemd unit
# - Creates system user/group (acip_user)

APP_USER=""
APP_GROUP=""
PREFIX="/opt/acip"
ETC_DIR="/etc/acip"
UNIT_SRC="packaging/acip-sidecar.service"
UNIT_DST="/etc/systemd/system/acip-sidecar.service"
DROPIN_DIR="/etc/systemd/system/acip-sidecar.service.d"

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

parse_args() {
  # Defaults
  L1_MODEL="gemini-2.0-flash"
  L2_MODEL="claude-3-5-haiku-latest"
  L1_MODEL_SET=0
  L2_MODEL_SET=0
  SENTRY_MODE="stub"
  PORT="18795"
  APP_USER_DEFAULT="acip_user"
  APP_GROUP_DEFAULT="acip_user"
  APP_USER_OVERRIDE=""
  APP_GROUP_OVERRIDE=""

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --l1-model)
        L1_MODEL="$2"; L1_MODEL_SET=1; shift 2 ;;
      --l2-model)
        L2_MODEL="$2"; L2_MODEL_SET=1; shift 2 ;;
      --sentry-mode)
        SENTRY_MODE="$2"; shift 2 ;;
      --port)
        PORT="$2"; shift 2 ;;
      --user)
        APP_USER_OVERRIDE="$2"; shift 2 ;;
      --group)
        APP_GROUP_OVERRIDE="$2"; shift 2 ;;
      -h|--help)
        cat <<'EOF'
Usage: install.sh [--port <port>] [--user <user>] [--group <group>] [--sentry-mode stub|live] [--l1-model <model>] [--l2-model <model>]

This installer configures the default model policy via environment variables.

Examples:
  # Safe default: stub mode (no external model calls)
  sudo ./scripts/install.sh --port 18795 --user acip_user --group acip_user --sentry-mode stub

  # Live mode requires explicit model choices:
  sudo ./scripts/install.sh --sentry-mode live \
    --l1-model gemini-2.0-flash --l2-model claude-3-5-haiku-latest
EOF
        exit 0
        ;;
      *)
        echo "Unknown arg: $1" >&2
        exit 1
        ;;
    esac
  done
}

model_provider_for() {
  # Map model name -> provider.
  # Keep this conservative and explicit.
  local m
  m="${1,,}"
  if [[ "$m" == claude-* || "$m" == anthropic/* ]]; then
    echo "anthropic"; return 0
  fi
  if [[ "$m" == gemini-* || "$m" == google/* ]]; then
    echo "gemini"; return 0
  fi
  # Heuristic fallback
  if [[ "$m" == *claude* || "$m" == *anthropic* ]]; then
    echo "anthropic"; return 0
  fi
  if [[ "$m" == *gemini* || "$m" == *google* ]]; then
    echo "gemini"; return 0
  fi
  echo "unknown"; return 0
}

main() {
  parse_args "$@"

  need_root
  need_cmd systemctl
  need_cmd install
  need_cmd id

  # setcap is optional (only needed for ports <1024)

  if ! command -v cargo >/dev/null 2>&1; then
    echo "cargo not found. Install Rust toolchain first." >&2
    exit 1
  fi

  # Apply overrides
  if [[ -n "${APP_USER_OVERRIDE}" ]]; then APP_USER="${APP_USER_OVERRIDE}"; fi
  if [[ -n "${APP_GROUP_OVERRIDE}" ]]; then APP_GROUP="${APP_GROUP_OVERRIDE}"; fi
  if [[ -z "${APP_USER}" ]]; then APP_USER="${APP_USER_DEFAULT}"; fi
  if [[ -z "${APP_GROUP}" ]]; then APP_GROUP="${APP_GROUP_DEFAULT}"; fi

  # Validate sentry mode
  if [[ "${SENTRY_MODE}" != "stub" && "${SENTRY_MODE}" != "live" ]]; then
    echo "Invalid --sentry-mode: ${SENTRY_MODE} (expected stub|live)" >&2
    exit 1
  fi

  # Live mode requires explicit model choices (no hidden defaults)
  if [[ "${SENTRY_MODE}" == "live" ]]; then
    if (( L1_MODEL_SET == 0 )); then
      echo "--sentry-mode live requires --l1-model" >&2
      exit 1
    fi
    if (( L2_MODEL_SET == 0 )); then
      echo "--sentry-mode live requires --l2-model" >&2
      exit 1
    fi
  fi

  # Validate port
  if ! [[ "${PORT}" =~ ^[0-9]+$ ]] || (( PORT < 1 || PORT > 65535 )); then
    echo "Invalid --port: ${PORT}" >&2
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

  # If binding to a privileged port (<1024), grant CAP_NET_BIND_SERVICE so we can
  # still run as the unprivileged service user.
  if (( PORT < 1024 )); then
    if command -v setcap >/dev/null 2>&1; then
      echo "[3/6] Granting CAP_NET_BIND_SERVICE to ${PREFIX}/acip-sidecar for privileged port ${PORT}"
      setcap cap_net_bind_service=+ep "${PREFIX}/acip-sidecar" || {
        echo "WARNING: setcap failed; binding to port ${PORT} may fail." >&2
        echo "         Install libcap2-bin and rerun installer, or choose a port >=1024." >&2
      }
    else
      echo "WARNING: port ${PORT} is <1024 but setcap is not available." >&2
      echo "         Install libcap2-bin (setcap) or choose a port >=1024." >&2
    fi
  fi

  echo "[4/6] Ensuring ${ETC_DIR} exists"
  install -d -m 0755 "${ETC_DIR}"

  if [[ ! -f "${ETC_DIR}/config.toml" ]]; then
    echo "Writing ${ETC_DIR}/config.toml from config.example.toml"
    install -m 0644 config.example.toml "${ETC_DIR}/config.toml"

    # Best-effort set configured port in the generated config.
    # (If you later change the config manually, this script will not overwrite it.)
    sed -i -E "s/^port\s*=\s*[0-9]+/port = ${PORT}/" "${ETC_DIR}/config.toml" 2>/dev/null || true
  else
    echo "Leaving existing ${ETC_DIR}/config.toml in place"
  fi

  if [[ ! -f "${ETC_DIR}/secrets.env" ]]; then
    echo "[secrets] Creating ${ETC_DIR}/secrets.env (mode 0600)"
    install -m 0600 /dev/null "${ETC_DIR}/secrets.env"

    echo "[secrets] Enter required secrets now (input hidden)."
    echo "         Leave blank to skip; you can edit ${ETC_DIR}/secrets.env later."

    read -r -s -p "GEMINI_API_KEY: " gemini_key; echo
    read -r -s -p "ANTHROPIC_API_KEY: " anthropic_key; echo
    read -r -s -p "ACIP_AUTH_TOKEN (recommended): " acip_token; echo

    {
      echo "# Required for live sentry mode:"
      [[ -n "${gemini_key}" ]] && echo "GEMINI_API_KEY=${gemini_key}"
      [[ -n "${anthropic_key}" ]] && echo "ANTHROPIC_API_KEY=${anthropic_key}"
      echo
      echo "# Auth token for callers (recommended):"
      [[ -n "${acip_token}" ]] && echo "ACIP_AUTH_TOKEN=${acip_token}"
      echo
    } >>"${ETC_DIR}/secrets.env"

    # Best-effort ensure perms (some filesystems may ignore chmod).
    chmod 0600 "${ETC_DIR}/secrets.env" 2>/dev/null || true
  else
    echo "[secrets] Leaving existing ${ETC_DIR}/secrets.env in place"
  fi

  echo "[5/6] Installing systemd unit"
  install -m 0644 "${UNIT_SRC}" "${UNIT_DST}"

  # Configure model policy via systemd drop-in env vars.
  # This is used when /etc/acip/policies.json is not configured.
  L1_PROVIDER=$(model_provider_for "${L1_MODEL}")
  L2_PROVIDER=$(model_provider_for "${L2_MODEL}")
  if [[ "$L1_PROVIDER" == "unknown" || "$L2_PROVIDER" == "unknown" ]]; then
    echo "ERROR: Could not infer provider for model(s)." >&2
    echo "  L1_MODEL=${L1_MODEL} -> ${L1_PROVIDER}" >&2
    echo "  L2_MODEL=${L2_MODEL} -> ${L2_PROVIDER}" >&2
    echo "Hint: use model names like gemini-*, claude-*" >&2
    exit 1
  fi

  install -d -m 0755 "$DROPIN_DIR"

  # Drop-in: sentry mode
  cat >"$DROPIN_DIR/00-sentry-mode.conf" <<EOF
[Service]
Environment=ACIP_SENTRY_MODE=${SENTRY_MODE}
EOF

  # Drop-in: models (only meaningful in live mode; harmless otherwise)
  cat >"$DROPIN_DIR/10-models.conf" <<EOF
[Service]
Environment=ACIP_L1_PROVIDER=${L1_PROVIDER}
Environment=ACIP_L1_MODEL=${L1_MODEL}
Environment=ACIP_L2_PROVIDER=${L2_PROVIDER}
Environment=ACIP_L2_MODEL=${L2_MODEL}
EOF

  # Drop-in: run user/group overrides (mirrors unit defaults)
  cat >"$DROPIN_DIR/05-user.conf" <<EOF
[Service]
User=${APP_USER}
Group=${APP_GROUP}
EOF

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
