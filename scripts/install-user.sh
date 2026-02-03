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

parse_args() {
  L1_MODEL="gemini-2.0-flash"
  L2_MODEL="claude-3-5-haiku-latest"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --l1-model)
        L1_MODEL="$2"; shift 2 ;;
      --l2-model)
        L2_MODEL="$2"; shift 2 ;;
      -h|--help)
        cat <<'EOF'
Usage: install-user.sh [--l1-model <model>] [--l2-model <model>]

This installer configures the default model policy via environment variables
in the systemd user service.
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
  local m
  m="${1,,}"
  if [[ "$m" == claude-* || "$m" == anthropic/* ]]; then
    echo "anthropic"; return 0
  fi
  if [[ "$m" == gemini-* || "$m" == google/* ]]; then
    echo "gemini"; return 0
  fi
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

    chmod 0600 "${ETC_DIR}/secrets.env" 2>/dev/null || true
  else
    echo "[secrets] Leaving existing ${ETC_DIR}/secrets.env in place"
  fi

  echo "[4/5] Installing systemd user unit"
  install -d -m 0755 "$HOME/.config/systemd/user"
  install -m 0644 "${UNIT_SRC}" "${UNIT_DST}"

  L1_PROVIDER=$(model_provider_for "${L1_MODEL}")
  L2_PROVIDER=$(model_provider_for "${L2_MODEL}")
  if [[ "$L1_PROVIDER" == "unknown" || "$L2_PROVIDER" == "unknown" ]]; then
    echo "ERROR: Could not infer provider for model(s)." >&2
    echo "  L1_MODEL=${L1_MODEL} -> ${L1_PROVIDER}" >&2
    echo "  L2_MODEL=${L2_MODEL} -> ${L2_PROVIDER}" >&2
    echo "Hint: use model names like gemini-*, claude-*" >&2
    exit 1
  fi

  DROPIN_DIR="$HOME/.config/systemd/user/acip-sidecar.service.d"
  install -d -m 0755 "$DROPIN_DIR"
  cat >"$DROPIN_DIR/10-models.conf" <<EOF
[Service]
Environment=ACIP_L1_PROVIDER=${L1_PROVIDER}
Environment=ACIP_L1_MODEL=${L1_MODEL}
Environment=ACIP_L2_PROVIDER=${L2_PROVIDER}
Environment=ACIP_L2_MODEL=${L2_MODEL}
EOF

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
