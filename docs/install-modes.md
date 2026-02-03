# ACIP Sidecar — Install Mode Decision Tree

Use this to pick the right deployment mode for **acip-sidecar**.

> Goal: smallest attack surface with enough convenience.

## Preference order (lowest blast radius → highest)

1) **Mode D — Docker** (loopback-only)
2) **Mode A — systemd global (direct `acip_user`)**
3) **Mode B — systemd global (root-drop)** *(only when required)*
4) **Mode C — systemd user service**

## Decision tree

### 1) Can you run it in Docker (and do you want the smallest host blast radius)?
- **Yes** → **Mode D: Docker**
- **No** → go to (2)

### 2) Do you have systemd and want the service to survive logouts/reboots?
- **Yes** → go to (3)
- **No** → **Mode C: systemd user service** (or run manually for dev)

### 3) Do you need a privileged TCP port (<1024) or other root-only pre-bind setup?
- **Privileged port only (<1024)** → You can usually still use **Mode A** by granting `CAP_NET_BIND_SERVICE` to the binary (`setcap`) so the service runs unprivileged.
- **Other root-only pre-bind steps** → **Mode B: systemd global (root-drop)**
- **No** → **Mode A: systemd global (direct `acip_user`)**

### 4) Do you need a Unix domain socket (instead of TCP)?
Any mode can use a Unix socket.
- Set `server.unix_socket = "/run/acip/acip-sidecar.sock"` (systemd global) or a user-writable path (user service).
- When Unix socket is set, TCP host/port are ignored.

---

## Mode D — Docker (preferred if possible)

Use when:
- You want the smallest host blast radius.
- You want the extraction toolchain (poppler/tesseract/libseccomp2) packaged.

Docs:
- `docs/docker.md`

---

## Mode A — systemd global (recommended if not using Docker): direct `acip_user`

Use when:
- You have systemd.
- You **do not** need a privileged port.
- You want least privilege and simple operation.

Characteristics:
- systemd starts the process as `acip_user`.
- No “root window.”

Config paths:
- `/etc/acip/config.toml`
- `/etc/acip/secrets.env` (0600)

Unit:
- `packaging/acip-sidecar.service`

---

## Mode B — systemd global (optional): root-drop

Use when:
- You must perform a root-only step before serving.
- (Binding to a privileged port alone can usually be handled by `CAP_NET_BIND_SERVICE` instead.)

Characteristics:
- systemd starts as root; the process drops privileges to `acip_user` before serving.
- Higher complexity; only use when required.

Unit:
- (planned) `packaging/acip-sidecar.rootdrop.service`

---

## Mode C — systemd user service (highest blast radius)

Use when:
- Convenience on a dev machine is more important than isolation.

Characteristics:
- Runs with your full user permissions (home directory, etc.).

Unit:
- `packaging/acip-sidecar.user.service`
