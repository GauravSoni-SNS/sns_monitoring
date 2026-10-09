#!/usr/bin/env bash
# SNS Endpoint Security — Linux installer.
# Installs the agent as systemd *user* services (run in the desktop session so screen/idle/
# window capture works). Low overhead: lightweight probes, screenshots on interval only.
#
#   sudo ./install-linux.sh --server https://sns.example.com --token <enroll-token> [--name NAME]
#
# Binaries (sns-service, sns-useragent, sns-agentctl) must sit next to this script
# (build them on Linux: cargo build --release --workspace).
set -euo pipefail

SERVER=""; TOKEN=""; NAME="$(hostname)"
while [ $# -gt 0 ]; do case "$1" in
  --server) SERVER="$2"; shift 2;;
  --token)  TOKEN="$2";  shift 2;;
  --name)   NAME="$2";   shift 2;;
  *) echo "unknown arg: $1"; exit 2;;
esac; done

HERE="$(cd "$(dirname "$0")" && pwd)"
PREFIX="/opt/sns"
DATA="$HOME/.local/share/sns"          # per-user data (encrypted store lives here)
USER_SVC="$HOME/.config/systemd/user"

echo "[1/6] Dependencies (capture + idle + usb + print tools)"
if command -v apt-get >/dev/null; then
  sudo apt-get update -y
  sudo apt-get install -y xdotool xprintidle scrot grim libsecret-tools cups-client usbutils || true
elif command -v dnf >/dev/null; then
  sudo dnf install -y xdotool xprintidle scrot grim libsecret cups usbutils || true
elif command -v pacman >/dev/null; then
  sudo pacman -S --noconfirm xdotool xprintidle scrot grim libsecret cups usbutils || true
else
  echo "  ! Unknown package manager — install manually: xdotool xprintidle scrot/grim cups usbutils"
fi

echo "[2/6] Install binaries -> $PREFIX"
sudo mkdir -p "$PREFIX"
for b in sns-service sns-useragent sns-agentctl; do
  sudo install -m 0755 "$HERE/$b" "$PREFIX/$b"
done
mkdir -p "$DATA"

echo "[3/6] Initialize config + keys + db"
SNS_DATA_ROOT="$DATA" "$PREFIX/sns-agentctl" init --system-name "$NAME" --data-root "$DATA" || true

echo "[4/6] Enroll with the central server"
if [ -n "$SERVER" ] && [ -n "$TOKEN" ]; then
  SNS_DATA_ROOT="$DATA" "$PREFIX/sns-agentctl" enroll --server "$SERVER" --token "$TOKEN" || true
fi

echo "[5/6] systemd --user services (run in your desktop session)"
mkdir -p "$USER_SVC"
cat > "$USER_SVC/sns-agent.service" <<EOF
[Unit]
Description=SNS Endpoint Security agent (supervisor: storage, screenshots, sync)
After=graphical-session.target
[Service]
Environment=SNS_DATA_ROOT=$DATA
ExecStart=$PREFIX/sns-service --console
Restart=always
RestartSec=5
Nice=10
[Install]
WantedBy=default.target
EOF
cat > "$USER_SVC/sns-capture.service" <<EOF
[Unit]
Description=SNS Endpoint Security capture (foreground app, idle, exfil)
After=graphical-session.target
[Service]
Environment=SNS_DATA_ROOT=$DATA
ExecStart=$PREFIX/sns-useragent
Restart=always
RestartSec=5
Nice=10
[Install]
WantedBy=default.target
EOF
systemctl --user daemon-reload
systemctl --user enable --now sns-agent.service sns-capture.service
# Survive logout:
sudo loginctl enable-linger "$USER" || true

echo "[6/6] Permissions"
if [ "${XDG_SESSION_TYPE:-}" = "wayland" ]; then
  echo "  ! Wayland detected: screen/window capture needs a portal grant."
  echo "    'grim' works on wlroots compositors; on GNOME/KDE you may be prompted to allow screen capture."
fi
echo "Done. Local panel: http://127.0.0.1:7731   Manage: systemctl --user status sns-agent"
