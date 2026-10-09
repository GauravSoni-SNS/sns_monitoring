#!/usr/bin/env bash
# SNS Endpoint Security — macOS installer.
# Installs the agent as launchd LaunchAgents (run in the user session). macOS requires the
# user to grant Screen Recording + Accessibility permission (TCC) — this CANNOT be silent;
# the script opens the right Settings panes and the agent degrades gracefully until granted.
#
#   sudo ./install-macos.sh --server https://sns.example.com --token <enroll-token> [--name NAME]
#
# Binaries (sns-service, sns-useragent, sns-agentctl) must sit next to this script
# (build on macOS: cargo build --release --workspace).
set -euo pipefail

SERVER=""; TOKEN=""; NAME="$(scutil --get ComputerName 2>/dev/null || hostname)"
while [ $# -gt 0 ]; do case "$1" in
  --server) SERVER="$2"; shift 2;;
  --token)  TOKEN="$2";  shift 2;;
  --name)   NAME="$2";   shift 2;;
  *) echo "unknown arg: $1"; exit 2;;
esac; done

HERE="$(cd "$(dirname "$0")" && pwd)"
PREFIX="/usr/local/sns"
DATA="$HOME/Library/Application Support/SNS"
LA="$HOME/Library/LaunchAgents"

echo "[1/5] Install binaries -> $PREFIX"
sudo mkdir -p "$PREFIX"
for b in sns-service sns-useragent sns-agentctl; do
  sudo install -m 0755 "$HERE/$b" "$PREFIX/$b"
done
mkdir -p "$DATA"

echo "[2/5] Initialize config + keys + db"
SNS_DATA_ROOT="$DATA" "$PREFIX/sns-agentctl" init --system-name "$NAME" --data-root "$DATA" || true

echo "[3/5] Enroll with the central server"
if [ -n "$SERVER" ] && [ -n "$TOKEN" ]; then
  SNS_DATA_ROOT="$DATA" "$PREFIX/sns-agentctl" enroll --server "$SERVER" --token "$TOKEN" || true
fi

echo "[4/5] launchd LaunchAgents"
mkdir -p "$LA"
make_plist () { # label  program
cat > "$LA/$1.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>$1</string>
  <key>ProgramArguments</key><array><string>$2</string>$3</array>
  <key>EnvironmentVariables</key><dict><key>SNS_DATA_ROOT</key><string>$DATA</string></dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ProcessType</key><string>Background</string>
  <key>Nice</key><integer>10</integer>
</dict></plist>
EOF
}
make_plist "com.sns.agent"   "$PREFIX/sns-service" "<string>--console</string>"
make_plist "com.sns.capture" "$PREFIX/sns-useragent" ""
launchctl unload "$LA/com.sns.agent.plist"   2>/dev/null || true
launchctl unload "$LA/com.sns.capture.plist" 2>/dev/null || true
launchctl load  "$LA/com.sns.agent.plist"
launchctl load  "$LA/com.sns.capture.plist"

echo "[5/5] Grant permissions (REQUIRED — macOS cannot do this silently)"
echo "  Opening Settings. Enable BOTH for the SNS agent:"
echo "   • Privacy & Security → Screen Recording"
echo "   • Privacy & Security → Accessibility"
open "x-apple.systempreferences:com.apple.preference.security?Privacy_ScreenCapture" || true
sleep 1
open "x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility" || true
echo "Done. Local panel: http://127.0.0.1:7731"
