# CROSS-PLATFORM.md — Windows · macOS · Linux

One codebase, three native agents. The admin (central server + dashboard) is web and already
runs anywhere; only the **agent** has per-OS capture code.

## Architecture
- **Shared core (`sns-shared`, `sns-core`):** events, SQLite storage, tamper-evident hash chain,
  sync engine, alerts, retention, crypto, config — fully cross-platform, built once.
- **Per-OS capture:** each collector has a Windows path (`#[cfg(windows)]`, Win32) and a Unix
  path (`#[cfg(unix)]`) in `collectors/platform_unix.rs` (Linux + macOS). Same event shapes, so
  the server/dashboard are identical for every OS.
- **Service model:** Windows Service (Win); systemd *user* services (Linux); launchd
  LaunchAgents (macOS). All run in the desktop session so screen/window/idle capture works.

## Feature parity (metadata-first, no keystrokes/contents)
| Feature | Windows | macOS | Linux |
|---|---|---|---|
| Foreground app + window title | Win32 | AppleScript/AX | xdotool (X11) |
| Idle time | GetLastInputInfo | ioreg HIDIdleTime | xprintidle (X11) |
| Screenshots | GDI | `screencapture` | grim (Wayland) / scrot / import |
| USB device identity | SetupDi | system_profiler | lsusb |
| Files copied to USB | drive letters | /Volumes scan | /media,/run/media scan |
| Print jobs | winspool | lpstat (CUPS) | lpstat (CUPS) |
| Installed transfer apps | registry | /Applications | dpkg/rpm |
| Encryption key wrap | DPAPI | (file 0600; Keychain = hardening TODO) | (file 0600; libsecret = hardening TODO) |

## Permissions (cannot be silent on Mac / Wayland)
- **macOS:** the installer opens **Screen Recording** + **Accessibility** settings; the agent
  degrades gracefully (keeps running, captures what it can) until the user grants them.
- **Linux Wayland:** screen/window capture needs a portal grant; `grim` works on wlroots, and
  GNOME/KDE prompt once. X11 needs no prompt.

## Build + package (on each OS)
- **Windows:** `installer\package.ps1` → zip; install via `Install.cmd`.
- **Linux:** `installer/unix/package-unix.sh` on a Linux box → `dist/SNSSecurityAgent-linux.tar.gz`;
  install via `sudo ./install-linux.sh --server <url> --token <enroll>`.
- **macOS:** `installer/unix/package-unix.sh` on a Mac → `dist/SNSSecurityAgent-macos.tar.gz`;
  install via `sudo ./install-macos.sh --server <url> --token <enroll>`.

Binaries are OS-specific (PE / Mach-O / ELF) — **build each on its own OS** (the bundled SQLite
needs that OS's C compiler; cross-compiling from Windows is not supported here).

## Distribution
Host the three bundles under the server's `/downloads/` and send users to **`/download`** — the
page detects their OS and shows the matching installer + enroll command.

## Low-overhead notes
Frequent probes (foreground, idle) are tiny short-lived reads; screenshots run only on the
configured interval (default 15 min); collectors are `Nice 10`. A later optimization replaces the
hottest Unix probes with direct native-library calls (libXss / CoreGraphics) instead of small
helper processes — noted in `platform_unix.rs`.
