#!/usr/bin/env bash
# Build + bundle the SNS agent for the CURRENT Unix OS (run on Linux to make the Linux
# bundle, on macOS to make the macOS bundle). Produces dist/SNSSecurityAgent-<os>.tar.gz
# containing the three binaries + the matching install script.
set -euo pipefail
cd "$(dirname "$0")/../.."          # repo root

OS="$(uname -s)"
case "$OS" in
  Linux)  TAG="linux";  SCRIPT="installer/unix/install-linux.sh";;
  Darwin) TAG="macos";  SCRIPT="installer/unix/install-macos.sh";;
  *) echo "unsupported OS: $OS"; exit 1;;
esac

echo "Building release binaries for $TAG ..."
cargo build --release --workspace

STAGE="dist/SNSSecurityAgent-$TAG"
rm -rf "$STAGE"; mkdir -p "$STAGE"
for b in sns-service sns-useragent sns-agentctl; do
  cp "target/release/$b" "$STAGE/$b"
  chmod +x "$STAGE/$b"
done
cp "$SCRIPT" "$STAGE/"
chmod +x "$STAGE/"*.sh
cp docs/HOW-TO-USE.md "$STAGE/" 2>/dev/null || true

tar czf "dist/SNSSecurityAgent-$TAG.tar.gz" -C dist "SNSSecurityAgent-$TAG"
echo "Bundle: dist/SNSSecurityAgent-$TAG.tar.gz"
