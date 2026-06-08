#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="$ROOT/bin"
VERSION="${1:-1.13.12}"

ARCH_RAW="$(uname -m)"
case "$ARCH_RAW" in
  x86_64) ARCH="amd64" ;;
  aarch64) ARCH="arm64" ;;
  *)
    echo "unsupported arch: $ARCH_RAW" >&2
    exit 1
    ;;
esac

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

URL="https://github.com/SagerNet/sing-box/releases/download/v${VERSION}/sing-box-${VERSION}-linux-${ARCH}.tar.gz"
ARCHIVE="$TMP_DIR/sing-box.tar.gz"

mkdir -p "$BIN_DIR"
curl -L "$URL" -o "$ARCHIVE"
tar -xzf "$ARCHIVE" -C "$TMP_DIR"
FOUND="$(find "$TMP_DIR" -type f -name sing-box | head -n 1)"

if [[ -z "$FOUND" ]]; then
  echo "sing-box binary not found in archive" >&2
  exit 1
fi

cp "$FOUND" "$BIN_DIR/sing-box"
chmod +x "$BIN_DIR/sing-box"
printf '%s\n' "$VERSION" > "$BIN_DIR/sing-box.version"

echo "installed $BIN_DIR/sing-box (version $VERSION)"
