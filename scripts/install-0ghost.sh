#!/bin/sh
set -eu

# 0Ghost (GhostFrame iStoreOS / OpenWrt arm64 Side-Router) One-Line Binary Installer
# Downloads prebuilt pure-binary bundle from public distribution repo (no source code required).

DIST_REPO="${DIST_REPO:-Spittingjiu/GhostFrame-Dist}"
TAG="${1:-latest}"
MIRROR_PREFIX="${MIRROR_PREFIX:-}"
TMP_DIR="$(mktemp -d /tmp/0ghost-inst.XXXXXX)"
trap 'rm -rf "$TMP_DIR"' EXIT INT TERM

if [ "$(id -u)" -ne 0 ]; then
	echo "[0Ghost] Please run as root." >&2
	exit 1
fi

ARCH="$(uname -m)"
case "$ARCH" in
	aarch64|arm64) PKG="0ghost-istoreos-arm64.tar.gz" ;;
	*) echo "[0Ghost] Unsupported architecture: $ARCH (requires aarch64/arm64)" >&2; exit 1 ;;
esac

if [ "$TAG" = "latest" ]; then
	URL="${MIRROR_PREFIX}https://github.com/${DIST_REPO}/releases/latest/download/${PKG}"
else
	URL="${MIRROR_PREFIX}https://github.com/${DIST_REPO}/releases/download/${TAG}/${PKG}"
fi

echo "[0Ghost] Downloading $URL ..."
curl -fsSL --retry 3 -o "$TMP_DIR/$PKG" "$URL"

tar -xzf "$TMP_DIR/$PKG" -C "$TMP_DIR"
/etc/init.d/0ghost stop >/dev/null 2>&1 || true
sh "$TMP_DIR/install-local.sh"
echo "[0Ghost] Done! Access LuCI -> 0Ghost Side-Router or http://<RouterIP>:19080/"
