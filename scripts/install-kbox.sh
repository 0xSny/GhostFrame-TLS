#!/bin/sh
set -eu

# KestrelBox (Kestrel iStoreOS / OpenWrt arm64 Side-Router) One-Line Binary Installer
# Downloads prebuilt pure-binary bundle from public distribution repo (no source code required).

DIST_REPO="${DIST_REPO:-Spittingjiu/Ghost}"
TAG="latest"
MIRROR_PREFIX="${MIRROR_PREFIX:-}"

while [ $# -gt 0 ]; do
	case "$1" in
		--mirror)
			MIRROR_PREFIX="${2:-}"
			shift 2
			;;
		--tag|--version)
			TAG="${2:-latest}"
			shift 2
			;;
		-*)
			echo "[KestrelBox] Unknown option: $1" >&2
			exit 1
			;;
		*)
			TAG="$1"
			shift
			;;
	esac
done

if [ -n "$MIRROR_PREFIX" ]; then
	MIRROR_PREFIX="${MIRROR_PREFIX%/}/"
fi
TMP_DIR="$(mktemp -d /tmp/kbox-inst.XXXXXX)"
trap 'rm -rf "$TMP_DIR"' EXIT INT TERM

if [ "$(id -u)" -ne 0 ]; then
	echo "[KestrelBox] Please run as root." >&2
	exit 1
fi

ARCH="$(uname -m)"
case "$ARCH" in
	aarch64|arm64) PKG="kbox-istoreos-arm64.tar.gz" ;;
	*) echo "[KestrelBox] Unsupported architecture: $ARCH (requires aarch64/arm64)" >&2; exit 1 ;;
esac

if [ "$TAG" = "latest" ]; then
	URL="${MIRROR_PREFIX}https://github.com/${DIST_REPO}/releases/latest/download/${PKG}"
else
	URL="${MIRROR_PREFIX}https://github.com/${DIST_REPO}/releases/download/${TAG}/${PKG}"
fi

echo "[KestrelBox] Downloading $URL ..."
curl -fsSL --retry 3 -o "$TMP_DIR/$PKG" "$URL"

tar -xzf "$TMP_DIR/$PKG" -C "$TMP_DIR"
/etc/init.d/kbox stop >/dev/null 2>&1 || true
/etc/init.d/0ghost stop >/dev/null 2>&1 || true
sh "$TMP_DIR/install-local.sh"
echo "[KestrelBox] Done! Access LuCI -> Services -> KestrelBox or http://<RouterIP>:19080/"
