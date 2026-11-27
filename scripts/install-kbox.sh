#!/bin/sh
set -eu

# KestrelBox (Kestrel iStoreOS / OpenWrt arm64 Side-Router) Verified Binary Installer
# Downloads prebuilt pure-binary bundle + signed manifest from distribution repo,
# verifies Ed25519 signature, version, arch, byte size, SHA-256, and tar entries
# BEFORE extracting or stopping the running router service.

DIST_REPO="${DIST_REPO:-Spittingjiu/Ghost}"
TAG="latest"
MIRROR_PREFIX="${MIRROR_PREFIX:-}"
PUBKEY_FILE="${KBOX_PUBKEY_FILE:-}"
MANIFEST_URL=""
ALLOW_UNSIGNED_DEV=0
DRY_RUN_VERIFY=0

# Pinned Ed25519 public key (PEM) for Kestrel release manifests.
DEFAULT_PUBKEY_PEM='-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAzGauZN3SoguIJrE/D8racRLmW9lRkbzxHpox8m+KnqI=
-----END PUBLIC KEY-----'
PINNED_PUBKEY_PEM="${KBOX_PUBKEY_PEM:-$DEFAULT_PUBKEY_PEM}"

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
		--pubkey)
			PUBKEY_FILE="${2:-}"
			shift 2
			;;
		--manifest-url)
			MANIFEST_URL="${2:-}"
			shift 2
			;;
		--allow-unsigned-dev)
			ALLOW_UNSIGNED_DEV=1
			shift
			;;
		--dry-run-verify)
			DRY_RUN_VERIFY=1
			shift
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

if [ "$DRY_RUN_VERIFY" -ne 1 ] && [ "$(id -u)" -ne 0 ]; then
	echo "[KestrelBox] Please run as root." >&2
	exit 1
fi

ARCH="$(uname -m)"
case "$ARCH" in
	aarch64|arm64)
		PKG="kbox-istoreos-arm64.tar.gz"
		MANIFEST_ARCH="arm64"
		;;
	*)
		echo "[KestrelBox] Unsupported architecture: $ARCH (requires aarch64/arm64)" >&2
		exit 1
		;;
esac

if [ "$TAG" = "latest" ]; then
	BASE_URL="${MIRROR_PREFIX}https://github.com/${DIST_REPO}/releases/latest/download"
else
	BASE_URL="${MIRROR_PREFIX}https://github.com/${DIST_REPO}/releases/download/${TAG}"
fi

PKG_URL="${BASE_URL}/${PKG}"
if [ -z "$MANIFEST_URL" ]; then
	MANIFEST_URL="${BASE_URL}/kbox-manifest.txt"
fi
SIG_URL="${MANIFEST_URL}.sig"

if [ -z "$PUBKEY_FILE" ] && [ -n "$PINNED_PUBKEY_PEM" ]; then
	PUBKEY_FILE="$TMP_DIR/kbox-pubkey.pem"
	printf '%s\n' "$PINNED_PUBKEY_PEM" > "$PUBKEY_FILE"
fi

echo "[KestrelBox] Downloading manifest $MANIFEST_URL ..."
curl -fsSL --retry 3 -o "$TMP_DIR/kbox-manifest.txt" "$MANIFEST_URL"

if [ "$ALLOW_UNSIGNED_DEV" -ne 1 ]; then
	if [ -z "$PUBKEY_FILE" ] || [ ! -r "$PUBKEY_FILE" ]; then
		echo "[KestrelBox] ERROR: No trusted release public key configured (--pubkey or KBOX_PUBKEY_PEM). Refusing unverified install." >&2
		exit 1
	fi
	if ! command -v openssl >/dev/null 2>&1; then
		echo "[KestrelBox] ERROR: openssl is required to verify manifest signature." >&2
		exit 1
	fi
	echo "[KestrelBox] Downloading signature $SIG_URL ..."
	curl -fsSL --retry 3 -o "$TMP_DIR/kbox-manifest.txt.sig" "$SIG_URL"
	if ! openssl pkeyutl -verify -pubin -inkey "$PUBKEY_FILE" -rawin \
		-sigfile "$TMP_DIR/kbox-manifest.txt.sig" -in "$TMP_DIR/kbox-manifest.txt" >/dev/null 2>&1; then
		echo "[KestrelBox] ERROR: Manifest Ed25519 signature verification FAILED! Leaving running service untouched." >&2
		exit 1
	fi
else
	echo "[KestrelBox] WARNING: --allow-unsigned-dev enabled; skipping manifest signature verification." >&2
fi

manifest_get() {
	awk -F= -v k="$1" '$1 == k { sub(/^[^=]*=/, ""); print; exit }' "$TMP_DIR/kbox-manifest.txt" | tr -d '\r'
}

M_VER="$(manifest_get version)"
M_ARCH="$(manifest_get arch)"
M_FILE="$(manifest_get file)"
M_SIZE="$(manifest_get size)"
M_SHA="$(manifest_get sha256)"

if [ -z "$M_VER" ] || [ -z "$M_ARCH" ] || [ -z "$M_FILE" ] || [ -z "$M_SIZE" ] || [ -z "$M_SHA" ]; then
	echo "[KestrelBox] ERROR: Incomplete manifest fields." >&2
	exit 1
fi
if [ "$M_ARCH" != "$MANIFEST_ARCH" ] || [ "$M_FILE" != "$PKG" ]; then
	echo "[KestrelBox] ERROR: Manifest arch/file mismatch (got arch=$M_ARCH file=$M_FILE)." >&2
	exit 1
fi
if [ "$TAG" != "latest" ] && [ "$M_VER" != "$TAG" ]; then
	echo "[KestrelBox] ERROR: Manifest version ($M_VER) does not match requested tag ($TAG)." >&2
	exit 1
fi

echo "[KestrelBox] Downloading $PKG_URL ..."
curl -fsSL --retry 3 -o "$TMP_DIR/$PKG" "$PKG_URL"

ACTUAL_SIZE="$(wc -c < "$TMP_DIR/$PKG" | tr -d ' ')"
if [ "$ACTUAL_SIZE" != "$M_SIZE" ]; then
	echo "[KestrelBox] ERROR: Size mismatch (got=$ACTUAL_SIZE want=$M_SIZE). Aborting." >&2
	exit 1
fi

ACTUAL_SHA="$(sha256sum "$TMP_DIR/$PKG" | awk '{print $1}')"
if [ "$ACTUAL_SHA" != "$M_SHA" ]; then
	echo "[KestrelBox] ERROR: SHA-256 mismatch (got=$ACTUAL_SHA want=$M_SHA). Aborting." >&2
	exit 1
fi

# Inspect tarball entries before extracting to prevent path traversal or corrupt archives.
TAR_LIST="$TMP_DIR/tar.list"
tar -tzf "$TMP_DIR/$PKG" > "$TAR_LIST"
if grep -Eq '(^/|(^|/)\.\.(/|$))' "$TAR_LIST"; then
	echo "[KestrelBox] ERROR: Tarball contains unsafe path traversal entry." >&2
	exit 1
fi
if ! grep -Eq '^(\./)?install-local\.sh$' "$TAR_LIST" || ! grep -Eq '^(\./)?usr/bin/kbox$' "$TAR_LIST"; then
	echo "[KestrelBox] ERROR: Tarball missing required install-local.sh or usr/bin/kbox." >&2
	exit 1
fi

if [ "$DRY_RUN_VERIFY" -eq 1 ]; then
	echo "[KestrelBox] Verified $PKG ($M_VER, $ACTUAL_SIZE bytes, sha256=$ACTUAL_SHA)."
	exit 0
fi

tar -xzf "$TMP_DIR/$PKG" -C "$TMP_DIR"
/etc/init.d/kbox stop >/dev/null 2>&1 || true
/etc/init.d/0ghost stop >/dev/null 2>&1 || true
sh "$TMP_DIR/install-local.sh"
echo "[KestrelBox] Done! Access LuCI -> Services -> KestrelBox or http://<RouterIP>/kbox/"
