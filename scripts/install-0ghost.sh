#!/bin/sh
set -eu

# KestrelBox (compat entrypoint install-0ghost.sh -> install-kbox.sh)
# Uses the same fail-closed signed manifest & checksum verification as install-kbox.sh.

BASE_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
if [ -f "$BASE_DIR/install-kbox.sh" ]; then
	exec sh "$BASE_DIR/install-kbox.sh" "$@"
fi

DIST_REPO="${DIST_REPO:-Spittingjiu/Ghost}"
MIRROR_PREFIX="${MIRROR_PREFIX:-}"
for arg in "$@"; do
	:
done
if [ -n "$MIRROR_PREFIX" ]; then
	MIRROR_PREFIX="${MIRROR_PREFIX%/}/"
fi
TMP_INST="$(mktemp /tmp/kbox-entry.XXXXXX)"
trap 'rm -f "$TMP_INST"' EXIT INT TERM
curl -fsSL --retry 3 -o "$TMP_INST" "${MIRROR_PREFIX}https://github.com/${DIST_REPO}/releases/latest/download/install-kbox.sh"
exec sh "$TMP_INST" "$@"
