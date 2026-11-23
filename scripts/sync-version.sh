#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION_FILE="${ROOT_DIR}/VERSION"

if [[ ! -f "${VERSION_FILE}" ]]; then
  echo "VERSION file not found: ${VERSION_FILE}" >&2
  exit 1
fi

RAW_VER="$(tr -d ' \t\r\n' < "${VERSION_FILE}")"
VER="${RAW_VER#v}"
VER="${VER%-LTS}"
if [[ ! "${VER}" =~ ^[0-9]+\.[0-9]+\.([0-9]+)$ ]]; then
  echo "Invalid VERSION '${RAW_VER}' (expected X.Y.Z, e.g. 4.0.40)" >&2
  exit 1
fi

BUILD_NUM="${BASH_REMATCH[1]}"
TAG_VER="v${VER}-LTS"

PYTHON_BIN=""
if command -v python3 >/dev/null 2>&1 && python3 -c "import sys" >/dev/null 2>&1; then
  PYTHON_BIN="python3"
elif command -v python >/dev/null 2>&1 && python -c "import sys" >/dev/null 2>&1; then
  PYTHON_BIN="python"
else
  echo "Python interpreter not found" >&2
  exit 1
fi

"${PYTHON_BIN}" - "${ROOT_DIR}" "${VER}" "${BUILD_NUM}" "${TAG_VER}" <<'PY'
import pathlib
import re
import sys

root = pathlib.Path(sys.argv[1])
ver = sys.argv[2]
build_num = sys.argv[3]
tag_ver = sys.argv[4]

go_updates = [
    ("mobile/mobile.go", r'(var\s+Version\s*=\s*")[^"]*(")', rf'\g<1>{tag_ver}\2'),
    ("internal/client/engine.go", r'(var\s+Version\s*=\s*")[^"]*(")', rf'\g<1>{tag_ver}\2'),
    ("internal/server/server.go", r'(var\s+Version\s*=\s*")[^"]*(")', rf'\g<1>{tag_ver}\2'),
    ("internal/tui/upgrade.go", r'(var\s+CurrentVersion\s*=\s*")[^"]*(")', rf'\g<1>{tag_ver}\2'),
    ("cmd/gft-core/main.go", r'(var\s+version\s*=\s*")[^"]*(")', rf'\g<1>{tag_ver}\2'),
    ("cmd/0ghost/main.go", r'(var\s+gatewayVersion\s*=\s*")[^"]*(")', rf'\g<1>{tag_ver}\2'),
    ("cmd/gft-client-gui/main_windows.go", r'(var\s+desktopVersion\s*=\s*")[^"]*(")', rf'\g<1>{tag_ver}\2'),
]

for rel, pat, repl in go_updates:
    p = root / rel
    text = p.read_text(encoding="utf-8")
    new_text, count = re.subn(pat, repl, text, count=1)
    if count != 1:
        raise RuntimeError(f"failed to update version in {rel}")
    p.write_text(new_text, encoding="utf-8", newline="\n")

plist_updates = [
    "ios/vpn/AppInfo.plist",
    "ios/vpn/TunnelInfo.plist",
    "ios/vpn/ControlInfo.plist",
    "ios/companion/CompanionInfo.plist",
]

for rel in plist_updates:
    p = root / rel
    text = p.read_text(encoding="utf-8")
    text, c1 = re.subn(
        r"(<key>CFBundleShortVersionString</key>\s*<string>)[^<]*(</string>)",
        rf"\g<1>{ver}\2",
        text,
        count=1,
    )
    text, c2 = re.subn(
        r"(<key>CFBundleVersion</key>\s*<string>)[^<]*(</string>)",
        rf"\g<1>{build_num}\2",
        text,
        count=1,
    )
    if c1 != 1 or c2 != 1:
        raise RuntimeError(f"failed to update plist versions in {rel}")
    p.write_text(text, encoding="utf-8", newline="\n")

print(f"Synced version -> VER={ver} BUILD={build_num} TAG={tag_ver}")
PY
