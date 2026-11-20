# GhostFrame-TLS (v4.0.2-LTS Unified Monorepo)

[![CI](https://github.com/Spittingjiu/GhostFrame-TLS/actions/workflows/ci.yml/badge.svg)](https://github.com/Spittingjiu/GhostFrame-TLS/actions/workflows/ci.yml)
[![Go Version](https://img.shields.io/badge/Go-1.26+-00ADD8?logo=go)](https://golang.org)
[![Platform](https://img.shields.io/badge/Platform-Linux%20|%20Windows%20|%20iOS%20|%20iStoreOS-blue)](https://github.com/Spittingjiu/GhostFrame-TLS)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Unified pure-Go (`CGO_ENABLED=0` for server/desktop/router) source monorepo for **GhostFrame v4.0.2-LTS** — built around a single shared protocol & routing core (`internal/gftrtc`, `internal/gft`, `internal/netbind`, `internal/client`) powering all four endpoints without duplicate kernel copies.

## Repository Architecture

```text
.
├── cmd/
│   ├── gft-server/             # Dual-stack server & interactive `gft` TUI control center
│   ├── gft-core/               # Headless Linux/OpenWrt CLI SOCKS5/HTTP daemon
│   ├── gft-client-gui/         # Native Windows Win32/GDI+ desktop & tray client (GhostFrame-Pro.exe)
│   └── 0ghost/                 # Phicomm N1 / iStoreOS arm64 transparent side-router (:19080)
├── internal/
│   ├── gftrtc/                 # GFT-RTC UDP engine (ICE-STUN, SRTP AEAD, XOR-FEC, SACK, Smart-Brutal, MBB)
│   ├── gft/                    # ApexScheduler, Chrome PQ uTLS, RecordSplitConn, gft3:// codec
│   ├── netbind/                # SO_MARK anti-loop, Darwin IP_BOUND_IF, RFC 7050/6052 NAT64 synthesis
│   ├── client/                 # Engine, multi-category RuleSet, embedded APNIC CN IPv4 CIDR table
│   ├── server/, sni/, qr/, tui/# Server runtime, probe mirroring, TUI & OTA rollback
│   ├── winui/                  # Pure-Go Win32/GDI+/DWM GUI & tray (Windows only)
│   ├── tproxy/                 # Linux fw4 nftables TPROXY/REDIRECT, Split-DNS (:7853), conflict resolver
│   └── tunstack/               # gVisor L3/L4 Netstack + Fake-IP DNS (isolated for mobile/iOS)
├── mobile/ & ios/              # GoMobile bridge + GhostFrameVPN (True TUN + ControlWidget) & Companion
├── openwrt/luci-app-0ghost/    # iStoreOS LuCI panel, procd service, hotplug self-heal hooks
├── tools/                      # AppIcon generator & OmniSign/AltStore iOS repo sync server
└── .github/workflows/          # Path-isolated per-platform CI & cross-repo binary release pipeline
```

## CI & Binary Distribution Workflows

- **`ci.yml`**: Protocol core, server & CLI tests (`-race`), fuzz checks, and cross-compile checks.
- **`build-client.yml`**: Windows GUI client build (`GhostFrame-Pro.exe`, zero `gvisor` linkage).
- **`build-0ghost.yml`**: N1/iStoreOS `linux/arm64` build & `0ghost-istoreos-arm64.tar.gz` bundle.
- **`ios-dual-ipa.yml`**: Strict path-filtered `macos-15` dual `.ipa` builds (`GhostFrameVPN` & `GhostFrameCompanion`).
- **`release-dist.yml`**: Tag/manual unified release building all platform binaries + `source.json` + `checksums.txt`, with automatic push to `Spittingjiu/GhostFrame-Dist` when `secrets.DIST_PUSH_TOKEN` is configured.

## Quick Verification

```bash
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" ./cmd/gft-server
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -H=windowsgui" ./cmd/gft-client-gui
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" ./cmd/0ghost
GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go vet ./mobile/... ./internal/tunstack/...
```

## License

Licensed under the [MIT License](LICENSE).
