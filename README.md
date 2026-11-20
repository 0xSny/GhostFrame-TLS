# GhostFrame-TLS (`v4.0.2-LTS`)

[![CI (Core & Server)](https://github.com/Spittingjiu/GhostFrame-TLS/actions/workflows/ci.yml/badge.svg)](https://github.com/Spittingjiu/GhostFrame-TLS/actions/workflows/ci.yml)
[![Build Windows Client](https://github.com/Spittingjiu/GhostFrame-TLS/actions/workflows/build-client.yml/badge.svg)](https://github.com/Spittingjiu/GhostFrame-TLS/actions/workflows/build-client.yml)
[![Build 0Ghost Side-Router](https://github.com/Spittingjiu/GhostFrame-TLS/actions/workflows/build-0ghost.yml/badge.svg)](https://github.com/Spittingjiu/GhostFrame-TLS/actions/workflows/build-0ghost.yml)
[![Build iOS Dual Unsigned IPAs](https://github.com/Spittingjiu/GhostFrame-TLS/actions/workflows/ios-dual-ipa.yml/badge.svg)](https://github.com/Spittingjiu/GhostFrame-TLS/actions/workflows/ios-dual-ipa.yml)
[![Go Version](https://img.shields.io/badge/Go-1.27+-00ADD8?logo=go)](https://golang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**GhostFrame (`GFT`)** is a pure-Go (`CGO_ENABLED=0` for server, desktop, and router targets) dual-stack encrypted transport proxy powered by the custom **GhostFrame-RTC (`GFT-RTC`)** UDP engine and Chrome post-quantum **uTLS** over TCP. This monorepo unites the shared protocol core and all four platform clients/gateways around a single zero-duplication codebase.

---

## Architecture & Core Capabilities

- **GFT-RTC Custom UDP Engine (`internal/gftrtc`)**:
  - **1-RTT WebRTC Wire Mimicry**: RFC 5389 ICE-STUN handshake (`Binding Request/Success` with CRC32 `FINGERPRINT` and swept anti-replay guard) upgrading into AES-128-GCM / ChaCha20-Poly1305 encrypted RFC 3550 RTP/SRTP data frames and periodic RTCP mimicry packets.
  - **Adaptive Word-Aligned XOR-FEC**: Dynamic parity sizing based on live loss rate with `8 ms` early flush and single-packet `0 ms` ring recovery.
  - **Zero-HOL SACK Multiplexing**: 64-bit packet space, `8192`-bit sliding replay window, 32-interval SACK, RACK + PTO recovery, exact early-close stream flow-control accounting, and anti-deadlock window patrol.
  - **Smart-Brutal Congestion Control**: Dual-zone latency-gradient controller distinguishing carrier UDP policing from real queue buildup with micro-burst pacing and `Auto-Probe` bandwidth estimation.
  - **Make-Before-Break Port Hopping**: AEAD-authenticated `FramePing`/`FramePong` probing across candidate UDP sockets prior to atomic traffic migration.
- **Dual-Stack Scheduler & uTLS Fallback (`internal/gft`)**:
  - `ApexScheduler` manages concurrent `GFT-RTC` sessions with least-loaded scheduling, proportional bandwidth splitting, and Chrome PQ `uTLS` + `RecordSplitConn` SNI splitting failover (`Auto` | `RTC` | `TCP`).
  - Pre-TLS `SessionID` steganography and `RewindConn` transparent origin mirroring (`internal/server`, `internal/sni`) defend against active probes with zero key leakage.
- **Cross-Platform Network Binding & NAT64 (`internal/netbind`)**:
  - Linux `SO_MARK` anti-loop tagging, Darwin `IP_BOUND_IF`/`IPV6_BOUND_IF` interface pinning, and pure-Go RFC 7050 (`ipv4only.arpa`) / RFC 6052 NAT64 IPv6 synthesis for IPv6-only cellular networks.
- **Built-In Multi-Category RuleSet & CN CIDR Engine (`internal/client`)**:
  - Categorized domain rules (AI, Google, Dev, Social, Streaming, CN Direct, Apple/Microsoft/Steam CN CDNs, Ad/Tracker blocklist) paired with a compact zlib-embedded APNIC Mainland China IPv4 CIDR table (`cn_ipv4.zlib`).

---

## Supported Platforms

| Component | Entry Point / Packages | Key Highlights |
| :--- | :--- | :--- |
| **Linux Server & TUI** | `cmd/gft-server`, `internal/{server,sni,qr,tui}` | Interactive `gft` TUI, OTA upgrade/rollback, QR sharing, SSRF guard (`198.18.0.0/15`, `100.64.0.0/10` & private ranges) |
| **Headless CLI Core** | `cmd/gft-core`, `internal/client` | Lightweight SOCKS5/HTTP daemon with `-low-mem` mode for Linux / ARM64 routers |
| **Windows Desktop GUI** | `cmd/gft-client-gui`, `internal/winui` | Single-binary (`GhostFrame-Pro.exe`) native Win32/GDI+/DWM GUI & tray, `Rule \| Global \| Core`, Registry backup |
| **iOS Dual Editions** | `ios/`, `mobile/`, `internal/tunstack/` | **GhostFrameVPN** (`NEPacketTunnelProvider` True TUN L3/L4 `gVisor` stack + Fake-IP persistence + iOS 18 Control Center `AudioPlaybackIntent` widget + `autoreleasepool` batching) & **GhostFrameCompanion** (portable local proxy) |
| **iStoreOS / OpenWrt (`0Ghost`)** | `cmd/0ghost`, `internal/tproxy`, `openwrt/luci-app-0ghost/` | Phicomm N1 (`linux/arm64`) `fw4 nftables` TPROXY / `REDIRECT` fallback, Split-DNS (`:7853`), full APNIC `@cn_ipv4` set + `/etc/0ghost/cn_ipv4.txt` override, `hotplug.d` + 12s watchdog, CSRF/Host-protected WebUI (`:19080`), LuCI top-pinned panel |

> Note: `gvisor.dev/gvisor` is strictly isolated inside `internal/tunstack` and `mobile` so server, Windows desktop, and `0Ghost` builds never link `gvisor`.

---

## Repository Layout

```text
.
├── cmd/
│   ├── gft-server/             # Dual-stack server & `gft` TUI control center
│   ├── gft-core/               # Headless SOCKS5/HTTP Linux/router daemon
│   ├── gft-client-gui/         # Native Windows Win32/GDI+ client (`GhostFrame-Pro.exe`)
│   └── 0ghost/                 # iStoreOS arm64 transparent side-router daemon & WebUI (:19080)
├── internal/
│   ├── gftrtc/                 # GFT-RTC UDP engine (ICE-STUN, SRTP, XOR-FEC, SACK, Smart-Brutal)
│   ├── gft/                    # ApexScheduler, uTLS, RecordSplitConn, RewindConn, `gft3://`
│   ├── netbind/                # SO_MARK, Darwin IP_BOUND_IF, RFC 7050/6052 NAT64 synthesis
│   ├── client/                 # Engine, RuleSet, embedded APNIC CN IPv4 CIDR, Split DNS, proxies
│   ├── server/, sni/, qr/, tui/# Server outbound, non-CDN prober, QR renderer, TUI menu
│   ├── winui/                  # Pure-Go Win32/GDI+/DWM UI & tray icon
│   ├── tproxy/                 # Linux nftables/iptables TPROXY, Split-DNS, conflict detection
│   └── tunstack/               # gVisor L3/L4 Netstack & persistent Fake-IP DNS (iOS TUN only)
├── mobile/                     # GoMobile bindings (`GhostMobile.xcframework`)
├── ios/                        # XcodeGen specs & Swift sources (`GhostFrameVPN`, `GhostFrameCompanion`, `ControlWidget`)
├── openwrt/luci-app-0ghost/    # iStoreOS LuCI JS view, procd init, ACLs & hotplug hooks
├── tools/
│   ├── gen-ios-icon/           # Procedural AppIcon generator
│   └── ios-repo-sync/          # Zero-dependency OmniSign / AltStore LAN source server
├── configs/
│   └── client.example.json     # Sanitized client config template
├── docs/                       # Architecture and deployment documentation
├── scripts/                    # Installers, 0Ghost packager & workstation mirror helper
├── install.sh                  # One-line Linux server & gft-core installer
├── Makefile
├── go.mod
└── go.sum
```

---

## Quick Installation

### Linux Server (`gft-server`)

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/Spittingjiu/GhostFrame-TLS/main/install.sh)
```

Unattended server setup with UDP port hopping:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/Spittingjiu/GhostFrame-TLS/main/install.sh) \
  --unattended --port 443 --hop 25000-32000
```

### iStoreOS / OpenWrt (`0Ghost` Prebuilt Binary Bundle)

```sh
sh <(curl -fsSL https://raw.githubusercontent.com/Spittingjiu/GhostFrame-TLS/main/scripts/install-0ghost.sh)
```

### iOS OmniSign / ESign Local Repo Sync

```bash
go run ./tools/ios-repo-sync
```

Pulls the latest `Build iOS Dual Unsigned IPAs` artifacts into `.ios-dist/` and serves an OmniSign/AltStore compatible `source.json` over LAN HTTP (`0.0.0.0:18080`).

---

## Building & Verification

Requires Go `1.27+`:

```bash
# 1. Server (Linux amd64 / arm64)
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o dist/gft-server-linux-amd64 ./cmd/gft-server

# 2. Windows GUI Client (zero CGO, no gVisor)
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -H=windowsgui" -o dist/GhostFrame-Pro.exe ./cmd/gft-client-gui

# 3. 0Ghost Side-Router (Linux arm64)
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o dist/0ghost-linux-arm64 ./cmd/0ghost

# 4. Darwin / iOS Mobile Bridge & Netstack Check
GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go vet ./mobile/... ./internal/tunstack/...

# 5. Core, Server, Desktop & Router Unit Tests
GFT_NO_SYSPROXY=1 CGO_ENABLED=0 go vet ./cmd/... ./internal/...
GFT_NO_SYSPROXY=1 CGO_ENABLED=0 go test -count=1 ./cmd/... ./internal/...
```

---

## CI/CD & Cross-Repository Binary Distribution

All workflows under `.github/workflows/` use strict `paths` filters so platform changes only trigger the relevant runners:

- `ci.yml` — Core & server vet, `-race` tests (Linux & Windows), fuzz smoke tests, and cross-compile verification.
- `build-client.yml` — Windows GUI client (`GhostFrame-Pro.exe`) build, tracked-secret audit, and zero-`gvisor` check.
- `build-0ghost.yml` — `0ghost` (`arm64` / `amd64`) and offline `0ghost-istoreos-arm64.tar.gz` (`luci-app-0ghost`) packaging.
- `ios-dual-ipa.yml` — `macos-15` GoMobile + XcodeGen builds for `GhostFrame-VPN-Unsigned.ipa` and `GhostFrame-Companion-Unsigned.ipa`.
- `release-dist.yml` — On `v*` tags or manual `workflow_dispatch`, builds all platform binaries, `install.sh`, `install-0ghost.sh`, `checksums.txt`, and `source.json`. When `secrets.DIST_PUSH_TOKEN` is configured, assets are automatically published to `Spittingjiu/Ghost` Releases without exposing source code.

See [docs/architecture.md](docs/architecture.md) and [docs/deployment.md](docs/deployment.md) for deeper protocol details.

## License

Licensed under the [MIT License](LICENSE).
