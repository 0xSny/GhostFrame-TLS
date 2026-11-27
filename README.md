# Kestrel (`v4.2.6`)

[![CI (Core & Server)](https://github.com/Spittingjiu/GhostFrame-TLS/actions/workflows/ci.yml/badge.svg)](https://github.com/Spittingjiu/GhostFrame-TLS/actions/workflows/ci.yml)
[![Build Kestrel Pro](https://github.com/Spittingjiu/GhostFrame-TLS/actions/workflows/build-client.yml/badge.svg)](https://github.com/Spittingjiu/GhostFrame-TLS/actions/workflows/build-client.yml)
[![Build KestrelBox Side-Router](https://github.com/Spittingjiu/GhostFrame-TLS/actions/workflows/build-0ghost.yml/badge.svg)](https://github.com/Spittingjiu/GhostFrame-TLS/actions/workflows/build-0ghost.yml)
[![Build Kestrel iOS Dual IPAs](https://github.com/Spittingjiu/GhostFrame-TLS/actions/workflows/ios-dual-ipa.yml/badge.svg)](https://github.com/Spittingjiu/GhostFrame-TLS/actions/workflows/ios-dual-ipa.yml)
[![Go Version](https://img.shields.io/badge/Go-1.27+-00ADD8?logo=go)](https://golang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Kestrel** (powered by **Kestrel-RTC** / `ksl4://`) is a pure-Go (`CGO_ENABLED=0` for server, desktop, and router targets) dual-stack encrypted transport proxy combining custom UDP **Kestrel-RTC** transport and Chrome post-quantum **uTLS** over TCP. Wire-compatible with legacy `gft3://` / `gft2://` links.

---

## Architecture & Core Capabilities

- **Kestrel-RTC Custom UDP Engine (`internal/gftrtc`)**:
  - **1-RTT WebRTC Wire Mimicry**: RFC 5389 ICE-STUN handshake (`Binding Request/Success` with CRC32 `FINGERPRINT` and swept anti-replay guard) upgrading into AES-128-GCM / ChaCha20-Poly1305 encrypted RFC 3550 RTP/SRTP data frames and periodic RTCP mimicry packets.
  - **Adaptive Word-Aligned XOR-FEC**: Dynamic parity sizing based on live loss rate with `8 ms` early flush and single-packet `0 ms` ring recovery.
  - **Zero-HOL SACK Multiplexing**: 64-bit packet space, `8192`-bit sliding replay window, 32-interval SACK, RACK + PTO recovery, exact early-close stream flow-control accounting, and anti-deadlock window patrol.
  - **Smart-Brutal Congestion Control**: Dual-zone latency-gradient controller distinguishing carrier UDP policing from real queue buildup with micro-burst pacing and `Auto-Probe` bandwidth estimation.
  - **Make-Before-Break Port Hopping**: AEAD-authenticated `FramePing`/`FramePong` probing across candidate UDP sockets prior to atomic traffic migration.
- **Dual-Stack Scheduler & uTLS Fallback (`internal/gft`)**:
  - `ApexScheduler` manages concurrent `Kestrel-RTC` sessions with least-loaded scheduling, proportional bandwidth splitting, and Chrome PQ `uTLS` + `RecordSplitConn` SNI splitting failover (`Auto` | `RTC` | `TCP`).
  - Pre-TLS `SessionID` steganography and `RewindConn` transparent origin mirroring (`internal/server`, `internal/sni`) defend against active probes with zero key leakage.
- **Cross-Platform Network Binding & NAT64 (`internal/netbind`)**:
  - Linux `SO_MARK` anti-loop tagging, Darwin `IP_BOUND_IF`/`IPV6_BOUND_IF` interface pinning, and pure-Go RFC 7050 (`ipv4only.arpa`) / RFC 6052 NAT64 IPv6 synthesis for IPv6-only cellular networks.
- **Smart CN DNS Pre-Probe & APNIC CIDR Engine (`internal/client`)**:
  - Categorized domain rules (AI, Google, Dev, Social, Streaming, CN Direct, Apple/Microsoft/Steam/WeChat/Game CDNs) paired with a compact zlib-embedded full APNIC Mainland China IPv4/IPv6 CIDR table (`cn_ipv4.zlib` / `cn_ipv6.zlib`) and a 350ms leak-free CN DNS pre-probe for unknown domains.

---

## Supported Platforms

| Component | Entry Point / Packages | Key Highlights |
| :--- | :--- | :--- |
| **Linux Server & TUI** | `cmd/gft-server`, `internal/{server,sni,qr,tui}` | `kestrel-server` / `ksl` TUI, OTA upgrade/rollback, `ksl4://` QR sharing, SSRF guard (`198.18.0.0/15`, `100.64.0.0/10` & private ranges) |
| **Headless CLI Core** | `cmd/gft-core`, `internal/client` | `kestrel-core` lightweight SOCKS5/HTTP daemon with `-low-mem` mode for Linux / ARM64 routers |
| **Windows Desktop GUI** | `cmd/gft-client-gui`, `cmd/kestrel-setup`, `internal/{winui,wininstall}` | WebView2 + Win32/DWM GUI & tray, `Kestrel-Pro-Setup` NSIS-free pure-Go installer, GitHub OTA updater (`SHA-256` + `MZ`), Registry backup |
| **Android Client** | `android/`, `mobile/`, `internal/tunstack/` | Kotlin/Compose UI + `VpnService` + GoMobile AAR + `gVisor` L3/L4 TUN stack (`Rule \| Global \| Core`) |
| **iOS Dual Editions** | `ios/`, `mobile/`, `internal/tunstack/` | **Kestrel Duo** (`NEPacketTunnelProvider` True TUN L3/L4 `gVisor` stack + Fake-IP persistence + iOS 18 Control Center `AudioPlaybackIntent` widget) & **Kestrel Air** (portable single-process mode) |
| **iStoreOS / OpenWrt (`KestrelBox`)** | `cmd/0ghost`, `internal/tproxy`, `openwrt/luci-app-0ghost/` | Phicomm N1 (`linux/arm64`) `kbox` `fw4 nftables` TPROXY / `REDIRECT` fallback, Split-DNS (`:7853`), full APNIC `@cn_ipv4` set + `/etc/kbox/cn_ipv4.txt` override, `hotplug.d` + 12s watchdog, bootstrap-token/password-gated WebUI (`127.0.0.1:19080` + `/kbox/`), LuCI top-pinned `KestrelBox` panel |

> Note: `gvisor.dev/gvisor` is strictly isolated inside `internal/tunstack` and `mobile` so server, Windows desktop (`Kestrel Pro`), and `KestrelBox` builds never link `gvisor`.

### Operating Modes & Upgrade Paths

| Concept | Behavior | Notes |
| :--- | :--- | :--- |
| **System Interception (`Rule` / `Global`)** | Takes over OS proxy (Windows WinINET) or system VPN/TUN (`Android` / `iOS Duo` / `KestrelBox`) | `Rule` bypasses LAN & Mainland China; `Global` tunnels all non-LAN traffic |
| **Local Proxy Only (`Core`)** | Runs local SOCKS5 (`:10808`) & HTTP (`:10809`) listeners without modifying OS proxy or mounting TUN/TPROXY | Ideal for manual per-app proxy or upstream chaining |
| **Installer vs Portable Upgrade** | `Kestrel-Pro-Setup` installs to `%LocalAppData%\Kestrel` with Start Menu shortcut & uninstaller; portable `.exe` updates in-place | Router `install-kbox.sh` verifies signed `kbox-manifest.txt` (`RELEASE_SIGNING_KEY_PEM` / `--pubkey`) before stopping `kbox` |

---

## Repository Layout

```text
.
├── cmd/
│   ├── gft-server/             # Dual-stack server & `ksl` TUI control center (`kestrel-server`)
│   ├── gft-core/               # Headless SOCKS5/HTTP Linux/router daemon (`kestrel-core`)
│   ├── gft-client-gui/         # Windows WebView2/Win32 desktop client (`Kestrel-Pro.exe`)
│   ├── kestrel-setup/          # Pure-Go Windows installer (`Kestrel-Pro-Setup.exe`)
│   └── 0ghost/                 # iStoreOS arm64 transparent side-router daemon (`kbox`) & WebUI (:19080)
├── internal/
│   ├── gftrtc/                 # Kestrel-RTC UDP engine (ICE-STUN, SRTP, XOR-FEC, SACK, Smart-Brutal)
│   ├── gft/                    # ApexScheduler, uTLS, RecordSplitConn, RewindConn, `ksl4://`
│   ├── netbind/                # SO_MARK, Darwin IP_BOUND_IF, RFC 7050/6052 NAT64 synthesis
│   ├── client/                 # Engine, RuleSet, embedded APNIC CN IPv4/IPv6 CIDR, smart DNS probe, proxies
│   ├── server/, sni/, qr/, tui/# Server outbound, non-CDN prober, QR renderer, TUI menu
│   ├── winui/, wininstall/     # Pure-Go WebView2/Win32 UI, tray, shortcut & registry installer
│   ├── tproxy/                 # Linux nftables/iptables TPROXY, Split-DNS, conflict detection
│   └── tunstack/               # gVisor L3/L4 Netstack & persistent Fake-IP DNS (iOS Duo & Android VpnService)
├── mobile/                     # GoMobile bindings (`GhostMobile.xcframework` & `GhostMobile.aar`)
├── android/                    # Kotlin/Compose Android client (`KestrelVpnService`)
├── ios/                        # XcodeGen specs & Swift sources (`Kestrel Duo`, `Kestrel Air`, `KestrelControlWidget`)
├── openwrt/luci-app-0ghost/    # iStoreOS LuCI JS view (`kbox`), procd init, ACLs & hotplug hooks
├── tools/
│   ├── gen-ios-icon/           # Procedural AppIcon generator
│   └── ios-repo-sync/          # Zero-dependency OmniSign / AltStore LAN source server
├── configs/
│   └── client.example.json     # Sanitized client config template
├── docs/                       # Architecture and deployment documentation
├── scripts/                    # Installers (`install-kbox.sh`), packager & workstation mirror helper
├── install.sh                  # One-line Linux `kestrel-server` & `kestrel-core` installer
├── Makefile
├── go.mod
└── go.sum
```

---

## Quick Installation

### Linux Server (`kestrel-server`)

```bash
bash <(curl -fsSL https://github.com/Spittingjiu/Ghost/releases/latest/download/install.sh)
```

Unattended server setup with UDP port hopping:

```bash
bash <(curl -fsSL https://github.com/Spittingjiu/Ghost/releases/latest/download/install.sh) \
  --unattended --port 443 --hop 25000-32000
```

### iStoreOS / OpenWrt (`KestrelBox` Prebuilt Binary Bundle)

```sh
curl -fsSL https://github.com/Spittingjiu/Ghost/releases/latest/download/install-kbox.sh | sh
```

### iOS OmniSign / ESign Local Repo Sync

```bash
go run ./tools/ios-repo-sync
```

Pulls the latest `Build Kestrel iOS Dual IPAs` artifacts into `.ios-dist/` and serves an OmniSign/AltStore compatible `source.json` over LAN HTTP (`0.0.0.0:18080`).

---

## Building & Verification

Requires Go `1.27+`:

```bash
# 1. Server (Linux amd64 / arm64)
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o dist/kestrel-server-linux-amd64 ./cmd/gft-server

# 2. Windows GUI Client (zero CGO, no gVisor)
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -H=windowsgui" -o dist/Kestrel-Pro.exe ./cmd/gft-client-gui

# 3. KestrelBox Side-Router (Linux arm64)
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o dist/kbox-linux-arm64 ./cmd/0ghost

# 4. Darwin / iOS Mobile Bridge & Netstack Check
GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go vet ./mobile/... ./internal/tunstack/...

# 5. Core, Server, Desktop & Router Unit Tests
KSL_NO_SYSPROXY=1 CGO_ENABLED=0 go vet ./cmd/... ./internal/...
KSL_NO_SYSPROXY=1 CGO_ENABLED=0 go test -count=1 ./cmd/... ./internal/...
```

---

## CI/CD & Cross-Repository Binary Distribution

All workflows under `.github/workflows/` use strict `paths` filters so platform changes only trigger the relevant runners:

- `ci.yml` — Core & server vet, `-race` tests (Linux & Windows), fuzz smoke tests, and cross-compile verification.
- `build-client.yml` — Windows GUI client (`Kestrel-Pro.exe`) build, tracked-secret audit, and zero-`gvisor` check.
- `build-0ghost.yml` — `kbox` (`arm64` / `amd64`) and offline `kbox-istoreos-arm64.tar.gz` (`KestrelBox` LuCI panel) packaging.
- `ios-dual-ipa.yml` — `macos-15` GoMobile + XcodeGen builds for `Kestrel-Duo-Unsigned.ipa` and `Kestrel-Air-Unsigned.ipa`.
- `release-dist.yml` — On `v*` tags or manual `workflow_dispatch`, builds all platform binaries, `install.sh`, `install-kbox.sh` (+ compat `install-0ghost.sh`), `checksums.txt`, and `source.json`. When `secrets.DIST_PUSH_TOKEN` is configured, assets are automatically published to `Spittingjiu/Ghost` Releases without exposing source code.

See [docs/architecture.md](docs/architecture.md) and [docs/deployment.md](docs/deployment.md) for deeper protocol details.

## License

Licensed under the [MIT License](LICENSE).
