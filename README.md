# GhostFrame-RTC (GFT)

[![CI](https://github.com/Spittingjiu/GhostFrame-TLS/actions/workflows/ci.yml/badge.svg)](https://github.com/Spittingjiu/GhostFrame-TLS/actions/workflows/ci.yml)
[![Go Version](https://img.shields.io/badge/Go-1.26+-00ADD8?logo=go)](https://golang.org)
[![Platform](https://img.shields.io/badge/Platform-Linux%20(amd64%2Farm64)%20|%20Windows%20|%20OpenWrt-blue)](https://github.com/Spittingjiu/GhostFrame-TLS)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

GhostFrame-RTC (v3.4) is a dual-stack (custom `GFT-RTC` over UDP + `uTLS` over TCP) stealth transport proxy written in 100% pure Go (`CGO_ENABLED=0`, zero third-party QUIC dependencies). It features RFC 5389 ICE-STUN authentication, SRTP-mimicked AEAD packet encapsulation, `uint64` word-aligned adaptive XOR-FEC, zero-HOL-blocking SACK multiplexing, `Smart-Brutal` congestion control, zero-feature Pre-TLS origin mirroring, a terminal control center (`gft`), and a native Win32/GDI+ desktop client (`GhostFrame-Pro.exe`).

## Features

- **Custom UDP Protocol Engine (`internal/gftrtc`)**:
  - **WebRTC Wire Mimicry (`wire.go`)**: 1-RTT RFC 5389 ICE-STUN handshake (`Binding Request/Success` with CRC32 `FINGERPRINT` and 180s anti-replay guard) upgrading into RFC 3550 RTP/SRTP data frames (`PT=96/111`, 90kHz clock, AES-128-GCM / ChaCha20-Poly1305 AEAD, masked 8-byte sequence numbers, `sync.Pool` 1600B buffer reuse).
  - **Adaptive Word-Aligned XOR-FEC (`fec.go`)**: `<1.5%` loss disabled, `1.5%–6%` K=10 parity, `>=6%` K=6 parity with `8 ms` early flush and 64-slot ring 0ms single-packet recovery.
  - **Zero-HOL-Blocking SACK Mux (`ack_sack.go`, `stream.go`)**: 64-bit packet space, 512-bit sliding replay window, 32-interval SACK, RACK + PTO loss recovery, independent per-stream `4 MB -> 16 MB` flow windows (`1 MB -> 4 MB` in `-low-mem` mode), and fragmented `UDPAssociation` + reliable stream fallback (`> 16 KB`).
  - **Smart-Brutal Congestion Control (`cc_smart_brutal.go`)**: Dual-zone latency-gradient controller distinguishing carrier UDP policing (`Zone A`: Auto-Probe `+35%/RTT` SlowStart, `0.95*B_est` Cruise, periodic `+15%` probe, `<=1.35x` compensation) from true queue buildup (`Zone B`: `0.80x` backoff gated on `rho > 1.65 && srtt-minRTT >= 25ms` or `ptoCount >= 3`) with 60fps (`12–16 ms`) micro-burst pacing.
  - **0ms In-Place Port Hopping (`session.go`)**: Hot-swaps ephemeral UDP sockets (`8 MB` buffers) every `25–50 s` with 3s graceful drain while preserving session identity and outbound `ClientID` NAT bindings.
- **Dual-Stack Scheduler & uTLS Fallback (`internal/gft`)**:
  - `ApexScheduler` runs `DefaultRTCPoolSize = 2` concurrent GFT-RTC sessions with least-loaded scheduling alongside Chrome PQ `uTLS` + `RecordSplitConn` SNI splitting and isolated `rtcLimiter` / `tcpLimiter` token buckets.
- **Active-Probe Immunity (`internal/server`, `internal/sni`)**:
  - Unauthenticated or malformed STUN/RTP packets are silently dropped with zero response bytes.
  - Pre-TLS `SessionID` HMAC verified before TLS completion via `MirrorInspector` and `RewindConn`; unauthorized TCP probes are transparently bridged to a probed non-CDN academic/research origin without key leakage.
- **Multi-Platform Clients & Control Center (`cmd/`, `internal/winui`, `internal/tui`)**:
  - **Windows (`cmd/gft-client-gui`)**: Zero-CGO native Win32/GDI+/DWM GUI (`920x690`) with `Auto | RTC | TCP` switcher, custom-drawn numeric `up_mbps` / `down_mbps` Smart-Brutal editor and hot-swap port editor, system tray, crash-safe Registry proxy backup, and `-no-sysproxy` / `GFT_NO_SYSPROXY=1` sandbox mode.
  - **Linux / ARM64 Router (`cmd/gft-core`)**: Headless SOCKS5/HTTP daemon with `-low-mem` mode and hardware-aware `ChaCha20-Poly1305` prioritization on AES-less ARM64 SoCs.
  - **Server (`cmd/gft-server`)**: Interactive `gft` TUI menu with transactional rollback locks, terminal QR rendering, and `gft_hop` firewall isolation.

## Repository Layout

```text
.
├── cmd/
│   ├── gft-client-gui/     # Native Windows Win32/GDI+ desktop & tray client
│   ├── gft-core/           # Headless Linux/OpenWrt/ARM64 client daemon
│   └── gft-server/         # Dual-stack server & `gft` TUI control center
├── internal/
│   ├── gftrtc/             # Pure-Go GFT-RTC UDP protocol (STUN/SRTP/FEC/SACK/Smart-Brutal)
│   ├── gft/                # ApexScheduler, RTC bridge, uTLS, Mux, RewindConn, ClientID
│   ├── client/             # Engine, Rule/Global/Core router, SOCKS5/HTTP, sysproxy
│   ├── server/             # Server runtime, outbound NAT, embedded stealth panel
│   ├── sni/                # Non-CDN origin pool & concurrent 4-check prober
│   ├── tui/                # `gft` interactive TUI, firewall manager, transactional rollback
│   └── winui/              # Pure-Go Win32/GDI+/DWM/Shell32 UI & system tray
├── configs/
│   └── client.example.json # Sanitized client configuration template
├── docs/
│   ├── architecture.md     # Protocol & transport architecture specification
│   └── deployment.md       # Server, Windows, N1/OpenWrt, and Clash Meta guide
├── .github/workflows/      # CI & multi-arch zero-CGO release pipelines
├── install.sh              # One-line Linux server & router installer
├── Makefile
├── go.mod
└── go.sum
```

## Quick Install

### Server (Ubuntu / Debian / Rocky / Arch Linux)

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/Spittingjiu/GhostFrame-TLS/main/install.sh)
```

Unattended install with UDP port hopping:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/Spittingjiu/GhostFrame-TLS/main/install.sh) \
  --unattended --port 443 --hop 25000-32000
```

Run `gft` anytime to open the interactive control center.

### Router / Headless Client (`gft-core`)

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/Spittingjiu/GhostFrame-TLS/main/install.sh) \
  --role client --link "gft3://..." --socks 0.0.0.0:10808 --low-mem
```

## Building from Source

Requires Go 1.26+. All targets compile with `CGO_ENABLED=0`:

```bash
# Server (Linux amd64 / arm64)
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o dist/gft-server-linux-amd64 ./cmd/gft-server

# Headless client core (Linux arm64 / amd64)
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o dist/gft-core-linux-arm64 ./cmd/gft-core

# Windows native GUI & tray client
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="-s -w -H=windowsgui" -o dist/GhostFrame-Pro.exe ./cmd/gft-client-gui
```

Or run `make build` / `make test`.

## Testing

Unit and integration tests automatically enable the in-memory system proxy sandbox (`IsMockSysProxy()`) so the host Windows Registry is never modified:

```bash
GFT_NO_SYSPROXY=1 go vet ./...
GFT_NO_SYSPROXY=1 CGO_ENABLED=0 go test -count=1 ./...
```

See [docs/architecture.md](docs/architecture.md) and [docs/deployment.md](docs/deployment.md) for protocol internals and operational guidance.

## License

Licensed under the [MIT License](LICENSE).
