# GhostFrame-TLS (GFT)

[![CI](https://github.com/Spittingjiu/GhostFrame-TLS/actions/workflows/ci.yml/badge.svg)](https://github.com/Spittingjiu/GhostFrame-TLS/actions/workflows/ci.yml)
[![Go Version](https://img.shields.io/badge/Go-1.26+-00ADD8?logo=go)](https://golang.org)
[![Platform](https://img.shields.io/badge/Platform-Linux%20(amd64%2Farm64)%20|%20Windows%20|%20OpenWrt-blue)](https://github.com/Spittingjiu/GhostFrame-TLS)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

GhostFrame-TLS is a dual-stack (QUIC + uTLS) stealth transport proxy written in pure Go (`CGO_ENABLED=0`), featuring zero-feature Pre-TLS/Pre-QUIC authentication, seamless lossless origin mirroring, striped multi-tuple QUIC port hopping, a terminal control center (`gft`), and a native Win32/GDI+ desktop client (`GhostFrame-Pro.exe`).

## Features

- **Dual-Stack Adaptive Transport (`internal/gft`)**:
  - **Striped QUIC Pool (`DefaultQUICPoolSize = 3`)**: Maintains concurrent QUIC sessions across independent UDP 5-tuples with staggered 35–65s port hopping, least-loaded stream scheduling, `8 MB` UDP socket buffers, `4 MB / 8 MB` initial flow-control windows, and `InitialPacketSize: 1250`.
  - **uTLS TCP Fallback**: Chrome PQ ClientHello fingerprint with SNI record splitting (`RecordSplitConn`), `4 MB` initial Mux window (`16 MB` max, `1500 ms` BDP scaling), and `63 KB` framing chunks.
  - **Full-Size UDP Continuity**: Fragmented RFC 9221 Datagrams (`<= 8192 B`) + QUIC UDP stream fallback (`<= 65507 B`) with persistent `ClientID` NAT binding across hops and failovers.
- **Active-Probe Immunity (`internal/server`, `internal/sni`)**:
  - Pre-TLS `SessionID` HMAC verified before TLS completion via `MirrorInspector` and `RewindConn`; unauthorized TCP probes are transparently bridged to a probed non-CDN academic/research origin without key leakage.
  - Pre-QUIC `AuthPacketConn` validates steganographic 16-byte Connection IDs and silently drops unauthorized UDP probes.
- **Multi-Platform Clients & Control Center (`cmd/`, `internal/winui`, `internal/tui`)**:
  - **Windows (`cmd/gft-client-gui`)**: Zero-CGO native Win32/GDI+/DWM GUI with system tray, custom-drawn numeric hot-swap port editor (`Engine.SetProxyPorts`), crash-safe Windows Registry proxy backup, and `-no-sysproxy` / `GFT_NO_SYSPROXY=1` test sandbox lock.
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
│   ├── client/             # Engine, Rule/Global/Core router, SOCKS5/HTTP, sysproxy
│   ├── gft/                # Protocol core (QUIC pool, uTLS, Mux, stego auth, rewind)
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
GFT_NO_SYSPROXY=1 go test -race -v ./...
```

See [docs/architecture.md](docs/architecture.md) and [docs/deployment.md](docs/deployment.md) for protocol internals and operational guidance.

## License

Licensed under the [MIT License](LICENSE).
