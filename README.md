# GhostFrame-TLS (GFT) v3.2

> **Native Multi-Platform · Decentralized Non-CDN SNI Probing · Built-in `gft` TUI Control Center · Phicomm N1 / Router Hardware Tuning**

[![CI](https://github.com/Spittingjiu/GhostFrame-TLS/actions/workflows/ci.yml/badge.svg)](https://github.com/Spittingjiu/GhostFrame-TLS/actions/workflows/ci.yml)
[![Go Version](https://img.shields.io/badge/Go-1.26+-00ADD8?logo=go)](https://golang.org)
[![Platform](https://img.shields.io/badge/Platform-Linux%20(amd64%2Farm64)%20|%20Windows%20|%20OpenWrt-blue)](https://github.com/Spittingjiu/GhostFrame-TLS)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## ⚡ Architecture Highlights (v3.2)

1. **One-Line Deployment & Built-in `gft` Control Center (`internal/tui`)**:
   - Unified `gft-server` binary exposes an interactive UTF-8/ANSI-aligned dashboard (`gft` symlink or `gft-server menu`) with 4 transactional safety locks (process lockfile, `.bak` backup + atomic rename, isolated `nft`/`iptables` `gft_hop` namespace, and 2.5s health-probe automatic rollback on broken changes).
   - Pure-Go embedded terminal half-block QR generator, multi-platform delivery card (Windows / Phicomm N1 / OpenClash), audit IP banning, OTA release updater with SHA-256 verification, and clean uninstall.
2. **Decentralized Non-CDN SNI Probing & Key-Preserving Rotation (`internal/sni`)**:
   - Zero centralized CDN or vendor defaults: concurrently probes regional university/research origins (`APAC-JP-KR`, `APAC-SG-HK`, `NA`, `EU`), enforces 4 checks (public non-self IP, TLS 1.3 + `h2`, CDN fingerprint exclusion, low RTT), and randomly selects among Top-5 via `crypto/rand`.
   - `RotateSNI` preserves the server private key so SPKI `Pin` stays identical for existing clients during SNI rotation.
3. **Unified Core Across Desktop & Phicomm N1 / Routers**:
   - **Windows (`GhostFrame-Pro.exe`)**: 100% pure Go zero-CGO native Win32/GDI+/DWM console + dynamic vector system tray (`internal/winui`), zero browser wrappers, `-no-sysproxy` / `GFT_NO_SYSPROXY=1` sandbox protection.
   - **Linux / Phicomm N1 S905D / OpenWrt (`gft-core`)**: Headless daemon with `-low-mem` (`4MB` stream window & bounded pool <35MB RSS) and automatic `ChaCha20-Poly1305` prioritization when ARM64 hardware lacks AES extensions.
4. **Dual-Track QUIC + uTLS Racing & Seamless UDP Continuity**:
   - Pre-TLS `SessionID` HMAC + Pre-QUIC `AuthPacketConn` silent drops + 0ms `RewindConn` mirroring.
   - Fragmented RFC 9221 Datagrams (`<=8192B`) + multiplexed QUIC stream UDP fallback (`<=65507B`) + `ClientID` NAT port preservation across 35–65s UDP port hopping and QUIC↔TCP failovers.

```text
[Apps / Games / OpenClash / Mihomo]
        │  SOCKS5 (TCP + UDP ASSOCIATE) / HTTP CONNECT
        ▼
[GhostFrame-Pro.exe (Win32) | gft-core (N1 arm64 / Linux)]
  ├─ Router: CN-IP / CN-Domain Bypass (Zero Local DNS Leak)
  ├─ ApexScheduler (ClientID NAT Preservation + SchedulerUDPAssoc)
  │    ├─ [QUIC Track]: Fragmented Datagrams / Stream UDP + Port Hopping
  │    └─ [TCP Pool]:  uTLS Chrome PQ + SNI Record Split + ChaCha20 (N1 S905D)
        ▼  TCP/UDP :443 (+ isolated gft_hop UDP range -> :443)
[gft-server (Dual-Stack) + `gft` TUI]
  ├─ TCP MirrorInspector ──► Pass: TLS 1.3 + ClientAuth(ClientID) ──► Shared NAT Pool
  │                      └── Fail: 0ms RewindConn Bridge ──► Auto-Probed Non-CDN SNI
  └─ UDP AuthPacketConn  ──► Pass: QUIC + Fragment Reassembly ──► Shared NAT Pool
                         └── Fail: 100% Silent Drop
```

---

## 🚀 Quick One-Line Install

### Server (Ubuntu / Debian / Rocky / Arch Linux)
```bash
bash <(curl -fsSL https://raw.githubusercontent.com/Spittingjiu/GhostFrame-TLS/main/install.sh)
```

Unattended server setup with port hopping:
```bash
bash <(curl -fsSL https://raw.githubusercontent.com/Spittingjiu/GhostFrame-TLS/main/install.sh) \
  --unattended --port 443 --hop 20000-30000
```

After installation, type `gft` at any time to open the control center.

### Client Daemon (Phicomm N1 / OpenWrt procd / Armbian / Linux Router)
```bash
bash <(curl -fsSL https://raw.githubusercontent.com/Spittingjiu/GhostFrame-TLS/main/install.sh) \
  --role client --link "gft3://..." --socks 0.0.0.0:10808 --low-mem
```

---

## 🛠️ Building from Source

```bash
cd 02_Source_Code

# 1. Server (Linux amd64 / arm64)
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o gft-server-linux-amd64 ./cmd/gft-server

# 2. Router / N1 Core (Linux arm64)
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o gft-core-linux-arm64 ./cmd/gft-core

# 3. Windows Native GUI & Tray Client
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="-s -w -H=windowsgui" -o ../GhostFrame-Pro.exe ./cmd/gft-client-gui
```

---

## 🧪 Testing & Safe Sandbox

All tests and sandboxed client launches avoid mutating Windows Registry Internet Settings automatically (`testing.Testing()` / `GFT_NO_SYSPROXY=1` / `-no-sysproxy`):

```bash
cd 02_Source_Code
GFT_NO_SYSPROXY=1 go vet ./...
GFT_NO_SYSPROXY=1 go test -race -v ./...
```

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
