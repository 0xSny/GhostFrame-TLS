# GhostFrame-RTC (v3.4) Architecture

## Overview

```text
[Apps / Games / Clash Meta]
        │  SOCKS5 (TCP + UDP ASSOCIATE) / HTTP CONNECT
        ▼
[GhostFrame-Pro.exe (Win32) | gft-core (Linux / ARM64)]
  ├─ Router: Built-in CN-IP & CN-Domain direct bypass (no local DNS leak)
  ├─ ApexScheduler (ClientID NAT Preservation + Isolated rtcLimiter / tcpLimiter)
  │    ├─ [GFT-RTC Pool]:  2 concurrent UDP 5-tuples, STUN+SRTP AEAD mimicry,
  │    │                   uint64 XOR-FEC, zero-HOL SACK, Smart-Brutal CC, 0ms Hop
  │    └─ [TCP uTLS Pool]: Chrome PQ ClientHello + SNI record split + 4MB->16MB Mux
        ▼  TCP/UDP :443 (+ optional UDP hop range -> :443)
[gft-server (Dual-Stack)]
  ├─ TCP MirrorInspector ──► Valid: TLS 1.3 + ClientAuth(ClientID) ──► Shared NAT Pool
  │                      └── Probe: 0ms RewindConn mirror ──► Probed Non-CDN SNI
  └─ UDP RTCListener     ──► Valid: STUN+SRTP+FEC+SACK ──► Shared NAT Pool
                         └── Probe: 0-byte silent drop
```

## Protocol & Transport Layers

### 1. GFT-RTC UDP Protocol Engine (`internal/gftrtc`)

- **Phase 1 — 1-RTT RFC 5389 ICE-STUN Handshake (`wire.go`)**:
  - Clients send standard `Binding Request (0x0001)` packets containing `USERNAME`, `ICE-CONTROLLING`, `PRIORITY`, `ATTR_GFT_TICKET (0xC057)` (`ClientEphPub(X25519) || SealedAuth`), and trailing RFC 5389 Section 15.5 CRC32 `FINGERPRINT (0x8028)`.
  - Servers enforce a `±90s` clock skew check and `180s` `ReplayGuard` cache; invalid packets are dropped silently with zero response bytes. Valid requests receive `Binding Success (0x0101)` carrying `XOR-MAPPED-ADDRESS` and `ServerEphPub(X25519) || SealedAck`. Forward-secret `c2s`/`s2c` AEAD traffic keys are derived via HKDF-SHA256.
- **Phase 2 — SRTP-Mimicked Transport & 0ms Recovery (`wire.go`, `fec.go`, `ack_sack.go`)**:
  - Data packets use RFC 3550 RTP v2 headers (`PT=96/111`, 90kHz timestamps, SSRC, masked 8-byte packet numbers) and 1360B target MTU, reusing 1600B buffers via `sync.Pool`.
  - Adaptive `uint64` XOR-FEC disables redundancy below `1.5%` loss, enables `K=10` for `1.5%–6%`, and `K=6` above `6%` with `8 ms` early group flush and 64-slot ring recovery.
  - 64-bit packet numbers, 512-bit replay windows, 32-interval SACK, RACK + PTO loss detection, and Smart-Brutal latency-gradient pacing (`cc_smart_brutal.go`) avoid carrier policing collapses while backing off smoothly on real bottleneck queues.
- **Zero-HOL Streams & Port Hopping (`stream.go`, `session.go`)**:
  - Reliable `RTCStream` instances maintain independent byte queues (`4 MB -> 16 MB` window, `1 MB -> 4 MB` in `-low-mem` mode). `RTCUDPAssoc` sends 1–16 datagram fragments (`<= 16 KB`) and upgrades larger datagrams cleanly over `__gft_udp_stream__:1`.
  - `Hop()` migrates the session to a freshly bound `8 MB` UDP socket toward a new port in `hop_range` every `25–50 s` without interrupting streams, draining the previous socket after `3 s`.

### 2. TCP Fallback Track (`internal/gft`)

- **Pre-TLS Steganography (`MirrorInspector` + `RewindConn`)**: Clients embed a 32-byte steganographic `SessionID` inside a Chrome uTLS `ClientHello` split across the SNI boundary (`RecordSplitConn`). Unauthorized TCP probes are rewound byte-for-byte and relayed transparently to the configured non-CDN mirror target.
- **TCP Mux (`mux.go`)**: `63 KB` maximum payload chunks; `4 MB` initial stream window scaling dynamically up to `16 MB` (`1 MB` / `4 MB` in `-low-mem` mode).

### 3. Decentralized Non-CDN SNI Selection (`internal/sni`)

- Concurrently probes curated non-CDN university and research origins across regional pools (`APAC-JP-KR`, `APAC-SG-HK`, `NA`, `EU`), verifying public non-self IP resolution, TLS 1.3 + `h2`, absence of CDN headers, and low handshake RTT.
- `RotateSNI` swaps the server SNI and mirror target while preserving the ECDSA private key so existing client SPKI pins stay valid.
