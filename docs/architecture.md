# GhostFrame-TLS Architecture

## Overview

```text
[Apps / Games / Clash Meta]
        │  SOCKS5 (TCP + UDP ASSOCIATE) / HTTP CONNECT
        ▼
[GhostFrame-Pro.exe (Win32) | gft-core (Linux / ARM64)]
  ├─ Router: Built-in CN-IP & CN-Domain direct bypass (no local DNS leak)
  ├─ ApexScheduler (ClientID NAT Preservation + Isolated tcpLimiter / quicLimiter)
  │    ├─ [Striped QUIC Pool]: 3 concurrent 5-tuples, 35-65s staggered hopping,
  │    │                       RFC 9221 Datagrams + stream fallback, 8MB UDP buffers
  │    └─ [TCP uTLS Pool]:     Chrome PQ ClientHello + SNI record split + 4MB->16MB Mux
        ▼  TCP/UDP :443 (+ optional UDP hop range -> :443)
[gft-server (Dual-Stack)]
  ├─ TCP MirrorInspector ──► Valid: TLS 1.3 + ClientAuth(ClientID) ──► Shared NAT Pool
  │                      └── Probe: 0ms RewindConn mirror ──► Probed Non-CDN SNI
  └─ UDP AuthPacketConn  ──► Valid: QUIC + Fragment Reassembly ──► Shared NAT Pool
                         └── Probe: Silent drop
```

## Protocol & Transport Layers

### 1. Pre-TLS & Pre-QUIC Steganography (`internal/gft`)

- **TCP (`MirrorInspector` + `RewindConn`)**: Clients embed a 32-byte steganographic `SessionID` (`Salt[16] || HMAC-SHA256(PSK, "gft-v3-tls" || Salt || ClientRandom || TimeBucket)[0:16]`) inside a Chrome uTLS `ClientHello` split across the SNI boundary (`RecordSplitConn`). Unauthorized probes are rewound byte-for-byte with `RewindConn` and relayed transparently to the configured mirror target.
- **UDP (`AuthPacketConn` + `StegoCIDGenerator`)**: QUIC Initial packets carry a 16-byte HMAC-authenticated Connection ID (`Salt[8] || HMAC-SHA256(PSK, "gft-v3-qcid" || Salt || TimeBucket)[0:8]`). Unauthenticated UDP packets are silently dropped before reaching `quic-go`.

### 2. High-BDP Flow Control (`mux.go`, `quic_engine.go`, `hardware.go`)

- **TCP Mux**: `63 KB` maximum payload chunks; `4 MB` initial stream window scaling dynamically up to `16 MB` within `1500 ms` consumption windows (`1 MB` / `4 MB` in `-low-mem` mode).
- **QUIC**: `4 MB` initial stream / `8 MB` initial connection receive windows (scaling to `16 MB` / `32 MB`), `InitialPacketSize: 1250` for PPPoE/NAT path safety, and `8 MB` OS UDP socket buffers (`TuneUDPSocketBuffers`) forwarded cleanly through `AuthPacketConn`.

### 3. Striped QUIC Pool & Failover (`scheduler.go`)

- When `hop_range` is configured, `ApexScheduler` maintains `DefaultQUICPoolSize = 3` concurrent `QUICSession` instances across independent local/remote UDP 5-tuples, rotating each slot independently every `35–65s` with graceful stream draining.
- `OpenStream` and `OpenUDP` select the healthy slot with the lowest active stream count (round-robin tie-breaker).
- `tcpLimiter` and `quicLimiter` are isolated so TCP handshake timeouts never starve QUIC dials or port hops.
- `SchedulerUDPAssoc` + 8-byte `ClientID` preserve server-side outbound NAT source ports across UDP port hops and QUIC↔TCP failovers.

### 4. Decentralized Non-CDN SNI Selection (`internal/sni`)

- Concurrently probes curated non-CDN university and research origins across regional pools (`APAC-JP-KR`, `APAC-SG-HK`, `NA`, `EU`), verifying public non-self IP resolution, TLS 1.3 + `h2`, absence of CDN headers, and low handshake RTT.
- `RotateSNI` swaps the server SNI and mirror target while preserving the ECDSA private key so existing client SPKI pins stay valid.
