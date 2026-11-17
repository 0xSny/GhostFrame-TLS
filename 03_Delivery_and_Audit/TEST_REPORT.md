# GhostFrame-TLS (GFT) v3.2 Apex 测试与安全审计报告

> 隐私脱敏版本：所有公网服务器 IP、本地路径、私钥及控制面板凭证均已剔除或替换为 RFC 5737 示例地址 (`198.51.100.10`)。

## 一、v3.2 Apex 核心安全与架构特性

- **Pre-TLS 零特征隐写握手 (`SessionID`)**：基于 `uTLS HelloChrome_Auto`（含 `X25519MLKEM768` 后量子 KeyShare），将 `Salt(16B) || HMAC-SHA256(...)[0:16]` 强绑定至当前 `ClientRandom` 与 30s 时间窗；在无 AES 硬件扩展的 ARM64（如斐讯 N1 S905D）上自动置顶 `ChaCha20-Poly1305`。
- **0ms `MirrorInspector` 去中心化非 CDN 透明反射**：服务端在 TLS 握手前对 ClientHello 前 76 字节做分段重组与 HMAC 验真，未授权探测包零延迟无损回放并双向透传至并发体检优选的非 CDN 高校/科研 SNI 或本地 Web 服务。
- **SNI Record 分片 (`RecordSplitConn`)**：仅对首个 ClientHello 记录按 SNI 中点（±4 字节抖动、0-5ms 间隔）切分为 2~3 个合法 TLS Record。
- **Pre-QUIC 静默丢弃 (`AuthPacketConn`) + 全尺寸 UDP 连续性**：未携带有效隐写 CID 的扫描包 100% 静默丢弃；支持分片 RFC 9221 Datagrams（至 8192B）+ `quicStreamUDP` 流式兜底（至 65507B），配合 8B `ClientID` 在 35-65s 端口跳跃及双栈切换期间保持 UDP 0 丢包与 NAT 源端口零漂移。
- **Dual-Track Racing (`ApexScheduler`)**：令牌桶限流（容量 2、速率 2/s、+50~200ms 抖动），UDP 阻断或劣化时 0ms 自动熔断切换至 uTLS TCP 连接池。
- **原生多端与注册表沙箱保护**：Windows 端采用纯 Go zero-CGO Win32/GDI+/Shell32 原生窗口与系统托盘 (`GhostFrame-Pro.exe`)；内置 `GFT_NO_SYSPROXY=1` / `-no-sysproxy` / `testing.Testing()` 沙箱锁防止误改宿主机代理；Linux / 斐讯 N1 盒子采用极简无头 `gft-core` (`-low-mem` 模式 4MB 窗口)；服务端内置 `gft` 等宽对齐 TUI 控制中心与四道事务回滚锁。
