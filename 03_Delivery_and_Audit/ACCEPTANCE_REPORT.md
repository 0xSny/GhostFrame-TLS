# GhostFrame-TLS (GFT) v3.2 工程交付说明

## 交付结构

- `install.sh`: Linux 服务端与斐讯 N1/OpenWrt `procd`/`systemd` 客户端一键部署脚本（含 NTP 校准、端口冲突无损引导、BBR+fq 与 25MB QUIC UDP 缓冲、SHA-256 强校验、`gft_hop` 独立防火墙表、自动选源与首屏交付卡）。
- `.github/workflows/ci.yml` & `.github/workflows/release.yml`: 双端 `go vet` / `go test -race` 持续集成与全平台 `CGO_ENABLED=0 -trimpath` 交叉编译发版流水线。
- `02_Source_Code/cmd/gft-server`: Linux/跨平台服务端入口与内置 `gft` TUI 交互控制中心 (`init` / `link` / `run` / `menu` / `show-card` / `sni-test`)。
- `02_Source_Code/cmd/gft-client-gui`: 100% 纯 Go 零 CGO 原生 Windows 图形控制台与托盘入口（`-ldflags="-s -w -H=windowsgui"` 单一 `GhostFrame-Pro.exe`；`-no-sysproxy` / `GFT_NO_SYSPROXY=1` 沙箱保护；`!windows` 提供无头守护模式）。
- `02_Source_Code/cmd/gft-core`: 轻量无头命令行客户端内核（适配斐讯 N1 `linux/arm64` / OpenWrt / x86 软路由，支持 `-link` 免配置启动、`-low-mem` 低内存档与 S905D 无 AES 指令集自动 `ChaCha20-Poly1305` 优先）。
- `02_Source_Code/internal/sni`: 去中心化非 CDN 高校/科研机构域名池 (`pool.go`) 与并发四重体检选源器 (`prober.go`) + 保留私钥无损换壳 (`RotateSNI`)。
- `02_Source_Code/internal/tui`: 东亚宽字符等宽对齐引擎 (`width.go`)、纯 Go 终端半块二维码 (`qr.go`)、独立防火墙表管理 (`firewall.go`)、四道事务回滚保护锁 (`tx.go`) 与 0-11 控制面板 (`menu.go`)。
- `02_Source_Code/internal/winui`: 纯 Go Windows 原生 GUI 与系统托盘包 (`user32` / `gdi32` / `gdiplus` / `dwmapi` / `shell32`)。
- `02_Source_Code/internal/gft`: 核心协议层 (`link.go`, `stealth.go`, `split_conn.go`, `auth_packet.go`, `quic_engine.go`, `scheduler.go`, `hardware.go`, `mux.go`, `pool.go`, `dial.go`, `rewind.go`, `knock.go`, `params.go`, `relay.go`)。
- `02_Source_Code/internal/server`: 服务端引擎 (`config.go`, `server.go`, `outbound.go`, `panel.go`, `blog.go`, `audit.go`, `stats.go`, `web/panel.html`)。
- `02_Source_Code/internal/client`: 客户端引擎 (`engine.go`, `router.go`, `socks5.go`, `httpproxy.go`, `sysproxy_backup.go`, `sysproxy_windows.go`, `sysproxy_other.go`)，内置注册表沙箱保护 (`IsMockSysProxy`)。

## 验证门禁

1. 宿主机零干扰验证：`go test`、`GFT_NO_SYSPROXY=1` 与 `-no-sysproxy` 模式下注册表 `ProxyEnable` / `ProxyServer` 零写入。
2. 去中心化选源与无损换壳：`gft-server sni-test` 并发测出非 CDN 低延迟源，`RotateSNI` 保持私钥与 SPKI `Pin` 不变。
3. TUI 排版对齐与自动回滚：CJK 混排右边框 0 错位；端口探测失败 2.5s 内自动回滚配置与防火墙规则。
4. 全平台编译与安全审计：`gft-server-linux-{amd64,arm64}`、`gft-core-linux-{amd64,arm64}`、`GhostFrame-Pro-windows-amd64.exe` 全部 `CGO_ENABLED=0 -trimpath` 编译通过，`bash -n install.sh` 通过，全仓无个人真实 IP、密钥或本地用户名残留。
