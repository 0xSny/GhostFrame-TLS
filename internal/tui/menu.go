package tui

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"ghostframe/internal/gft"
	"ghostframe/internal/server"
	"ghostframe/internal/sni"
)

const (
	DefaultConfigPath = "/etc/gft/server.json"
	ReleaseRepo       = "Spittingjiu/GhostFrame-TLS"
	SysctlConfPath    = "/etc/sysctl.d/99-gft-apex.conf"
)

// Controller drives the interactive `gft` terminal control center.
type Controller struct {
	CfgPath string
	In      io.Reader
	Out     io.Writer
	Tx      *TransactionRunner
	Box     BoxStyle
}

func NewController(cfgPath string) *Controller {
	if cfgPath == "" {
		cfgPath = DefaultConfigPath
	}
	return &Controller{
		CfgPath: cfgPath,
		In:      os.Stdin,
		Out:     os.Stdout,
		Tx:      NewTransactionRunner(cfgPath),
		Box:     DefaultBoxStyle(76),
	}
}

func (c *Controller) printf(format string, args ...any) {
	_, _ = fmt.Fprintf(c.Out, format, args...)
}

func (c *Controller) okMsg(msg string) {
	c.printf("%s %s\n", c.Box.c("\x1b[32m", "[✓]"), msg)
}

func (c *Controller) warnMsg(msg string) {
	c.printf("%s %s\n", c.Box.c("\x1b[33m", "[!]"), msg)
}

func (c *Controller) errMsg(msg string) {
	c.printf("%s %s\n", c.Box.c("\x1b[31m", "[×]"), msg)
}

func (c *Controller) prompt(sc *bufio.Scanner, label string) string {
	c.printf("%s ", c.Box.c("\x1b[36m", label))
	if !sc.Scan() {
		return ""
	}
	return strings.TrimSpace(sc.Text())
}

func (c *Controller) pause(sc *bufio.Scanner) {
	c.printf("\n按 Enter 返回主菜单...")
	sc.Scan()
}

// RenderDashboard builds the boxed status & 0-11 menu frame with exact column alignment.
func (c *Controller) RenderDashboard(cfg *server.Config, active bool, bbrState string, snap server.RuntimeSnapshot, sniRTT time.Duration) string {
	b := c.Box
	var sb strings.Builder
	sb.WriteString(b.Top("GhostFrame-TLS (GFT) v3.2 Apex 交互控制中心") + "\n")

	svcBadge := b.c("\x1b[31m", "[○] 已停止")
	if active {
		svcBadge = b.c("\x1b[32m", "[●] 运行中")
	}
	quicBadge := "QUIC: 启用"
	if cfg.DisableQUIC {
		quicBadge = "QUIC: 关闭"
	}
	hopBadge := "关闭"
	if cfg.HopRange != "" {
		hopBadge = cfg.HopRange
	}
	rttTxt := "--"
	if sniRTT > 0 {
		rttTxt = fmt.Sprintf("%dms", sniRTT.Milliseconds())
	}

	port := ConfigListenPort(cfg.Listen)
	sb.WriteString(b.Line(fmt.Sprintf("服务状态: %s   |  内核拥塞: %s  |  监听端口: %d", svcBadge, bbrState, port)) + "\n")
	sb.WriteString(b.Line(fmt.Sprintf("双栈传输: %s  |  UDP 跳跃: %s   |  校验模式: %s", quicBadge, hopBadge, strings.ToUpper(cfg.CertMode))) + "\n")
	sb.WriteString(b.Line(fmt.Sprintf("伪装域名: %s (本机握手: %s) | 回落: %s", cfg.SNI, rttTxt, cfg.FallbackMode)) + "\n")
	sb.WriteString(b.Line(fmt.Sprintf("实时流量: ↑%s ↓%s (速率 ↑%s/s ↓%s/s) | 拦截探测: %d 次",
		fmtBytes(snap.TotalUp), fmtBytes(snap.TotalDown),
		fmtBytes(snap.UpBps), fmtBytes(snap.DownBps), snap.BlockedCount)) + "\n")
	sb.WriteString(b.Divider() + "\n")

	items := []string{
		"[1] 查看多端连接配置与终端二维码        [7] 威胁感知审计与探测 IP 封禁",
		"[2] 更换伪装域名 (SNI) 与回落策略       [8] 服务启停与实时彩色滚动日志",
		"[3] 修改监听端口与双栈通道开关          [9] 网络环境自检与内核加速调优",
		"[4] 配置 UDP 动态端口跳跃 (PortHop)     [10] 在线热更新与配置备份恢复",
		"[5] 轮换密钥、SPKI 证书与管理凭据       [11] 彻底卸载 GFT 服务端",
		"[6] 调整流量整形与硬件性能档位          [0] 退出控制面板",
	}
	for _, it := range items {
		sb.WriteString(b.Line(it) + "\n")
	}
	sb.WriteString(b.Bottom() + "\n")
	return sb.String()
}

// ShowDeliveryCard prints gft3:// link, half-block terminal QR, Windows/N1/Clash config.
func ShowDeliveryCard(cfgPath string, out io.Writer) error {
	c := NewController(cfgPath)
	c.Out = out
	cfg, err := server.LoadConfig(cfgPath)
	if err != nil {
		return err
	}
	p := gft.DefaultParams()
	if cfg.Params != nil && cfg.Params.Validate() == nil {
		p = *cfg.Params
	}
	uri := cfg.Link(p).Encode()
	qr, qerr := RenderTerminalQR(uri, c.Box.UTF8)

	b := c.Box
	c.printf("%s\n", b.Top("GhostFrame-TLS (GFT) v3.2 多端部署交付卡"))
	c.printf("%s\n", b.Line(fmt.Sprintf("节点地址: %s:%d   SNI: %s   Hop: %s",
		cfg.PublicHost, ConfigListenPort(cfg.Listen), cfg.SNI, nonEmpty(cfg.HopRange, "未开启"))))
	c.printf("%s\n", b.Bottom())

	c.printf("\n[1] 通用导入链接 (Windows GhostFrame-Pro.exe 按 Ctrl+V 直接导入):\n%s\n", uri)
	if qerr == nil {
		c.printf("\n[2] 终端扫描二维码:\n%s", qr)
	}
	c.printf("\n[3] 斐讯 N1 (S905D) / OpenWrt / Linux 无头内核启动命令:\n")
	c.printf("gft-core -low-mem -socks 0.0.0.0:10808 -link %q\n", uri)

	c.printf("\n[4] OpenClash / Mihomo 上游节点配置片段:\n")
	c.printf("proxies:\n  - name: \"GhostFrame-Apex\"\n    type: socks5\n    server: 127.0.0.1\n    port: 10808\n    udp: true\n")
	c.printf("\n提示: 在终端随时输入 `gft` 即可打开交互式管理控制中心。\n")
	return nil
}

// Run starts the interactive TUI loop.
func (c *Controller) Run() error {
	sc := bufio.NewScanner(c.In)
	sc.Buffer(make([]byte, 4096), 64*1024)

	for {
		cfg, err := server.LoadConfig(c.CfgPath)
		if err != nil {
			c.errMsg(fmt.Sprintf("无法加载配置 %s: %v", c.CfgPath, err))
			return err
		}
		active := c.Tx.ActiveFn()
		bbr := readBBRStatus()
		snap := readRuntimeSnapshot(cfg.StateDir)
		sniRTT := quickMeasureSNI(cfg.SNI)

		c.printf("\x1b[2J\x1b[H")
		c.printf("%s", c.RenderDashboard(cfg, active, bbr, snap, sniRTT))
		choice := c.prompt(sc, "请输入操作编号 [0-11]:")

		switch choice {
		case "0", "q", "exit":
			c.printf("已退出 GhostFrame-TLS 控制中心。\n")
			return nil
		case "1":
			_ = ShowDeliveryCard(c.CfgPath, c.Out)
			c.pause(sc)
		case "2":
			c.handleSNIMenu(sc, cfg)
		case "3":
			c.handlePortAndQUICMenu(sc, cfg)
		case "4":
			c.handleHopMenu(sc, cfg)
		case "5":
			c.handleRotateCredsMenu(sc, cfg)
		case "6":
			c.handleParamsMenu(sc, cfg)
		case "7":
			c.handleAuditMenu(sc, cfg)
		case "8":
			c.handleServiceAndLogsMenu(sc)
		case "9":
			c.handleSelfCheckMenu(sc, cfg)
		case "10":
			c.handleUpdateAndBackupMenu(sc, cfg)
		case "11":
			if c.handleUninstallMenu(sc) {
				return nil
			}
		default:
			c.warnMsg("无效输入，请选择 0-11。")
			time.Sleep(800 * time.Millisecond)
		}
	}
}

func (c *Controller) handleSNIMenu(sc *bufio.Scanner, cfg *server.Config) {
	c.printf("\n--- 更换伪装域名 (SNI) 与回落策略 ---\n")
	c.printf("  [1] 智能测速推荐 (并发探测区域高校/科研非 CDN 镜像站 Top-5)\n")
	c.printf("  [2] 手动输入冷门域名 (执行四重体检并无损换壳)\n")
	c.printf("  [3] 切换自有域名 ACME 真证书模式\n")
	c.printf("  [4] 配置本机网站共存反代 (Caddy/Nginx reverse_proxy)\n")
	c.printf("  [0] 返回\n")
	sub := c.prompt(sc, "请选择:")
	switch sub {
	case "1":
		c.printf("正在并发测速非 CDN TLS1.3+H2 候选池 (上限 3s)...\n")
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		results := sni.ProbeAll(ctx, nil, sni.ProbeOptions{SelfPublicIP: cfg.PublicHost})
		cancel()
		top := sni.QualifiedSorted(results)
		if len(top) == 0 {
			c.errMsg("未探测到满足 TLS 1.3 + H2 且无 CDN 特征的可用目标。")
			c.pause(sc)
			return
		}
		limit := minInt(5, len(top))
		b := BoxStyle{UTF8: c.Box.UTF8, Color: c.Box.Color, Width: 76}
		c.printf("%s\n", b.Top("推荐低延迟非 CDN 伪装源 Top-5"))
		for i := 0; i < limit; i++ {
			r := top[i]
			warn := ""
			if r.LatencyWarn {
				warn = " (>50ms)"
			}
			line := fmt.Sprintf("[%d] %-26s | %-11s | %3dms%s | %s",
				i+1, r.Domain, r.Region, r.HandshakeRTT.Milliseconds(), warn, TruncateToWidth(r.CertIssuer, 18))
			c.printf("%s\n", b.Line(line))
		}
		c.printf("%s\n", b.Bottom())
		selStr := c.prompt(sc, fmt.Sprintf("输入编号 [1-%d] 套用 (直接回车取消):", limit))
		idx, err := strconv.Atoi(selStr)
		if err != nil || idx < 1 || idx > limit {
			return
		}
		chosen := top[idx-1].Domain
		c.applyRotatedSNI(chosen)
	case "2":
		dom := c.prompt(sc, "请输入目标域名 (例 ftp.jaist.ac.jp):")
		if dom == "" {
			return
		}
		c.printf("正在对 %s 执行四重安全体检...\n", dom)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		r := sni.ProbeOne(ctx, "CUSTOM", dom, sni.ProbeOptions{SelfPublicIP: cfg.PublicHost})
		cancel()
		c.printProbeChecklist(r)
		if !r.DNSOK || !r.TLS13H2OK {
			c.errMsg("核心协议栈校验未通过，已拒绝写入。")
			c.pause(sc)
			return
		}
		if r.CDNDetected || r.LatencyWarn {
			confirm := c.prompt(sc, "检测到 CDN 或较高反射延迟 (>50ms)，仍要强制使用? [y/N]:")
			if !strings.EqualFold(confirm, "y") {
				return
			}
		}
		c.applyRotatedSNI(dom)
	case "3":
		dom := c.prompt(sc, "请输入已解析到本机的自有域名:")
		if dom == "" {
			return
		}
		email := c.prompt(sc, "请输入 ACME 通知邮箱 (可回车留空):")
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		ok, ips, derr := sni.CheckDomainPointsToIP(ctx, dom, cfg.PublicHost)
		cancel()
		if derr != nil || !ok {
			c.warnMsg(fmt.Sprintf("DNS 解析 %v 与本机公网 IP (%s) 不一致: %v", ips, cfg.PublicHost, derr))
			if !strings.EqualFold(c.prompt(sc, "仍要强制切换为 ACME 模式? [y/N]:"), "y") {
				return
			}
		}
		err := c.Tx.Apply(func(nc *server.Config) error {
			nc.CertMode = "acme"
			nc.SNI = dom
			nc.ACMEDomains = []string{dom}
			nc.ACMEEmail = email
			nc.Pin = ""
			return nil
		})
		if err != nil {
			c.errMsg(err.Error())
		} else {
			c.okMsg(fmt.Sprintf("已切换至 ACME 真证书模式 (域名 %s, Verify=ca)。", dom))
		}
	case "4":
		target := c.prompt(sc, "请输入本机反代地址 (例 http://127.0.0.1:8080):")
		if target == "" {
			return
		}
		err := c.Tx.Apply(func(nc *server.Config) error {
			nc.FallbackMode = "reverse_proxy"
			nc.FallbackTarget = target
			return nil
		})
		if err != nil {
			c.errMsg(err.Error())
		} else {
			c.okMsg("已切换为 reverse_proxy 共存回落模式 -> " + target)
		}
	}
	c.pause(sc)
}

func (c *Controller) applyRotatedSNI(domain string) {
	var newPin string
	err := c.Tx.Apply(func(nc *server.Config) error {
		_ = nc
		pin, rerr := server.RotateSNI(c.CfgPath, domain)
		if rerr != nil {
			return rerr
		}
		// Re-load mutated fields into nc so Tx SaveConfigAtomic keeps RotateSNI changes
		updated, lerr := server.LoadConfig(c.CfgPath)
		if lerr != nil {
			return lerr
		}
		*nc = *updated
		newPin = pin
		return nil
	})
	if err != nil {
		c.errMsg(err.Error())
		return
	}
	c.okMsg(fmt.Sprintf("已无损更换 SNI -> %s (复用原私钥，SPKI Pin 保持不变: %s)", domain, newPin))
}

func (c *Controller) printProbeChecklist(r sni.ProbeResult) {
	mark := func(ok bool, txt string) {
		if ok {
			c.printf("  %s %s\n", c.Box.c("\x1b[32m", "✓"), txt)
		} else {
			c.printf("  %s %s\n", c.Box.c("\x1b[33m", "!"), txt)
		}
	}
	mark(r.DNSOK, fmt.Sprintf("校验 1 DNS 合法性: %s (%s)", nonEmpty(r.ResolvedIP, "-"), nonEmpty(r.DNSErr, "非内网且未指向本机")))
	mark(r.TLS13H2OK, fmt.Sprintf("校验 2 TLS1.3+H2: 协商=%s 签发=%s (%s)", nonEmpty(r.Protocol, "-"), nonEmpty(r.CertIssuer, "-"), nonEmpty(r.TLSErr, "通过")))
	mark(!r.CDNDetected, fmt.Sprintf("校验 3 CDN 排雷: %s", nonEmpty(r.CDNReason, "无常见 CDN 特征")))
	mark(!r.LatencyWarn, fmt.Sprintf("校验 4 同区域延迟: %dms", r.HandshakeRTT.Milliseconds()))
}

func (c *Controller) handlePortAndQUICMenu(sc *bufio.Scanner, cfg *server.Config) {
	curPort := ConfigListenPort(cfg.Listen)
	c.printf("\n--- 监听端口 (%d) 与 QUIC 双栈 (%v) ---\n", curPort, !cfg.DisableQUIC)
	c.printf("  [1] 修改主监听端口 (将预检冲突并同步更新 Hop 目标端口)\n")
	c.printf("  [2] 切换 QUIC UDP 通道开关 (当前: %v)\n", !cfg.DisableQUIC)
	sub := c.prompt(sc, "请选择:")
	switch sub {
	case "1":
		pStr := c.prompt(sc, "请输入新端口 [1-65535]:")
		np, err := strconv.Atoi(pStr)
		if err != nil || np < 1 || np > 65535 {
			c.errMsg("端口无效")
			c.pause(sc)
			return
		}
		if np != curPort && CheckPortOccupied(np) {
			c.errMsg(fmt.Sprintf("端口 %d 已被本机其他进程占用，拒绝覆盖。", np))
			c.pause(sc)
			return
		}
		host, _, _ := net.SplitHostPort(cfg.Listen)
		if err := c.Tx.Apply(func(nc *server.Config) error {
			nc.Listen = net.JoinHostPort(host, strconv.Itoa(np))
			return nil
		}); err != nil {
			c.errMsg(err.Error())
		} else {
			c.okMsg(fmt.Sprintf("主监听端口已安全更新为 %d", np))
		}
	case "2":
		if err := c.Tx.Apply(func(nc *server.Config) error {
			nc.DisableQUIC = !nc.DisableQUIC
			return nil
		}); err != nil {
			c.errMsg(err.Error())
		} else {
			c.okMsg("QUIC 双栈开关已更新")
		}
	}
	c.pause(sc)
}

func (c *Controller) handleHopMenu(sc *bufio.Scanner, cfg *server.Config) {
	c.printf("\n--- UDP 动态端口跳跃 (当前: %s) ---\n", nonEmpty(cfg.HopRange, "未开启"))
	c.printf("  [1] 开启 / 修改端口跳跃范围 (例 20000-30000)\n")
	c.printf("  [2] 关闭 UDP 端口跳跃并清理独立防火墙链\n")
	sub := c.prompt(sc, "请选择:")
	switch sub {
	case "1":
		rng := c.prompt(sc, "请输入端口段 [1024-65535，例 20000-30000]:")
		lo, hi, err := ParseHopRange(rng)
		if err != nil {
			c.errMsg(err.Error())
			c.pause(sc)
			return
		}
		canon := fmt.Sprintf("%d-%d", lo, hi)
		if err := c.Tx.Apply(func(nc *server.Config) error {
			nc.HopRange = canon
			return nil
		}); err != nil {
			c.errMsg(err.Error())
		} else {
			c.okMsg("UDP 端口跳跃已启用: " + canon)
			c.warnMsg(fmt.Sprintf("重要提醒: 请在云厂商安全组/控制台放行 UDP %d-%d 入站规则！", lo, hi))
		}
	case "2":
		if err := c.Tx.Apply(func(nc *server.Config) error {
			nc.HopRange = ""
			return nil
		}); err != nil {
			c.errMsg(err.Error())
		} else {
			c.okMsg("已关闭 UDP 端口跳跃并销毁 gft_hop 防火墙表")
		}
	}
	c.pause(sc)
}

func (c *Controller) handleRotateCredsMenu(sc *bufio.Scanner, cfg *server.Config) {
	c.printf("\n--- 轮换密钥、证书与管理凭据 ---\n")
	c.printf("  [1] 轮换 32B PSK 预共享密钥\n")
	c.printf("  [2] 全量重新生成 ECDSA P-256 密钥对 (会改变 SPKI Pin)\n")
	c.printf("  [3] 重置秘密 Web 面板路径与管理员密码\n")
	switch c.prompt(sc, "请选择:") {
	case "1":
		psk, err := server.RotatePSK()
		if err != nil {
			c.errMsg(err.Error())
		} else if err := c.Tx.Apply(func(nc *server.Config) error { nc.PSK = psk; return nil }); err != nil {
			c.errMsg(err.Error())
		} else {
			c.okMsg("已轮换 PSK，请通过 [1] 重新复制客户端链接！")
		}
	case "2":
		if err := c.Tx.Apply(func(nc *server.Config) error { return server.RegenerateKeypair(nc) }); err != nil {
			c.errMsg(err.Error())
		} else {
			c.okMsg("已重签 ECDSA 证书与密钥对，SPKI Pin 已刷新！")
		}
	case "3":
		pPath, pPass, pHash, err := server.RotatePanelCreds()
		if err != nil {
			c.errMsg(err.Error())
		} else if err := c.Tx.Apply(func(nc *server.Config) error {
			nc.PanelPath = pPath
			nc.PanelHash = pHash
			return nil
		}); err != nil {
			c.errMsg(err.Error())
		} else {
			c.okMsg(fmt.Sprintf("面板路径: %s | 新密码: %s (仅显示这一次)", pPath, pPass))
		}
	}
	c.pause(sc)
}

func (c *Controller) handleParamsMenu(sc *bufio.Scanner, cfg *server.Config) {
	cur := gft.DefaultParams()
	if cfg.Params != nil && cfg.Params.Validate() == nil {
		cur = *cfg.Params
	}
	c.printf("\n--- 流量整形参数 (当前: Pad=%d..%dB Prob=%d%% HB=%d..%dms) ---\n",
		cur.PadMin, cur.PadMax, cur.PadProb, cur.HbMinMs, cur.HbMaxMs)
	c.printf("  [A] 旗舰极速档 (零负担直连体验: Pad 0-24B / 15%% / HB 25-60s)\n")
	c.printf("  [B] 抗封锁强混淆档 (高压环境推荐: Pad 16-128B / 60%% / HB 10-30s)\n")
	c.printf("  [C] 自定义五元组参数\n")
	var next gft.Params
	switch strings.ToUpper(c.prompt(sc, "请选择 [A/B/C]:")) {
	case "A":
		next = gft.Params{PadMin: 0, PadMax: 24, PadProb: 15, HbMinMs: 25000, HbMaxMs: 60000}
	case "B":
		next = gft.Params{PadMin: 16, PadMax: 128, PadProb: 60, HbMinMs: 10000, HbMaxMs: 30000}
	case "C":
		next.PadMin, _ = strconv.Atoi(c.prompt(sc, "PadMin (0-128):"))
		next.PadMax, _ = strconv.Atoi(c.prompt(sc, "PadMax (PadMin-255):"))
		next.PadProb, _ = strconv.Atoi(c.prompt(sc, "PadProb (0-100):"))
		next.HbMinMs, _ = strconv.Atoi(c.prompt(sc, "HbMinMs (>=1000):"))
		next.HbMaxMs, _ = strconv.Atoi(c.prompt(sc, "HbMaxMs (>=HbMinMs):"))
		if err := next.Validate(); err != nil {
			c.errMsg("参数不合法: " + err.Error())
			c.pause(sc)
			return
		}
	default:
		return
	}
	if err := c.Tx.Apply(func(nc *server.Config) error {
		nc.Params = &next
		if nc.StateDir != "" {
			pb, _ := json.Marshal(next)
			_ = server.WriteFileAtomic(filepath.Join(nc.StateDir, "params.json"), pb, 0o600)
		}
		return nil
	}); err != nil {
		c.errMsg(err.Error())
	} else {
		c.okMsg("流量整形档位已应用并同步至客户端配置链接")
	}
	c.pause(sc)
}

func (c *Controller) handleAuditMenu(sc *bufio.Scanner, cfg *server.Config) {
	auditPath := filepath.Join(cfg.StateDir, "audit.json")
	au := server.NewAudit(auditPath)
	entries := au.List()
	c.printf("\n--- 威胁感知审计 (%d 条探测 IP 记录) ---\n", len(entries))
	for i := 0; i < len(entries) && i < 20; i++ {
		e := entries[i]
		banStr := ""
		if e.Banned {
			banStr = " [BANNED]"
		}
		c.printf("  %2d) %-18s  次数=%-4d  最近=%s%s  原因=%v\n",
			i+1, e.IP, e.Count, e.Last.Format("01-02 15:04"), banStr, e.Reasons)
	}
	c.printf("\n  [1] 封禁指定 IP   [2] 解封指定 IP   [3] 清空探测历史   [0] 返回\n")
	switch c.prompt(sc, "请选择:") {
	case "1":
		ip := c.prompt(sc, "输入要封禁的 IP:")
		if au.SetBan(ip, true) {
			au.Flush()
			c.okMsg("已将 " + ip + " 加入封禁列表")
		} else {
			c.errMsg("IP 格式无效")
		}
	case "2":
		ip := c.prompt(sc, "输入要解封的 IP:")
		if au.SetBan(ip, false) {
			au.Flush()
			c.okMsg("已解除 " + ip + " 的封禁")
		} else {
			c.errMsg("IP 格式无效")
		}
	case "3":
		au.Clear(false)
		c.okMsg("已清空非封禁历史探测记录")
	}
	c.pause(sc)
}

func (c *Controller) handleServiceAndLogsMenu(sc *bufio.Scanner) {
	c.printf("\n--- 服务管理与实时日志 ---\n")
	c.printf("  [1] 启动   [2] 重启   [3] 停止   [4] 查看实时滚动日志 (Ctrl+C 安全返回)\n")
	switch c.prompt(sc, "请选择:") {
	case "1":
		out, err := exec.Command("systemctl", "start", c.Tx.ServiceName).CombinedOutput()
		if err != nil {
			c.errMsg(string(out))
		} else {
			c.okMsg("已启动 " + c.Tx.ServiceName)
		}
	case "2":
		if err := c.Tx.RestartFn(); err != nil {
			c.errMsg(err.Error())
		} else {
			c.okMsg("已重启 " + c.Tx.ServiceName)
		}
	case "3":
		out, err := exec.Command("systemctl", "stop", c.Tx.ServiceName).CombinedOutput()
		if err != nil {
			c.errMsg(string(out))
		} else {
			c.warnMsg("已停止 " + c.Tx.ServiceName)
		}
	case "4":
		c.printf("正在跟随日志 (按 Ctrl+C 结束查看并返回主菜单)...\n")
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		cmd := exec.CommandContext(ctx, "journalctl", "-u", c.Tx.ServiceName, "-n", "50", "-f", "--no-pager")
		cmd.Stdout = c.Out
		cmd.Stderr = c.Out
		_ = cmd.Run()
		stop()
		c.printf("\n")
		return
	}
	c.pause(sc)
}

func (c *Controller) handleSelfCheckMenu(sc *bufio.Scanner, cfg *server.Config) {
	c.printf("\n--- 网络环境自检与内核调优 ---\n")
	c.printf("  1. TCP 拥塞控制: %s\n", readBBRStatus())
	c.printf("  2. net.core.rmem_max: %s | wmem_max: %s\n",
		readSysctl("/proc/sys/net/core/rmem_max"), readSysctl("/proc/sys/net/core/wmem_max"))
	c.printf("  3. NTP 时钟校验 (比对 HTTP Date 基准): ")
	drift, derr := checkHTTPClockDrift()
	if derr != nil {
		c.printf("跳过 (%v)\n", derr)
	} else if drift > 15*time.Second || drift < -15*time.Second {
		c.printf("偏移异常 (%v > 15s，建议校准)\n", drift.Round(time.Second))
	} else {
		c.printf("正常 (误差 %v)\n", drift.Round(time.Millisecond))
	}
	port := ConfigListenPort(cfg.Listen)
	c.printf("  4. 本机监听套接字状态 (:%d): %v\n", port, CheckPortOccupied(port))

	if strings.EqualFold(c.prompt(sc, "\n是否一键写入 /etc/sysctl.d/99-gft-apex.conf 并应用 BBR + 25MB UDP 缓冲? [y/N]:"), "y") {
		sysctlBody := "net.core.default_qdisc = fq\n" +
			"net.ipv4.tcp_congestion_control = bbr\n" +
			"net.core.rmem_max = 26214400\n" +
			"net.core.wmem_max = 26214400\n" +
			"net.core.rmem_default = 2097152\n" +
			"net.core.wmem_default = 2097152\n" +
			"net.ipv4.udp_rmem_min = 16384\n" +
			"net.ipv4.udp_wmem_min = 16384\n"
		if err := server.WriteFileAtomic(SysctlConfPath, []byte(sysctlBody), 0o644); err != nil {
			c.errMsg(err.Error())
		} else {
			out, aerr := exec.Command("sysctl", "--system").CombinedOutput()
			if aerr != nil {
				c.warnMsg(string(out))
			} else {
				c.okMsg("BBR + fq 与 25MB QUIC UDP 缓冲调优已持久化生效！")
			}
		}
	}
	c.pause(sc)
}

func (c *Controller) handleUpdateAndBackupMenu(sc *bufio.Scanner, cfg *server.Config) {
	c.printf("\n--- 在线更新与配置备份 ---\n")
	c.printf("  [1] 检查 GitHub Release 并校验 SHA-256 热更新 gft-server\n")
	c.printf("  [2] 备份 /etc/gft 至 /root/gft-backup-%s.tar.gz\n", time.Now().Format("20060102"))
	c.printf("  [3] 从 .tar.gz 备份包恢复配置\n")
	switch c.prompt(sc, "请选择:") {
	case "1":
		if err := c.performOTAUpdate(); err != nil {
			c.errMsg("更新失败: " + err.Error())
		} else {
			c.okMsg("已校验 SHA-256 并热更新至最新版！")
		}
	case "2":
		dst := fmt.Sprintf("/root/gft-backup-%s.tar.gz", time.Now().Format("20060102"))
		out, err := exec.Command("tar", "-czf", dst, "-C", filepath.Dir(c.CfgPath), ".").CombinedOutput()
		if err != nil {
			c.errMsg(fmt.Sprintf("%v: %s", err, string(out)))
		} else {
			c.okMsg("备份完成: " + dst)
		}
	case "3":
		src := c.prompt(sc, "请输入备份文件路径:")
		if src == "" {
			return
		}
		out, err := exec.Command("tar", "-xzf", src, "-C", filepath.Dir(c.CfgPath)).CombinedOutput()
		if err != nil {
			c.errMsg(fmt.Sprintf("%v: %s", err, string(out)))
		} else if rerr := c.Tx.RestartFn(); rerr != nil {
			c.errMsg(rerr.Error())
		} else {
			c.okMsg("配置已恢复并重启服务！")
		}
	}
	_ = cfg
	c.pause(sc)
}

func (c *Controller) performOTAUpdate() error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/repos/"+ReleaseRepo+"/releases/latest", nil)
	req.Header.Set("User-Agent", "GhostFrame-Updater/3.2")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("release API HTTP %d", resp.StatusCode)
	}
	var rel struct {
		TagName string `json:"tag_name"`
		Assets  []struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return err
	}
	assetName := fmt.Sprintf("gft-server-linux-%s", runtime.GOARCH)
	var binURL, sumURL string
	for _, a := range rel.Assets {
		if a.Name == assetName {
			binURL = a.URL
		} else if a.Name == "checksums.txt" {
			sumURL = a.URL
		}
	}
	if binURL == "" || sumURL == "" {
		return fmt.Errorf("release %s missing %s or checksums.txt", rel.TagName, assetName)
	}

	c.printf("发现版本 %s，正在下载 %s 并校验 SHA-256...\n", rel.TagName, assetName)
	sumBytes, err := httpGetBytes(sumURL)
	if err != nil {
		return err
	}
	wantHash := ""
	for _, ln := range strings.Split(string(sumBytes), "\n") {
		f := strings.Fields(ln)
		if len(f) >= 2 && strings.TrimPrefix(f[1], "./") == assetName {
			wantHash = strings.ToLower(f[0])
			break
		}
	}
	if wantHash == "" {
		return errors.New("checksums.txt does not contain " + assetName)
	}

	binBytes, err := httpGetBytes(binURL)
	if err != nil {
		return err
	}
	gotSum := sha256.Sum256(binBytes)
	if hex.EncodeToString(gotSum[:]) != wantHash {
		return errors.New("SHA-256 verification failed, aborting replace")
	}

	target := "/opt/ghostframe/gft-server"
	if err := server.WriteFileAtomic(target, binBytes, 0o755); err != nil {
		return err
	}
	return c.Tx.RestartFn()
}

func (c *Controller) handleUninstallMenu(sc *bufio.Scanner) bool {
	c.warnMsg("此操作将停止 GhostFrame 服务、清理 gft_hop 防火墙表并删除全部程序与配置。")
	if c.prompt(sc, "请输入 yes 确认彻底卸载:") != "yes" {
		c.printf("已取消卸载。\n")
		c.pause(sc)
		return false
	}
	_, _ = exec.Command("systemctl", "stop", c.Tx.ServiceName).CombinedOutput()
	_, _ = exec.Command("systemctl", "disable", c.Tx.ServiceName).CombinedOutput()
	_ = c.Tx.FW.RemoveHopRules()
	_, _ = exec.Command("sysctl", "--system").CombinedOutput()
	for _, p := range []string{
		"/etc/systemd/system/ghostframe.service",
		SysctlConfPath,
		"/usr/local/bin/gft",
	} {
		_ = os.Remove(p)
	}
	_, _ = exec.Command("systemctl", "daemon-reload").CombinedOutput()
	for _, dir := range []string{"/opt/ghostframe", "/etc/gft", "/var/lib/gft"} {
		_ = os.RemoveAll(dir)
	}
	c.okMsg("GhostFrame-TLS 已彻底卸载，宿主机现有规则与 SSH 端口未受任何影响。")
	return true
}

func readBBRStatus() string {
	cc := readSysctl("/proc/sys/net/ipv4/tcp_congestion_control")
	if cc == "" {
		return "N/A"
	}
	qd := readSysctl("/proc/sys/net/core/default_qdisc")
	if qd != "" {
		return cc + "+" + qd
	}
	return cc
}

func readSysctl(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return "-"
	}
	return strings.TrimSpace(string(b))
}

func readRuntimeSnapshot(stateDir string) server.RuntimeSnapshot {
	if stateDir == "" {
		return server.RuntimeSnapshot{}
	}
	var s server.RuntimeSnapshot
	if b, err := os.ReadFile(filepath.Join(stateDir, "stats.json")); err == nil {
		_ = json.Unmarshal(b, &s)
	}
	return s
}

func quickMeasureSNI(domain string) time.Duration {
	if domain == "" {
		return 0
	}
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	r := sni.ProbeOne(ctx, "", domain, sni.ProbeOptions{})
	return r.HandshakeRTT
}

func checkHTTPClockDrift() (time.Duration, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodHead, "https://cloudflare.com", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	_ = resp.Body.Close()
	dateHdr := resp.Header.Get("Date")
	t, err := http.ParseTime(dateHdr)
	if err != nil {
		return 0, err
	}
	return time.Since(t), nil
}

func httpGetBytes(u string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download %s: HTTP %d", u, resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

func fmtBytes(b uint64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.2fGB", float64(b)/(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.1fMB", float64(b)/(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.1fKB", float64(b)/(1<<10))
	default:
		return fmt.Sprintf("%dB", b)
	}
}

func nonEmpty(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
