package tui

import (
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"

	"ghostframe/internal/server"
)

// ParseHopRange validates "min-max" where 1024 <= min < max <= 65535.
func ParseHopRange(spec string) (int, int, error) {
	parts := strings.Split(strings.TrimSpace(spec), "-")
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("invalid hop range %q (expected min-max)", spec)
	}
	lo, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
	hi, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err1 != nil || err2 != nil || lo < 1024 || hi > 65535 || lo >= hi {
		return 0, 0, fmt.Errorf("hop range must satisfy 1024 <= min < max <= 65535, got %q", spec)
	}
	return lo, hi, nil
}

// ParseProcNetUDPPorts parses listening/bound local UDP ports within [lo, hi] (excluding excludePort)
// from Linux /proc/net/udp or /proc/net/udp6 table output.
func ParseProcNetUDPPorts(content string, lo, hi, excludePort int) []int {
	seen := make(map[int]struct{})
	lines := strings.Split(content, "\n")
	for _, ln := range lines {
		fields := strings.Fields(ln)
		if len(fields) < 4 {
			continue
		}
		localAddr := fields[1]
		colon := strings.LastIndexByte(localAddr, ':')
		if colon < 0 {
			continue
		}
		p, err := strconv.ParseInt(localAddr[colon+1:], 16, 32)
		if err != nil {
			continue
		}
		port := int(p)
		if port >= lo && port <= hi && port != excludePort {
			seen[port] = struct{}{}
		}
	}
	return sortedPorts(seen)
}

// ParseSSUDPOutput parses non-GFT bound UDP ports within [lo, hi] (excluding excludePort) from `ss -ulnp`.
func ParseSSUDPOutput(content string, lo, hi, excludePort int) []int {
	seen := make(map[int]struct{})
	for _, ln := range strings.Split(content, "\n") {
		if ln == "" || strings.Contains(ln, "gft-server") {
			continue
		}
		fields := strings.Fields(ln)
		if len(fields) < 4 {
			continue
		}
		// Locate local address token (column containing ':' after State/Recv-Q/Send-Q)
		for _, tok := range fields {
			colon := strings.LastIndexByte(tok, ':')
			if colon <= 0 {
				continue
			}
			if p, err := strconv.Atoi(strings.TrimSuffix(tok[colon+1:], ",")); err == nil {
				if p >= lo && p <= hi && p != excludePort {
					seen[p] = struct{}{}
				}
				break
			}
		}
	}
	return sortedPorts(seen)
}

func sortedPorts(seen map[int]struct{}) []int {
	if len(seen) == 0 {
		return nil
	}
	out := make([]int, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Ints(out)
	return out
}

// DetectOccupiedUDPPorts scans /proc/net/udp, /proc/net/udp6, and `ss -ulnp` for existing
// non-GFT UDP listeners inside [lo, hi] so port-hopping rules exempt co-hosted services (e.g. Hysteria2).
func DetectOccupiedUDPPorts(lo, hi, excludePort int) []int {
	seen := make(map[int]struct{})
	for _, path := range []string{"/proc/net/udp", "/proc/net/udp6"} {
		if b, err := os.ReadFile(path); err == nil {
			for _, p := range ParseProcNetUDPPorts(string(b), lo, hi, excludePort) {
				seen[p] = struct{}{}
			}
		}
	}
	if _, err := exec.LookPath("ss"); err == nil {
		if out, err := exec.Command("ss", "-ulnp").Output(); err == nil {
			for _, p := range ParseSSUDPOutput(string(out), lo, hi, excludePort) {
				seen[p] = struct{}{}
			}
		}
	}
	return sortedPorts(seen)
}

// FirewallManager isolates GFT UDP port-hopping NAT rules inside a dedicated
// nftables table (`inet gft_hop`) or iptables chain (`GFT_HOP`) without touching
// unrelated host firewall rules or SSH port 22.
type FirewallManager struct {
	RunCmd      func(name string, args ...string) ([]byte, error)
	HasCmdFn    func(name string) bool
	DetectUDPFn func(lo, hi, excludePort int) []int
}

func NewFirewallManager() *FirewallManager {
	return &FirewallManager{
		RunCmd: func(name string, args ...string) ([]byte, error) {
			return exec.Command(name, args...).CombinedOutput()
		},
		DetectUDPFn: DetectOccupiedUDPPorts,
	}
}

func (f *FirewallManager) hasCmd(name string) bool {
	if f.HasCmdFn != nil {
		return f.HasCmdFn(name)
	}
	_, err := exec.LookPath(name)
	return err == nil
}

// ApplyHopRule atomically creates or replaces UDP port-hopping REDIRECT rules while automatically
// generating RETURN exemptions for any co-hosted UDP services occupying ports within hopRange.
// If hopRange is empty, it cleanly removes only the GFT hop rules.
func (f *FirewallManager) ApplyHopRule(hopRange string, targetPort int) error {
	if strings.TrimSpace(hopRange) == "" {
		return f.RemoveHopRules()
	}
	lo, hi, err := ParseHopRange(hopRange)
	if err != nil {
		return err
	}
	if targetPort < 1 || targetPort > 65535 {
		return fmt.Errorf("invalid target port %d", targetPort)
	}

	detect := f.DetectUDPFn
	if detect == nil {
		detect = DetectOccupiedUDPPorts
	}
	exempt := detect(lo, hi, targetPort)

	if f.hasCmd("nft") {
		_, _ = f.RunCmd("nft", "delete", "table", "inet", "gft_hop")
		var sb strings.Builder
		sb.WriteString("add table inet gft_hop\n")
		sb.WriteString("add chain inet gft_hop prerouting { type nat hook prerouting priority dstnat; policy accept; }\n")
		if len(exempt) > 0 {
			parts := make([]string, len(exempt))
			for i, p := range exempt {
				parts[i] = strconv.Itoa(p)
			}
			sb.WriteString("add rule inet gft_hop prerouting udp dport { ")
			sb.WriteString(strings.Join(parts, ", "))
			sb.WriteString(" } return\n")
		}
		fmt.Fprintf(&sb, "add rule inet gft_hop prerouting udp dport %d-%d redirect to :%d\n", lo, hi, targetPort)
		if f.HasCmdFn != nil {
			if out, err := f.RunCmd("nft", "-f", "-", sb.String()); err != nil {
				return fmt.Errorf("nft apply gft_hop failed: %v (%s)", err, strings.TrimSpace(string(out)))
			}
			return nil
		}
		cmd := exec.Command("nft", "-f", "-")
		cmd.Stdin = strings.NewReader(sb.String())
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("nft apply gft_hop failed: %v (%s)", err, strings.TrimSpace(string(out)))
		}
		return nil
	}

	if f.hasCmd("iptables") {
		portSpec := fmt.Sprintf("%d:%d", lo, hi)
		dstSpec := strconv.Itoa(targetPort)
		_, _ = f.RunCmd("iptables", "-t", "nat", "-N", "GFT_HOP")
		_, _ = f.RunCmd("iptables", "-t", "nat", "-F", "GFT_HOP")
		_, _ = f.RunCmd("iptables", "-t", "nat", "-D", "PREROUTING", "-j", "GFT_HOP")
		if _, err := f.RunCmd("iptables", "-t", "nat", "-C", "PREROUTING", "-p", "udp", "-j", "GFT_HOP"); err != nil {
			if out, ierr := f.RunCmd("iptables", "-t", "nat", "-A", "PREROUTING", "-p", "udp", "-j", "GFT_HOP"); ierr != nil {
				return fmt.Errorf("iptables link GFT_HOP failed: %v (%s)", ierr, strings.TrimSpace(string(out)))
			}
		}
		for i := 0; i < len(exempt); i += 15 {
			end := i + 15
			if end > len(exempt) {
				end = len(exempt)
			}
			chunk := exempt[i:end]
			if len(chunk) == 1 {
				if out, err := f.RunCmd("iptables", "-t", "nat", "-A", "GFT_HOP", "-p", "udp", "--dport", strconv.Itoa(chunk[0]), "-j", "RETURN"); err != nil {
					return fmt.Errorf("iptables add GFT_HOP RETURN failed: %v (%s)", err, strings.TrimSpace(string(out)))
				}
			} else {
				parts := make([]string, len(chunk))
				for j, p := range chunk {
					parts[j] = strconv.Itoa(p)
				}
				if out, err := f.RunCmd("iptables", "-t", "nat", "-A", "GFT_HOP", "-p", "udp", "-m", "multiport", "--dports", strings.Join(parts, ","), "-j", "RETURN"); err != nil {
					return fmt.Errorf("iptables add GFT_HOP multiport RETURN failed: %v (%s)", err, strings.TrimSpace(string(out)))
				}
			}
		}
		if out, err := f.RunCmd("iptables", "-t", "nat", "-A", "GFT_HOP", "-p", "udp", "--dport", portSpec, "-j", "REDIRECT", "--to-ports", dstSpec); err != nil {
			return fmt.Errorf("iptables add GFT_HOP rule failed: %v (%s)", err, strings.TrimSpace(string(out)))
		}
		if f.hasCmd("netfilter-persistent") {
			_, _ = f.RunCmd("netfilter-persistent", "save")
		}
		return nil
	}
	return nil
}

// RemoveHopRules removes only the isolated `gft_hop` table / `GFT_HOP` chain.
func (f *FirewallManager) RemoveHopRules() error {
	var firstErr error
	if f.hasCmd("nft") {
		_, _ = f.RunCmd("nft", "delete", "table", "inet", "gft_hop")
	}
	if f.hasCmd("iptables") {
		_, _ = f.RunCmd("iptables", "-t", "nat", "-D", "PREROUTING", "-p", "udp", "-j", "GFT_HOP")
		_, _ = f.RunCmd("iptables", "-t", "nat", "-D", "PREROUTING", "-j", "GFT_HOP")
		_, _ = f.RunCmd("iptables", "-t", "nat", "-F", "GFT_HOP")
		_, _ = f.RunCmd("iptables", "-t", "nat", "-X", "GFT_HOP")
		if f.hasCmd("netfilter-persistent") {
			_, _ = f.RunCmd("netfilter-persistent", "save")
		}
	}
	return firstErr
}

// HighBDPSysctlConf contains BBR + fq + 32MB UDP buffer tuning for GFT-RTC servers.
const HighBDPSysctlConf = "net.core.default_qdisc = fq\n" +
	"net.ipv4.tcp_congestion_control = bbr\n" +
	"net.core.rmem_max = 33554432\n" +
	"net.core.wmem_max = 33554432\n" +
	"net.core.rmem_default = 8388608\n" +
	"net.core.wmem_default = 8388608\n" +
	"net.ipv4.udp_rmem_min = 65536\n" +
	"net.ipv4.udp_wmem_min = 65536\n" +
	"net.core.netdev_max_backlog = 16384\n"

// ApplyKernelSysctl persists HighBDPSysctlConf atomically to confPath and activates it via sysctl.
func ApplyKernelSysctl(confPath string, runCmd func(string, ...string) ([]byte, error)) error {
	if confPath == "" {
		confPath = SysctlConfPath
	}
	if err := server.WriteFileAtomic(confPath, []byte(HighBDPSysctlConf), 0o644); err != nil {
		return err
	}
	if runCmd == nil {
		runCmd = func(name string, args ...string) ([]byte, error) {
			return exec.Command(name, args...).CombinedOutput()
		}
	}
	out, err := runCmd("sysctl", "-p", confPath)
	_, _ = runCmd("sysctl", "--system")
	if err != nil {
		return fmt.Errorf("sysctl apply failed: %v (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}
