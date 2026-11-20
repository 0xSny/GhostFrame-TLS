//go:build linux

package tproxy

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DetectLANEnvironment inspects /proc/net/route and active network interfaces
// to identify the primary LAN interface (e.g. "br-lan"), router IP, and upstream gateway IP.
func DetectLANEnvironment() (ifaceName, lanIP, gatewayIP string) {
	if f, err := os.Open("/proc/net/route"); err == nil {
		defer f.Close()
		sc := bufio.NewScanner(f)
		first := true
		for sc.Scan() {
			if first {
				first = false
				continue
			}
			fields := strings.Fields(sc.Text())
			if len(fields) < 8 {
				continue
			}
			if fields[1] == "00000000" && fields[7] == "00000000" {
				ifaceName = fields[0]
				if gw, ok := parseHexIPv4(fields[2]); ok {
					gatewayIP = gw
				}
				break
			}
		}
	}
	if ifaceName == "" {
		ifaceName = "br-lan"
	}
	if ifc, err := net.InterfaceByName(ifaceName); err == nil {
		if addrs, err := ifc.Addrs(); err == nil {
			for _, a := range addrs {
				if ipNet, ok := a.(*net.IPNet); ok {
					if ip4 := ipNet.IP.To4(); ip4 != nil && !ip4.IsLoopback() {
						lanIP = ip4.String()
						break
					}
				}
			}
		}
	}
	return ifaceName, lanIP, gatewayIP
}

func parseHexIPv4(h string) (string, bool) {
	b, err := hex.DecodeString(strings.TrimSpace(h))
	if err != nil || len(b) != 4 {
		return "", false
	}
	// /proc/net/route stores IPv4 in host byte order (little-endian on ARM64/x86_64).
	return net.IPv4(b[3], b[2], b[1], b[0]).String(), true
}

// HasNFTTProxy reports whether the Linux kernel currently provides nft_tproxy + nft_socket.
func HasNFTTProxy() bool {
	if _, err := os.Stat("/sys/module/nft_tproxy"); err == nil {
		return true
	}
	if b, err := os.ReadFile("/proc/modules"); err == nil {
		s := string(b)
		if strings.Contains(s, "nft_tproxy") {
			return true
		}
	}
	// Try modprobe once if available (non-fatal).
	_ = exec.Command("modprobe", "nft_tproxy").Run()
	_ = exec.Command("modprobe", "nft_socket").Run()
	if _, err := os.Stat("/sys/module/nft_tproxy"); err == nil {
		return true
	}
	return false
}

// CalibrateKernel ensures ip_forward=1, disables ICMP send_redirects, and enables liberal
// TCP conntrack window checking so single-arm asymmetric routing never stalls connections.
func CalibrateKernel(lanIface string) {
	writeSysctl("/proc/sys/net/ipv4/ip_forward", "1")
	writeSysctl("/proc/sys/net/ipv4/conf/all/route_localnet", "1")
	writeSysctl("/proc/sys/net/ipv4/conf/default/route_localnet", "1")
	writeSysctl("/proc/sys/net/ipv4/conf/all/send_redirects", "0")
	writeSysctl("/proc/sys/net/ipv4/conf/default/send_redirects", "0")
	if lanIface != "" {
		writeSysctl(filepath.Join("/proc/sys/net/ipv4/conf", lanIface, "route_localnet"), "1")
		writeSysctl(filepath.Join("/proc/sys/net/ipv4/conf", lanIface, "send_redirects"), "0")
	}
	if _, err := os.Stat("/proc/sys/net/netfilter/nf_conntrack_tcp_be_liberal"); err == nil {
		writeSysctl("/proc/sys/net/netfilter/nf_conntrack_tcp_be_liberal", "1")
	} else {
		_ = exec.Command("sysctl", "-w", "net.netfilter.nf_conntrack_tcp_be_liberal=1").Run()
	}
}

// CheckFirewallHealthy verifies that `table inet kestrel0` and the TPROXY policy route
// are still mounted (e.g. not wiped by an external fw4 reload or hotplug event).
func CheckFirewallHealthy(mode GatewayMode, tproxyMark, routeTable int) bool {
	if mode == ModePort {
		return true
	}
	if routeTable <= 0 {
		routeTable = 100
	}
	if _, err := exec.LookPath("nft"); err == nil {
		if err := exec.Command("nft", "list", "table", "inet", "kestrel0").Run(); err != nil {
			return false
		}
		if HasNFTTProxy() {
			out, err := exec.Command("ip", "rule", "show").Output()
			if err != nil {
				return false
			}
			needle := fmt.Sprintf("lookup %d", routeTable)
			if !strings.Contains(string(out), needle) {
				return false
			}
		}
		return true
	}
	return exec.Command("iptables", "-t", "nat", "-L", "KSL_TCP").Run() == nil &&
		exec.Command("iptables", "-t", "nat", "-L", "KSL_DNS").Run() == nil
}

func writeSysctl(path, val string) {
	_ = os.WriteFile(path, []byte(val+"\n"), 0o644)
}

// ApplyFirewall atomically mounts the isolated GhostFrame side-router firewall table (`table inet ghost0`)
// and policy routing (`fwmark 0x1 -> table 100`). Management ports (22, 80, 443, 7681, 19080, 10808, 10809)
// are unconditionally whitelisted at the very top of every chain.
func ApplyFirewall(spec FirewallSpec) (string, error) {
	if spec.TProxyMark <= 0 {
		spec.TProxyMark = 1
	}
	if spec.RouteTable <= 0 {
		spec.RouteTable = 100
	}
	if spec.FWMark <= 0 {
		spec.FWMark = 0xff
	}

	if spec.Mode == ModePort {
		CleanupFirewall(spec.TProxyMark, spec.RouteTable)
		return "none (port-only)", nil
	}

	lanIface, _, _ := DetectLANEnvironment()
	CalibrateKernel(lanIface)

	// Configure policy routing table for TPROXY marked packets.
	markStr := fmt.Sprintf("0x%x", spec.TProxyMark)
	tblStr := strconv.Itoa(spec.RouteTable)
	cleanPolicyRoute(markStr, tblStr)
	if out, err := exec.Command("ip", "rule", "add", "fwmark", markStr, "lookup", tblStr, "pref", "100").CombinedOutput(); err != nil {
		return "", fmt.Errorf("ip rule add failed: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	if out, err := exec.Command("ip", "route", "replace", "local", "0.0.0.0/0", "dev", "lo", "table", tblStr).CombinedOutput(); err != nil {
		cleanPolicyRoute(markStr, tblStr)
		return "", fmt.Errorf("ip route replace failed: %w (%s)", err, strings.TrimSpace(string(out)))
	}

	if _, err := exec.LookPath("nft"); err == nil {
		spec.PreferTProxy = HasNFTTProxy()
		script := BuildNFTablesScript(spec)
		cmd := exec.Command("nft", "-f", "-")
		cmd.Stdin = strings.NewReader(script)
		var out bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &out
		if err := cmd.Run(); err != nil {
			if spec.PreferTProxy {
				// Automatic fallback to REDIRECT + DNS if TPROXY kernel hook fails.
				spec.PreferTProxy = false
				script = BuildNFTablesScript(spec)
				cmd2 := exec.Command("nft", "-f", "-")
				cmd2.Stdin = strings.NewReader(script)
				var out2 bytes.Buffer
				cmd2.Stdout = &out2
				cmd2.Stderr = &out2
				if err2 := cmd2.Run(); err2 != nil {
					CleanupFirewall(spec.TProxyMark, spec.RouteTable)
					return "", fmt.Errorf("nft apply failed: %w (%s)", err2, strings.TrimSpace(out2.String()))
				}
				return "nftables (REDIRECT+DNS fallback)", nil
			}
			CleanupFirewall(spec.TProxyMark, spec.RouteTable)
			return "", fmt.Errorf("nft apply failed: %w (%s)", err, strings.TrimSpace(out.String()))
		}
		if spec.PreferTProxy {
			return "nftables (fw4 TPROXY+DNS)", nil
		}
		return "nftables (fw4 REDIRECT+DNS)", nil
	}

	// Legacy fw3/iptables fallback.
	if err := applyIPTablesFallback(spec); err != nil {
		CleanupFirewall(spec.TProxyMark, spec.RouteTable)
		return "", err
	}
	return "iptables (REDIRECT+DNS)", nil
}

// CleanupFirewall atomically removes `table inet kestrel0` (and legacy `ghost0`), policy routing, and any fallback iptables chains.
func CleanupFirewall(tproxyMark, routeTable int) {
	if tproxyMark <= 0 {
		tproxyMark = 1
	}
	if routeTable <= 0 {
		routeTable = 100
	}
	_ = exec.Command("nft", "delete", "table", "inet", "kestrel0").Run()
	_ = exec.Command("nft", "delete", "table", "inet", "ghost0").Run()
	cleanPolicyRoute(fmt.Sprintf("0x%x", tproxyMark), strconv.Itoa(routeTable))
	cleanupIPTablesFallback()
}

func cleanPolicyRoute(markStr, tblStr string) {
	for i := 0; i < 4; i++ {
		if err := exec.Command("ip", "rule", "del", "fwmark", markStr, "table", tblStr).Run(); err != nil {
			break
		}
	}
	_ = exec.Command("ip", "route", "flush", "table", tblStr).Run()
}

func applyIPTablesFallback(spec FirewallSpec) error {
	cleanupIPTablesFallback()
	markHex := fmt.Sprintf("0x%x", spec.FWMark)

	cmds := [][]string{
		{"iptables", "-t", "nat", "-N", "KSL_DNS"},
		{"iptables", "-t", "nat", "-A", "KSL_DNS", "-m", "mark", "--mark", markHex, "-j", "RETURN"},
		{"iptables", "-t", "nat", "-A", "KSL_DNS", "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", strconv.Itoa(spec.DNSPort)},
		{"iptables", "-t", "nat", "-A", "KSL_DNS", "-p", "tcp", "--dport", "53", "-j", "REDIRECT", "--to-ports", strconv.Itoa(spec.DNSPort)},
		{"iptables", "-t", "nat", "-I", "PREROUTING", "1", "-j", "KSL_DNS"},

		{"iptables", "-t", "nat", "-N", "KSL_TCP"},
		{"iptables", "-t", "nat", "-A", "KSL_TCP", "-m", "mark", "--mark", markHex, "-j", "RETURN"},
		{"iptables", "-t", "nat", "-A", "KSL_TCP", "-m", "addrtype", "--dst-type", "LOCAL", "-j", "RETURN"},
		{"iptables", "-t", "nat", "-A", "KSL_TCP", "-d", "127.0.0.0/8", "-j", "RETURN"},
		{"iptables", "-t", "nat", "-A", "KSL_TCP", "-d", "10.0.0.0/8", "-j", "RETURN"},
		{"iptables", "-t", "nat", "-A", "KSL_TCP", "-d", "172.16.0.0/12", "-j", "RETURN"},
		{"iptables", "-t", "nat", "-A", "KSL_TCP", "-d", "192.168.0.0/16", "-j", "RETURN"},
		{"iptables", "-t", "nat", "-A", "KSL_TCP", "-d", "224.0.0.0/4", "-j", "RETURN"},
	}
	for _, vip := range filterValidIPv4s(spec.VPSIPs) {
		cmds = append(cmds, []string{"iptables", "-t", "nat", "-A", "KSL_TCP", "-d", vip, "-j", "RETURN"})
	}
	cmds = append(cmds,
		[]string{"iptables", "-t", "nat", "-A", "KSL_TCP", "-p", "tcp", "-j", "REDIRECT", "--to-ports", strconv.Itoa(spec.TCPPort)},
		[]string{"iptables", "-t", "nat", "-A", "PREROUTING", "-p", "tcp", "-j", "KSL_TCP"},
	)

	for _, args := range cmds {
		if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
			return fmt.Errorf("%s failed: %w (%s)", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

func cleanupIPTablesFallback() {
	for _, args := range [][]string{
		{"iptables", "-t", "nat", "-D", "PREROUTING", "-j", "KSL_DNS"},
		{"iptables", "-t", "nat", "-D", "PREROUTING", "-p", "tcp", "-j", "KSL_TCP"},
		{"iptables", "-t", "nat", "-F", "KSL_DNS"},
		{"iptables", "-t", "nat", "-X", "KSL_DNS"},
		{"iptables", "-t", "nat", "-F", "KSL_TCP"},
		{"iptables", "-t", "nat", "-X", "KSL_TCP"},
		{"iptables", "-t", "nat", "-D", "PREROUTING", "-j", "GHOST0_DNS"},
		{"iptables", "-t", "nat", "-D", "PREROUTING", "-p", "tcp", "-j", "GHOST0_TCP"},
		{"iptables", "-t", "nat", "-F", "GHOST0_DNS"},
		{"iptables", "-t", "nat", "-X", "GHOST0_DNS"},
		{"iptables", "-t", "nat", "-F", "GHOST0_TCP"},
		{"iptables", "-t", "nat", "-X", "GHOST0_TCP"},
	} {
		_ = exec.Command(args[0], args[1:]...).Run()
	}
}

var (
	cpuMu       sync.Mutex
	prevCPUIdle uint64
	prevCPUTot  uint64
)

// ReadSystemStats reads live host memory & CPU utilization from /proc without spawning child processes.
func ReadSystemStats() (memUsedMB, memTotalMB, cpuPct float64) {
	if b, err := os.ReadFile("/proc/meminfo"); err == nil {
		var totalKB, availKB uint64
		for _, ln := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(ln, "MemTotal:") {
				f := strings.Fields(ln)
				if len(f) >= 2 {
					totalKB, _ = strconv.ParseUint(f[1], 10, 64)
				}
			} else if strings.HasPrefix(ln, "MemAvailable:") {
				f := strings.Fields(ln)
				if len(f) >= 2 {
					availKB, _ = strconv.ParseUint(f[1], 10, 64)
				}
			}
		}
		if totalKB > 0 {
			memTotalMB = float64(totalKB) / 1024.0
			if totalKB >= availKB {
				memUsedMB = float64(totalKB-availKB) / 1024.0
			}
		}
	}

	if b, err := os.ReadFile("/proc/stat"); err == nil {
		lines := strings.SplitN(string(b), "\n", 2)
		if len(lines) > 0 && strings.HasPrefix(lines[0], "cpu ") {
			fields := strings.Fields(lines[0])
			var tot, idle uint64
			for i := 1; i < len(fields); i++ {
				v, _ := strconv.ParseUint(fields[i], 10, 64)
				tot += v
				if i == 4 || i == 5 { // idle + iowait
					idle += v
				}
			}
			cpuMu.Lock()
			if prevCPUTot > 0 && tot > prevCPUTot {
				dt := float64(tot - prevCPUTot)
				di := float64(idle - prevCPUIdle)
				if dt > 0 {
					cpuPct = ((dt - di) / dt) * 100.0
					if cpuPct < 0 {
						cpuPct = 0
					}
				}
			}
			prevCPUTot = tot
			prevCPUIdle = idle
			cpuMu.Unlock()
		}
	}
	return memUsedMB, memTotalMB, cpuPct
}

var _ = time.Second
