package tproxy

import (
	"fmt"
	"net"
	"os"
	"strings"

	"ghostframe/internal/client"
)

const DefaultCNIPv4OverridePath = "/etc/0ghost/cn_ipv4.txt"

// EffectiveCNIPv4CIDRs returns external override CIDRs from overridePath (defaulting to
// /etc/0ghost/cn_ipv4.txt if present and non-empty), or the embedded complete APNIC table.
func EffectiveCNIPv4CIDRs(overridePath string) []string {
	path := strings.TrimSpace(overridePath)
	if path == "" {
		path = DefaultCNIPv4OverridePath
	}
	if b, err := os.ReadFile(path); err == nil {
		var custom []string
		for _, ln := range strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n") {
			if idx := strings.IndexAny(ln, "#;"); idx >= 0 {
				ln = ln[:idx]
			}
			s := strings.TrimSpace(ln)
			if s == "" {
				continue
			}
			if !strings.Contains(s, "/") {
				if ip := net.ParseIP(s); ip != nil && ip.To4() != nil {
					s = ip.To4().String() + "/32"
				}
			}
			if _, ipNet, err := net.ParseCIDR(s); err == nil && ipNet.IP.To4() != nil {
				custom = append(custom, ipNet.String())
			}
		}
		if len(custom) > 0 {
			return custom
		}
	}
	return client.CNPublicIPv4CIDRs()
}

// BuildNFTablesScript builds the complete atomic nftables ruleset inside
// `table inet ghost0` so start/reload/stop remain 100% isolated and leak-free.
func BuildNFTablesScript(spec FirewallSpec) string {
	markHex := fmt.Sprintf("0x%x", spec.FWMark)
	tproxyMarkHex := fmt.Sprintf("0x%x", spec.TProxyMark)
	if spec.FWMark <= 0 {
		markHex = "0xff"
	}
	if spec.TProxyMark <= 0 {
		tproxyMarkHex = "0x1"
	}
	if spec.TCPPort <= 0 {
		spec.TCPPort = 10880
	}
	if spec.UDPPort <= 0 {
		spec.UDPPort = 10881
	}
	if spec.DNSPort <= 0 {
		spec.DNSPort = 7853
	}
	if spec.WebPort <= 0 {
		spec.WebPort = 19080
	}
	if spec.SocksPort <= 0 {
		spec.SocksPort = 10808
	}
	if spec.HTTPPort <= 0 {
		spec.HTTPPort = 10809
	}

	var b strings.Builder
	b.WriteString("table inet ghost0\n")
	b.WriteString("delete table inet ghost0\n")
	b.WriteString("table inet ghost0 {\n")

	// 1. Reserved & LAN bypass ranges (RFC1918 + loopback + multicast + broadcast + CGNAT).
	b.WriteString("  set lan_bypass_v4 {\n")
	b.WriteString("    type ipv4_addr\n")
	b.WriteString("    flags interval\n")
	b.WriteString("    auto-merge\n")
	b.WriteString("    elements = { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 255.255.255.255/32 }\n")
	b.WriteString("  }\n")

	// 2. Active VPS / node server IPs bypass set.
	vpsIPs := filterValidIPv4s(spec.VPSIPs)
	b.WriteString("  set vps_bypass_v4 {\n")
	b.WriteString("    type ipv4_addr\n")
	b.WriteString("    flags interval\n")
	if len(vpsIPs) > 0 {
		b.WriteString("    elements = { ")
		b.WriteString(strings.Join(vpsIPs, ", "))
		b.WriteString(" }\n")
	}
	b.WriteString("  }\n")

	// 3. Mainland China IPv4 kernel-level direct bypass set (@cn_ipv4).
	cnCIDRs := EffectiveCNIPv4CIDRs(spec.CNIPv4OverridePath)
	b.WriteString("  set cn_ipv4 {\n")
	b.WriteString("    type ipv4_addr\n")
	b.WriteString("    flags interval\n")
	b.WriteString("    auto-merge\n")
	if len(cnCIDRs) > 0 {
		b.WriteString("    elements = {\n      ")
		for i, c := range cnCIDRs {
			if i > 0 {
				if i%12 == 0 {
					b.WriteString(",\n      ")
				} else {
					b.WriteString(", ")
				}
			}
			b.WriteString(c)
		}
		b.WriteString("\n    }\n")
	}
	b.WriteString("  }\n")

	// 4. Optional LAN client device filter set.
	devIPs := filterValidIPv4s(spec.DeviceIPs)
	hasDevFilter := (spec.DeviceMode == DeviceOnly || spec.DeviceMode == DeviceBypass) && len(devIPs) > 0
	if hasDevFilter {
		b.WriteString("  set device_filter_v4 {\n")
		b.WriteString("    type ipv4_addr\n")
		b.WriteString("    flags interval\n")
		b.WriteString("    elements = { ")
		b.WriteString(strings.Join(devIPs, ", "))
		b.WriteString(" }\n")
		b.WriteString("  }\n")
	}

	devMatchRule := ""
	if hasDevFilter {
		if spec.DeviceMode == DeviceOnly {
			devMatchRule = "    ip saddr != @device_filter_v4 return\n"
		} else if spec.DeviceMode == DeviceBypass {
			devMatchRule = "    ip saddr @device_filter_v4 return\n"
		}
	}

	// 5. Dynamic DNS interception (never touches /etc/config/dhcp).
	b.WriteString("  chain dns_nat {\n")
	b.WriteString("    type nat hook prerouting priority dstnat - 10; policy accept;\n")
	b.WriteString(fmt.Sprintf("    meta mark %s return\n", markHex))
	if len(vpsIPs) > 0 {
		b.WriteString("    ip daddr @vps_bypass_v4 return\n")
	}
	if devMatchRule != "" {
		b.WriteString(devMatchRule)
	}
	b.WriteString(fmt.Sprintf("    iifname != \"lo\" meta l4proto { tcp, udp } th dport 53 redirect to :%d\n", spec.DNSPort))
	b.WriteString("  }\n")

	b.WriteString("  chain dns_output {\n")
	b.WriteString("    type nat hook output priority dstnat - 10; policy accept;\n")
	b.WriteString(fmt.Sprintf("    meta mark %s return\n", markHex))
	b.WriteString("    ip daddr 127.0.0.0/8 return\n")
	if len(vpsIPs) > 0 {
		b.WriteString("    ip daddr @vps_bypass_v4 return\n")
	}
	b.WriteString(fmt.Sprintf("    meta l4proto { tcp, udp } th dport 53 redirect to :%d\n", spec.DNSPort))
	b.WriteString("  }\n")

	// 6. Prerouting transparent forwarding chain (TPROXY when supported; otherwise pure TCP REDIRECT nat chain).
	if spec.PreferTProxy {
		b.WriteString("  chain mangle_prerouting {\n")
		b.WriteString("    type filter hook prerouting priority mangle; policy accept;\n")
		b.WriteString(fmt.Sprintf("    meta mark %s return\n", markHex))
		b.WriteString(fmt.Sprintf("    fib daddr type local meta l4proto { tcp, udp } th dport { 22, 80, 443, 7681, %d, %d, %d } return\n",
			spec.WebPort, spec.SocksPort, spec.HTTPPort))
		b.WriteString("    fib daddr type local return\n")
		b.WriteString("    ip daddr @lan_bypass_v4 return\n")
		b.WriteString("    ip6 daddr { ::1/128, fe80::/10, fc00::/7 } return\n")
		if len(vpsIPs) > 0 {
			b.WriteString("    ip daddr @vps_bypass_v4 return\n")
		}
		if devMatchRule != "" {
			b.WriteString(devMatchRule)
		}
		b.WriteString("    meta l4proto { tcp, udp } th dport 53 return\n")
		if spec.Mode == ModeRule {
			b.WriteString("    ip daddr @cn_ipv4 return\n")
		}
		b.WriteString(fmt.Sprintf("    meta l4proto tcp socket transparent 1 meta mark set %s accept\n", tproxyMarkHex))
		b.WriteString(fmt.Sprintf("    meta l4proto tcp tproxy ip to 127.0.0.1:%d meta mark set %s accept\n", spec.TCPPort, tproxyMarkHex))
		b.WriteString(fmt.Sprintf("    meta l4proto udp tproxy ip to 127.0.0.1:%d meta mark set %s accept\n", spec.UDPPort, tproxyMarkHex))
		b.WriteString("  }\n")
	} else {
		b.WriteString("  chain tcp_redir_nat {\n")
		b.WriteString("    type nat hook prerouting priority dstnat; policy accept;\n")
		b.WriteString(fmt.Sprintf("    meta mark %s return\n", markHex))
		b.WriteString(fmt.Sprintf("    fib daddr type local tcp dport { 22, 80, 443, 7681, %d, %d, %d } return\n",
			spec.WebPort, spec.SocksPort, spec.HTTPPort))
		b.WriteString("    fib daddr type local return\n")
		b.WriteString("    ip daddr @lan_bypass_v4 return\n")
		if len(vpsIPs) > 0 {
			b.WriteString("    ip daddr @vps_bypass_v4 return\n")
		}
		if devMatchRule != "" {
			b.WriteString(devMatchRule)
		}
		b.WriteString("    tcp dport 53 return\n")
		if spec.Mode == ModeRule {
			b.WriteString("    ip daddr @cn_ipv4 return\n")
		}
		b.WriteString(fmt.Sprintf("    meta l4proto tcp redirect to :%d\n", spec.TCPPort))
		b.WriteString("  }\n")
	}

	// 7. Local router output marking (TPROXY only; omitted in pure REDIRECT fallback to avoid dangling fwmark).
	if spec.PreferTProxy && spec.DeviceMode == DeviceAll {
		b.WriteString("  chain mangle_output {\n")
		b.WriteString("    type route hook output priority mangle; policy accept;\n")
		b.WriteString(fmt.Sprintf("    meta mark %s return\n", markHex))
		b.WriteString("    ct direction reply return\n")
		b.WriteString("    fib daddr type local return\n")
		b.WriteString("    ip daddr @lan_bypass_v4 return\n")
		b.WriteString("    ip6 daddr { ::1/128, fe80::/10, fc00::/7 } return\n")
		if len(vpsIPs) > 0 {
			b.WriteString("    ip daddr @vps_bypass_v4 return\n")
		}
		b.WriteString("    meta l4proto { tcp, udp } th dport 53 return\n")
		if spec.Mode == ModeRule {
			b.WriteString("    ip daddr @cn_ipv4 return\n")
		}
		b.WriteString(fmt.Sprintf("    meta l4proto { tcp, udp } meta mark set %s accept\n", tproxyMarkHex))
		b.WriteString("  }\n")
	}

	// 8. Optional IPv6 leak guard in forward hook when FilterAAAA is enabled.
	if spec.FilterAAAA {
		b.WriteString("  chain forward_v6_guard {\n")
		b.WriteString("    type filter hook forward priority filter - 5; policy accept;\n")
		b.WriteString(fmt.Sprintf("    meta mark %s return\n", markHex))
		b.WriteString("    meta nfproto ipv6 ip6 daddr { ::1/128, fe80::/10, fc00::/7 } return\n")
		if hasDevFilter {
			if spec.DeviceMode == DeviceOnly {
				b.WriteString("    ip saddr != @device_filter_v4 return\n")
			} else if spec.DeviceMode == DeviceBypass {
				b.WriteString("    ip saddr @device_filter_v4 return\n")
			}
		}
		b.WriteString("    meta nfproto ipv6 reject with icmpv6 port-unreachable\n")
		b.WriteString("  }\n")
	}

	// 9. Optional LAN dynamic masquerade (SNAT) for single-arm asymmetric routing compatibility.
	if spec.LANMasquerade {
		b.WriteString("  chain postrouting_masq {\n")
		b.WriteString("    type nat hook postrouting priority srcnat - 5; policy accept;\n")
		b.WriteString(fmt.Sprintf("    meta mark %s return\n", markHex))
		b.WriteString("    iifname != \"lo\" oifname != \"lo\" masquerade\n")
		b.WriteString("  }\n")
	}

	b.WriteString("}\n")
	return b.String()
}

func filterValidIPv4s(in []string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, raw := range in {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		if ip := net.ParseIP(s); ip != nil {
			if ip4 := ip.To4(); ip4 != nil {
				norm := ip4.String()
				if _, ok := seen[norm]; !ok {
					seen[norm] = struct{}{}
					out = append(out, norm)
				}
			}
			continue
		}
		if _, ipNet, err := net.ParseCIDR(s); err == nil {
			if ipNet.IP.To4() != nil {
				norm := ipNet.String()
				if _, ok := seen[norm]; !ok {
					seen[norm] = struct{}{}
					out = append(out, norm)
				}
			}
		}
	}
	return out
}
