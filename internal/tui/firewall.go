package tui

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
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

// FirewallManager isolates GFT UDP port-hopping NAT rules inside a dedicated
// nftables table (`inet gft_hop`) or iptables chain (`GFT_HOP`) without touching
// unrelated host firewall rules or SSH port 22.
type FirewallManager struct {
	RunCmd func(name string, args ...string) ([]byte, error)
}

func NewFirewallManager() *FirewallManager {
	return &FirewallManager{
		RunCmd: func(name string, args ...string) ([]byte, error) {
			return exec.Command(name, args...).CombinedOutput()
		},
	}
}

func (f *FirewallManager) hasCmd(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// ApplyHopRule atomically creates or replaces UDP port-hopping REDIRECT rules.
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

	if f.hasCmd("nft") {
		_, _ = f.RunCmd("nft", "delete", "table", "inet", "gft_hop")
		script := fmt.Sprintf(
			"add table inet gft_hop\n"+
				"add chain inet gft_hop prerouting { type nat hook prerouting priority dstnat; policy accept; }\n"+
				"add rule inet gft_hop prerouting udp dport %d-%d redirect to :%d\n",
			lo, hi, targetPort,
		)
		cmd := exec.Command("nft", "-f", "-")
		cmd.Stdin = strings.NewReader(script)
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
		if _, err := f.RunCmd("iptables", "-t", "nat", "-C", "PREROUTING", "-j", "GFT_HOP"); err != nil {
			if out, ierr := f.RunCmd("iptables", "-t", "nat", "-A", "PREROUTING", "-j", "GFT_HOP"); ierr != nil {
				return fmt.Errorf("iptables link GFT_HOP failed: %v (%s)", ierr, strings.TrimSpace(string(out)))
			}
		}
		if out, err := f.RunCmd("iptables", "-t", "nat", "-A", "GFT_HOP", "-p", "udp", "--dport", portSpec, "-j", "REDIRECT", "--to-ports", dstSpec); err != nil {
			return fmt.Errorf("iptables add GFT_HOP rule failed: %v (%s)", err, strings.TrimSpace(string(out)))
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
		_, _ = f.RunCmd("iptables", "-t", "nat", "-D", "PREROUTING", "-j", "GFT_HOP")
		_, _ = f.RunCmd("iptables", "-t", "nat", "-F", "GFT_HOP")
		_, _ = f.RunCmd("iptables", "-t", "nat", "-X", "GFT_HOP")
	}
	return firstErr
}
