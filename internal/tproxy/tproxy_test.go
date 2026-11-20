package tproxy

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ghostframe/internal/client"
)

func TestSniffTCPDomainHTTPHost(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	req := "GET /generate_204 HTTP/1.1\r\nHost: cp.cloudflare.com\r\nUser-Agent: test\r\n\r\n"
	go func() {
		_, _ = c2.Write([]byte(req))
	}()

	domain, rewound := SniffTCPDomain(c1, 200*time.Millisecond)
	if domain != "cp.cloudflare.com" {
		t.Fatalf("expected sniffed host cp.cloudflare.com, got %q", domain)
	}
	buf := make([]byte, len(req))
	if _, err := io.ReadFull(rewound, buf); err != nil {
		t.Fatalf("read rewound failed: %v", err)
	}
	if string(buf) != req {
		t.Fatalf("rewound bytes altered: %q", string(buf))
	}
}

func TestSniffTCPDomainBinaryFastExit(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	payload := []byte("SSH-2.0-OpenSSH_9.6\r\n")
	go func() {
		_, _ = c2.Write(payload)
	}()

	start := time.Now()
	domain, rewound := SniffTCPDomain(c1, 500*time.Millisecond)
	if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
		t.Fatalf("expected fast exit on non-TLS/non-HTTP protocol, took %v", elapsed)
	}
	if domain != "" {
		t.Fatalf("expected empty domain, got %q", domain)
	}
	out := make([]byte, len(payload))
	if _, err := io.ReadFull(rewound, out); err != nil {
		t.Fatalf("read rewound failed: %v", err)
	}
	if !bytes.Equal(out, payload) {
		t.Fatalf("payload mismatch")
	}
}

func TestSplitDNSFilterAAAAAndReject(t *testing.T) {
	client.SetNoSysProxy(true)
	eng, err := client.NewEngine("")
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}
	defer eng.Close()
	if err := eng.SetCustomRules([]string{"DOMAIN-SUFFIX,doubleclick.net,REJECT"}); err != nil {
		t.Fatalf("SetCustomRules failed: %v", err)
	}

	srv := NewSplitDNSServer("127.0.0.1:0", eng, nil, true, func() GatewayMode { return ModeRule })

	qAAAA, err := client.BuildDNSQuery(0x1122, "www.google.com", 28)
	if err != nil {
		t.Fatalf("BuildDNSQuery AAAA failed: %v", err)
	}
	respAAAA := srv.HandlePacket(qAAAA)
	if len(respAAAA) < 12 || binary.BigEndian.Uint16(respAAAA[0:2]) != 0x1122 {
		t.Fatalf("invalid AAAA filtered response")
	}
	rcodeAAAA := binary.BigEndian.Uint16(respAAAA[2:4]) & 0x0F
	if rcodeAAAA != 0 || binary.BigEndian.Uint16(respAAAA[6:8]) != 0 {
		t.Fatalf("expected NOERROR with 0 answers for AAAA, got rcode=%d an=%d", rcodeAAAA, binary.BigEndian.Uint16(respAAAA[6:8]))
	}

	qRej, err := client.BuildDNSQuery(0x3344, "ad.doubleclick.net", 1)
	if err != nil {
		t.Fatalf("BuildDNSQuery reject failed: %v", err)
	}
	respRej := srv.HandlePacket(qRej)
	rcodeRej := binary.BigEndian.Uint16(respRej[2:4]) & 0x0F
	if rcodeRej != 3 {
		t.Fatalf("expected NXDOMAIN (3) for rejected domain, got %d", rcodeRej)
	}
}

func TestBuildNFTablesScriptOrderingAndSafety(t *testing.T) {
	spec := FirewallSpec{
		Mode:          ModeRule,
		DeviceMode:    DeviceOnly,
		DeviceIPs:     []string{"192.168.1.50", "192.168.1.51"},
		VPSIPs:        []string{"203.0.113.10"},
		TCPPort:       10880,
		UDPPort:       10881,
		DNSPort:       7853,
		WebPort:       19080,
		SocksPort:     10808,
		HTTPPort:      10809,
		FWMark:        0xff,
		TProxyMark:    0x1,
		RouteTable:    100,
		PreferTProxy:  true,
		FilterAAAA:    true,
		LANMasquerade: true,
	}
	script := BuildNFTablesScript(spec)

	required := []string{
		"table inet ghost0 {",
		"set lan_bypass_v4",
		"set vps_bypass_v4",
		"203.0.113.10",
		"set cn_ipv4",
		"set device_filter_v4",
		"192.168.1.50",
		"meta mark 0xff return",
		"th dport { 22, 80, 443, 7681, 19080, 10808, 10809 } return",
		"ip daddr @lan_bypass_v4 return",
		"ip daddr @vps_bypass_v4 return",
		"ip saddr != @device_filter_v4 return",
		"ip daddr @cn_ipv4 return",
		"tproxy ip to 127.0.0.1:10880 meta mark set 0x1 accept",
		"tproxy ip to 127.0.0.1:10881 meta mark set 0x1 accept",
		"redirect to :7853",
		"chain forward_v6_guard",
		"meta nfproto ipv6 reject with icmpv6 port-unreachable",
		"chain postrouting_masq",
		"iifname != \"lo\" oifname != \"lo\" masquerade",
	}
	for _, needle := range required {
		if !strings.Contains(script, needle) {
			t.Fatalf("expected nftables script to contain %q", needle)
		}
	}

	// Verify management ports and mark bypass strictly precede @cn_ipv4 and tproxy inside mangle_prerouting.
	idxPre := strings.Index(script, "chain mangle_prerouting")
	preSection := script[idxPre:]
	posMark := strings.Index(preSection, "meta mark 0xff return")
	posMgmt := strings.Index(preSection, "22, 80, 443, 7681")
	posCN := strings.Index(preSection, "ip daddr @cn_ipv4 return")
	posTProxy := strings.Index(preSection, "tproxy ip to 127.0.0.1:10880")
	if !(posMark >= 0 && posMark < posMgmt && posMgmt < posCN && posCN < posTProxy) {
		t.Fatalf("unexpected rule precedence in mangle_prerouting: mark=%d mgmt=%d cn=%d tproxy=%d", posMark, posMgmt, posCN, posTProxy)
	}
}

func TestEffectiveCNIPv4CIDRsAndOverride(t *testing.T) {
	// 1. Built-in APNIC table should unpack >= 5000 valid IPv4 CIDRs.
	def := EffectiveCNIPv4CIDRs(filepath.Join(t.TempDir(), "nonexistent.txt"))
	if len(def) < 5000 {
		t.Fatalf("expected >= 5000 embedded APNIC CN CIDRs, got %d", len(def))
	}

	// 2. Router-side override (/etc/0ghost/cn_ipv4.txt equivalent) cleanly replaces embedded set.
	ovPath := filepath.Join(t.TempDir(), "cn_ipv4.txt")
	if err := os.WriteFile(ovPath, []byte("# comment\n223.5.5.5\n119.29.0.0/16 ; dnspod\ninvalid_cidr\n"), 0o644); err != nil {
		t.Fatalf("write override failed: %v", err)
	}
	ov := EffectiveCNIPv4CIDRs(ovPath)
	if len(ov) != 2 || ov[0] != "223.5.5.5/32" || ov[1] != "119.29.0.0/16" {
		t.Fatalf("unexpected override CIDRs: %v", ov)
	}

	// 3. Verify !PreferTProxy (REDIRECT fallback) never emits tproxy or socket transparent statements.
	redirSpec := FirewallSpec{
		Mode:         ModeRule,
		PreferTProxy: false,
		TCPPort:      10880,
		UDPPort:      10881,
		DNSPort:      7853,
	}
	redirScript := BuildNFTablesScript(redirSpec)
	for _, forbidden := range []string{"tproxy ip to", "socket transparent", "meta mark set 0x1"} {
		if strings.Contains(redirScript, forbidden) {
			t.Fatalf("unexpected TPROXY syntax %q inside PreferTProxy=false fallback script", forbidden)
		}
	}
	if !strings.Contains(redirScript, "chain tcp_redir_nat") || !strings.Contains(redirScript, "meta l4proto tcp redirect to :10880") {
		t.Fatalf("expected REDIRECT fallback chain in PreferTProxy=false script")
	}
}
