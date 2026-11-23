package netbind

import (
	"net"
	"testing"
)

func TestIsExcludedInterfaceName(t *testing.T) {
	excluded := []string{"lo0", "utun0", "utun4", "ipsec0", "ppp0", "awdl0", "llw0", "bridge100", "ap1", "anpi0", "xhc0", "pktap0", "stf0", "gif0", "feth0", "vmenet0", ""}
	for _, name := range excluded {
		if !IsExcludedInterfaceName(name) {
			t.Fatalf("expected %q to be excluded", name)
		}
	}

	allowed := []string{"en0", "en1", "pdp_ip0", "pdp_ip1", "eth0"}
	for _, name := range allowed {
		if IsExcludedInterfaceName(name) {
			t.Fatalf("expected %q to be allowed", name)
		}
	}
}

func TestIsLoopbackAddress(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:443", "127.0.1.1:80", "[::1]:443", "::1", "localhost:7890"} {
		if !isLoopbackAddress(addr) {
			t.Fatalf("expected %q to be detected as loopback", addr)
		}
	}
	for _, addr := range []string{"", ":0", "0.0.0.0:443", "38.105.30.170:443", "[2001:4860:4860::8888]:443"} {
		if isLoopbackAddress(addr) {
			t.Fatalf("expected %q NOT to be loopback", addr)
		}
	}
}

func TestSelectBestInterface(t *testing.T) {
	candidates := []InterfaceCandidate{
		{Name: "lo0", Up: true, Loopback: true, HasUnicast: true},
		{Name: "utun4", Up: true, Loopback: false, HasUnicast: true},
		{Name: "awdl0", Up: true, Loopback: false, HasUnicast: true},
		{Name: "llw0", Up: true, Loopback: false, HasUnicast: true},
		{Name: "bridge0", Up: true, Loopback: false, HasUnicast: true},
		{Name: "ap1", Up: true, Loopback: false, HasUnicast: true},
		{Name: "pdp_ip0", Up: true, Loopback: false, HasUnicast: true},
		{Name: "en0", Up: true, Loopback: false, HasUnicast: true},
	}

	if got := SelectBestInterface(candidates, ""); got != "en0" {
		t.Fatalf("expected en0 priority, got %q", got)
	}
	if got := SelectBestInterface(candidates, "pdp_ip0"); got != "pdp_ip0" {
		t.Fatalf("expected preferred pdp_ip0, got %q", got)
	}
	if got := SelectBestInterface(candidates, "utun4"); got != "en0" {
		t.Fatalf("expected excluded utun4 preference to be ignored, got %q", got)
	}

	// Wi-Fi down -> fall back to cellular pdp_ip0
	cellularOnly := []InterfaceCandidate{
		{Name: "utun3", Up: true, Loopback: false, HasUnicast: true},
		{Name: "en0", Up: false, Loopback: false, HasUnicast: false},
		{Name: "pdp_ip0", Up: true, Loopback: false, HasUnicast: true},
	}
	if got := SelectBestInterface(cellularOnly, "en0"); got != "pdp_ip0" {
		t.Fatalf("expected cellular fallback pdp_ip0 when en0 down, got %q", got)
	}
}

func TestPreferredInterfaceRoundTrip(t *testing.T) {
	SetPreferredInterface("pdp_ip0")
	t.Cleanup(func() { SetPreferredInterface("") })
	if got := PreferredInterface(); got != "pdp_ip0" {
		t.Fatalf("expected pdp_ip0, got %q", got)
	}
}

func TestIsRoutableUnicastIP(t *testing.T) {
	if isRoutableUnicastIP(net.ParseIP("169.254.12.34")) {
		t.Fatal("expected IPv4 link-local 169.254.x.x to be rejected")
	}
	if isRoutableUnicastIP(net.ParseIP("fe80::1")) {
		t.Fatal("expected IPv6 link-local fe80::1 to be rejected")
	}
	if isRoutableUnicastIP(net.ParseIP("127.0.0.1")) {
		t.Fatal("expected loopback 127.0.0.1 to be rejected")
	}
	if !isRoutableUnicastIP(net.ParseIP("10.123.45.6")) {
		t.Fatal("expected cellular/NAT IPv4 10.x to be accepted")
	}
	if !isRoutableUnicastIP(net.ParseIP("192.168.1.50")) {
		t.Fatal("expected LAN IPv4 192.168.x.x to be accepted")
	}
	if !isRoutableUnicastIP(net.ParseIP("2409:8900::1")) {
		t.Fatal("expected global unicast IPv6 to be accepted")
	}
}

func TestDirectBindToggle(t *testing.T) {
	if !DirectBindEnabled() {
		t.Fatal("expected DirectBindEnabled to default to true")
	}
	SetDirectBindEnabled(false)
	t.Cleanup(func() { SetDirectBindEnabled(true) })
	if DirectBindEnabled() {
		t.Fatal("expected DirectBindEnabled to be false after disabling")
	}
	SetDirectBindEnabled(true)
	if !DirectBindEnabled() {
		t.Fatal("expected DirectBindEnabled to be true after re-enabling")
	}
}

func TestOutboundMarkToggle(t *testing.T) {
	if got := OutboundMark(); got != 0 {
		t.Fatalf("expected default OutboundMark 0, got %d", got)
	}
	SetOutboundMark(0xff)
	t.Cleanup(func() { SetOutboundMark(0) })
	if got := OutboundMark(); got != 0xff {
		t.Fatalf("expected OutboundMark 0xff, got 0x%x", got)
	}
	SetOutboundMark(-5)
	if got := OutboundMark(); got != 0 {
		t.Fatalf("expected negative OutboundMark clamped to 0, got %d", got)
	}
}

type mockProtector struct {
	lastFD int32
}

func (m *mockProtector) ProtectFD(fd int32) bool {
	m.lastFD = fd
	return fd > 0
}

func TestSocketProtectorRoundTrip(t *testing.T) {
	if HasSocketProtector() {
		t.Fatal("expected HasSocketProtector() == false initially")
	}
	mp := &mockProtector{}
	SetSocketProtector(mp)
	t.Cleanup(func() { SetSocketProtector(nil) })

	if !HasSocketProtector() {
		t.Fatal("expected HasSocketProtector() == true after registration")
	}
	if !ProtectSocketFD(42) || mp.lastFD != 42 {
		t.Fatalf("expected ProtectSocketFD(42) true with lastFD=42, got lastFD=%d", mp.lastFD)
	}
	if ProtectSocketFD(0) {
		t.Fatal("expected ProtectSocketFD(0) false")
	}
}
