package netbind

import (
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
)

// ErrFakeIPBlocked is returned when a direct outbound socket or resolver receives
// an internal Fake-IP range address (198.18.0.0/15 or fd18:c612::/64).
var ErrFakeIPBlocked = errors.New("netbind: target IP falls inside Fake-IP reserved range")

var excludedPrefixes = []string{
	"lo",
	"utun",
	"ipsec",
	"ppp",
	"awdl",
	"llw",
	"bridge",
	"ap",
	"anpi",
	"xhc",
	"pktap",
	"stf",
	"gif",
	"feth",
	"vmenet",
}

var (
	preferredMu        sync.RWMutex
	preferredIface     string
	directBindEnabled  atomic.Bool
	outboundMark       atomic.Int32
	physicalFamiliesFn = defaultPhysicalInterfaceFamilies
)

func init() {
	directBindEnabled.Store(true)
}

// SetOutboundMark configures the Linux SO_MARK value (e.g. 0xff) attached to
// outbound sockets created via netbind.Control for anti-loop transparent proxying.
// Passing 0 disables SO_MARK tagging.
func SetOutboundMark(mark int) {
	if mark < 0 {
		mark = 0
	}
	outboundMark.Store(int32(mark))
}

// OutboundMark returns the active Linux SO_MARK value (0 if disabled).
func OutboundMark() int {
	return int(outboundMark.Load())
}

// SetDirectBindEnabled controls whether netbind.Control pins outbound sockets to a
// physical interface via IP_BOUND_IF/IPV6_BOUND_IF. Inside iOS NEPacketTunnelProvider,
// disable direct binding so the kernel's default physical route & NAT64 work natively.
func SetDirectBindEnabled(enabled bool) {
	directBindEnabled.Store(enabled)
}

// DirectBindEnabled reports whether physical interface socket pinning is enabled.
func DirectBindEnabled() bool {
	return directBindEnabled.Load()
}

// SetPreferredInterface sets the preferred physical outbound interface name (e.g. "en0", "pdp_ip0").
// Passing an empty string clears the preference and falls back to automatic detection.
func SetPreferredInterface(name string) {
	preferredMu.Lock()
	preferredIface = strings.TrimSpace(name)
	preferredMu.Unlock()
	ResetNAT64Cache()
}

// PreferredInterface returns the currently configured preferred physical interface name, if any.
func PreferredInterface() string {
	preferredMu.RLock()
	name := preferredIface
	preferredMu.RUnlock()
	return name
}

// IsExcludedInterfaceName reports whether an interface name belongs to virtual/tunnel/local interfaces
// that must never be bound as the outbound physical interface on Darwin/iOS.
func IsExcludedInterfaceName(name string) bool {
	lower := strings.ToLower(strings.TrimSpace(name))
	if lower == "" {
		return true
	}
	for _, prefix := range excludedPrefixes {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

// isLoopbackAddress reports whether address targets localhost / 127.0.0.0/8 / ::1.
func isLoopbackAddress(address string) bool {
	trimmed := strings.TrimSpace(address)
	if trimmed == "" {
		return false
	}
	host := trimmed
	if h, _, err := net.SplitHostPort(trimmed); err == nil {
		host = h
	} else {
		host = strings.Trim(trimmed, "[]")
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// InterfaceCandidate captures interface state used for physical interface selection.
type InterfaceCandidate struct {
	Name       string
	Up         bool
	Loopback   bool
	HasUnicast bool
}

// SelectBestInterface picks the highest-priority physical interface from candidates.
// Preference order:
//  1. Explicitly preferred interface (if up, non-loopback, has unicast IP, and not excluded)
//  2. "en0" (Wi-Fi / Ethernet primary on iOS/macOS)
//  3. Other non-excluded "en*" interfaces (e.g., en1 / USB / wired)
//  4. "pdp_ip*" (iOS cellular interface, ordered numerically/lexically)
//  5. Any remaining eligible non-excluded physical interface
func SelectBestInterface(candidates []InterfaceCandidate, preferred string) string {
	eligible := make([]string, 0, len(candidates))
	preferred = strings.TrimSpace(preferred)

	for _, c := range candidates {
		if !c.Up || c.Loopback || !c.HasUnicast || IsExcludedInterfaceName(c.Name) {
			continue
		}
		if preferred != "" && c.Name == preferred {
			return c.Name
		}
		eligible = append(eligible, c.Name)
	}
	for _, name := range eligible {
		if name == "en0" {
			return name
		}
	}
	for _, name := range eligible {
		if strings.HasPrefix(name, "en") {
			return name
		}
	}
	for _, name := range eligible {
		if strings.HasPrefix(name, "pdp_ip") {
			return name
		}
	}
	if len(eligible) > 0 {
		return eligible[0]
	}
	return ""
}

func isRoutableUnicastIP(ip net.IP) bool {
	if ip == nil || ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() {
		return false
	}
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}
	return true
}

func interfaceHasValidUnicast(iface net.Interface) bool {
	addrs, err := iface.Addrs()
	if err != nil {
		return false
	}
	for _, addr := range addrs {
		var ip net.IP
		switch v := addr.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if isRoutableUnicastIP(ip) {
			return true
		}
	}
	return false
}

// IsFakeIP reports whether ip falls within the internal TUN Fake-IP ranges
// (198.18.0.0/15 or fd18:c612::/64).
func IsFakeIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip4 := ip.To4(); ip4 != nil {
		return ip4[0] == 198 && (ip4[1] == 18 || ip4[1] == 19)
	}
	ip16 := ip.To16()
	if ip16 == nil {
		return false
	}
	return ip16[0] == 0xfd &&
		ip16[1] == 0x18 &&
		ip16[2] == 0xc6 &&
		ip16[3] == 0x12 &&
		ip16[4] == 0 &&
		ip16[5] == 0 &&
		ip16[6] == 0 &&
		ip16[7] == 0
}

func parseAddressIP(address string) net.IP {
	trimmed := strings.TrimSpace(address)
	if trimmed == "" {
		return nil
	}
	host := trimmed
	if h, _, err := net.SplitHostPort(trimmed); err == nil {
		host = h
	} else {
		host = strings.Trim(trimmed, "[]")
	}
	if idx := strings.IndexByte(host, '%'); idx >= 0 {
		host = host[:idx]
	}
	return net.ParseIP(host)
}

func interfaceHasRoutableFamily(iface *net.Interface, wantV4 bool) bool {
	if iface == nil {
		return false
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return false
	}
	for _, addr := range addrs {
		var ip net.IP
		switch v := addr.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if !isRoutableUnicastIP(ip) {
			continue
		}
		if wantV4 && ip.To4() != nil {
			return true
		}
		if !wantV4 && ip.To4() == nil {
			return true
		}
	}
	return false
}

func defaultPhysicalInterfaceFamilies() (hasV4, hasV6 bool) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return true, false
	}
	for i := range ifaces {
		iface := &ifaces[i]
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 || IsExcludedInterfaceName(iface.Name) {
			continue
		}
		if interfaceHasRoutableFamily(iface, true) {
			hasV4 = true
		}
		if interfaceHasRoutableFamily(iface, false) {
			hasV6 = true
		}
	}
	if !hasV4 && !hasV6 {
		return true, false
	}
	return hasV4, hasV6
}

// PhysicalInterfaceFamilies reports whether the active physical interface has routable
// IPv4 and/or IPv6 addresses.
func PhysicalInterfaceFamilies() (hasV4, hasV6 bool) {
	nat64Mu.RLock()
	fn := physicalFamiliesFn
	nat64Mu.RUnlock()
	if fn == nil {
		return true, false
	}
	return fn()
}
