package netbind

import (
	"context"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	nat64CacheTTL         = 30 * time.Second
	nat64FallbackCacheTTL = 2 * time.Second
)

var (
	// Well-Known NAT64 Prefix (RFC 6052: 64:ff9b::/96).
	wellKnownNAT64Prefix = [12]byte{0x00, 0x64, 0xff, 0x9b}

	nat64Mu        sync.RWMutex
	nat64HasPrefix bool
	nat64Prefix    [12]byte
	nat64ExpiresAt time.Time

	// Overridable hooks for platform-specific detection (bind_darwin.go) and unit tests.
	isPureIPv6PhysicalFn = func() bool { return false }
	lookupIPv6Fn         = defaultLookupIPv6
	lookupHostIPsFn      = defaultLookupHostIPs
)

func defaultLookupIPv6(ctx context.Context, host string) ([]net.IP, error) {
	if ctx == nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
	}
	return net.DefaultResolver.LookupIP(ctx, "ip6", host)
}

func defaultLookupHostIPs(ctx context.Context, host string) ([]net.IP, error) {
	if ctx == nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
	}
	return net.DefaultResolver.LookupIP(ctx, "ip", host)
}

// ResetNAT64Cache clears any cached carrier NAT64 /96 prefix so the next dial
// re-evaluates DNS64/ipv4only.arpa after a network transition (Wi-Fi <-> 4G/5G).
func ResetNAT64Cache() {
	nat64Mu.Lock()
	nat64HasPrefix = false
	nat64Prefix = [12]byte{}
	nat64ExpiresAt = time.Time{}
	nat64Mu.Unlock()
}

// IsPureIPv6Physical reports whether the active physical interface is pure-IPv6.
func IsPureIPv6Physical() bool {
	nat64Mu.RLock()
	fn := isPureIPv6PhysicalFn
	nat64Mu.RUnlock()
	return fn()
}

// SetNAT64TestHooks overrides NAT64 detection/DNS64 hooks for cross-package tests
// and returns a restore callback that also clears the NAT64 cache.
func SetNAT64TestHooks(
	isPureIPv6 func() bool,
	lookupIPv6 func(context.Context, string) ([]net.IP, error),
	lookupHost func(context.Context, string) ([]net.IP, error),
) func() {
	nat64Mu.Lock()
	origPure := isPureIPv6PhysicalFn
	origV6 := lookupIPv6Fn
	origHost := lookupHostIPsFn
	if isPureIPv6 != nil {
		isPureIPv6PhysicalFn = isPureIPv6
	}
	if lookupIPv6 != nil {
		lookupIPv6Fn = lookupIPv6
	}
	if lookupHost != nil {
		lookupHostIPsFn = lookupHost
	}
	nat64HasPrefix = false
	nat64Prefix = [12]byte{}
	nat64ExpiresAt = time.Time{}
	nat64Mu.Unlock()
	return func() {
		nat64Mu.Lock()
		isPureIPv6PhysicalFn = origPure
		lookupIPv6Fn = origV6
		lookupHostIPsFn = origHost
		nat64HasPrefix = false
		nat64Prefix = [12]byte{}
		nat64ExpiresAt = time.Time{}
		nat64Mu.Unlock()
	}
}

// ExtractNAT64Prefix extracts the /96 NAT64 prefix from an AAAA answer to RFC 7050 ipv4only.arpa
// (whose synthesized IPv4 suffix is 192.0.0.170 or 192.0.0.171), or returns ok=false otherwise.
func ExtractNAT64Prefix(ip net.IP) ([12]byte, bool) {
	var prefix [12]byte
	if ip == nil || ip.To4() != nil {
		return prefix, false
	}
	ip16 := ip.To16()
	if len(ip16) != net.IPv6len {
		return prefix, false
	}
	// RFC 7050 well-known IPv4-only addresses: 192.0.0.170 and 192.0.0.171.
	is170 := ip16[12] == 192 && ip16[13] == 0 && ip16[14] == 0 && ip16[15] == 170
	is171 := ip16[12] == 192 && ip16[13] == 0 && ip16[14] == 0 && ip16[15] == 171
	if !is170 && !is171 {
		return prefix, false
	}
	copy(prefix[:], ip16[:12])
	return prefix, true
}

// SynthesizeNAT64IPv4 maps an IPv4 address onto a /96 NAT64 IPv6 address (RFC 6052).
func SynthesizeNAT64IPv4(prefix [12]byte, ip4 net.IP) net.IP {
	v4 := ip4.To4()
	if v4 == nil {
		return nil
	}
	out := make(net.IP, net.IPv6len)
	copy(out[:12], prefix[:])
	copy(out[12:16], v4)
	return out
}

// DiscoverNAT64Prefix queries RFC 7050 ipv4only.arpa to discover the active /96 NAT64 prefix.
// Operator-discovered prefixes are cached for 30s; transient fallback to wellKnownNAT64Prefix
// is cached only for 2s so handoffs retry quickly. Cleared on ResetNAT64Cache().
func DiscoverNAT64Prefix(ctx context.Context) ([12]byte, bool) {
	nat64Mu.RLock()
	lookupFn := lookupIPv6Fn
	if nat64HasPrefix && time.Now().Before(nat64ExpiresAt) {
		p := nat64Prefix
		nat64Mu.RUnlock()
		return p, true
	}
	nat64Mu.RUnlock()

	lookupCtx := ctx
	if lookupCtx == nil {
		var cancel context.CancelFunc
		lookupCtx, cancel = context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
	}

	var discovered [12]byte
	found := false
	if ips, err := lookupFn(lookupCtx, "ipv4only.arpa"); err == nil {
		for _, ip := range ips {
			if p, ok := ExtractNAT64Prefix(ip); ok {
				discovered = p
				found = true
				break
			}
		}
	}
	ttl := nat64CacheTTL
	if !found {
		discovered = wellKnownNAT64Prefix
		ttl = nat64FallbackCacheTTL
	}

	nat64Mu.Lock()
	nat64Prefix = discovered
	nat64HasPrefix = true
	nat64ExpiresAt = time.Now().Add(ttl)
	nat64Mu.Unlock()
	return discovered, true
}

// ResolveTargetHost prepares host for outbound dialing. On pure-IPv6 cellular networks
// (where CLAT46 is unavailable inside iOS NEPacketTunnelProvider), IPv4 destinations are
// automatically synthesized into NAT64 IPv6 addresses via RFC 7050/6052.
func ResolveTargetHost(ctx context.Context, host string) string {
	h := strings.TrimSpace(host)
	h = strings.Trim(h, "[]")
	nat64Mu.RLock()
	isPureV6Fn := isPureIPv6PhysicalFn
	hostLookupFn := lookupHostIPsFn
	nat64Mu.RUnlock()
	if h == "" || !isPureV6Fn() {
		return h
	}

	if ip := net.ParseIP(h); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			prefix, ok := DiscoverNAT64Prefix(ctx)
			if ok {
				if synth := SynthesizeNAT64IPv4(prefix, ip4); synth != nil {
					return synth.String()
				}
			}
		}
		return ip.String()
	}

	if ips, err := hostLookupFn(ctx, h); err == nil && len(ips) > 0 {
		for _, ip := range ips {
			if ip.To4() == nil && ip.To16() != nil {
				return ip.String()
			}
		}
		if ip4 := ips[0].To4(); ip4 != nil {
			if prefix, ok := DiscoverNAT64Prefix(ctx); ok {
				if synth := SynthesizeNAT64IPv4(prefix, ip4); synth != nil {
					return synth.String()
				}
			}
		}
	}
	return h
}

// ResolveTCPHostPort returns host:port with automatic NAT64 IPv6 synthesis on pure-IPv6 networks.
func ResolveTCPHostPort(ctx context.Context, host string, port int) string {
	return net.JoinHostPort(ResolveTargetHost(ctx, host), strconv.Itoa(port))
}

// ResolveUDPAddr resolves host:port with automatic NAT64 IPv6 synthesis on pure-IPv6 networks.
func ResolveUDPAddr(ctx context.Context, host string, port int) (*net.UDPAddr, error) {
	resolved := ResolveTargetHost(ctx, host)
	return net.ResolveUDPAddr("udp", net.JoinHostPort(resolved, strconv.Itoa(port)))
}

// ResolveTCPTarget translates a "host:port" string for outbound TCP dialing,
// synthesizing NAT64 IPv6 addresses automatically on pure-IPv6 networks.
func ResolveTCPTarget(ctx context.Context, hostport string) string {
	h, p, err := net.SplitHostPort(strings.TrimSpace(hostport))
	if err != nil {
		return hostport
	}
	port, err := strconv.Atoi(p)
	if err != nil || port <= 0 || port > 65535 {
		return hostport
	}
	return ResolveTCPHostPort(ctx, h, port)
}

// ResolveUDPTarget resolves a "host:port" string into a *net.UDPAddr with automatic
// NAT64 IPv6 synthesis on pure-IPv6 networks.
func ResolveUDPTarget(ctx context.Context, hostport string) (*net.UDPAddr, error) {
	h, p, err := net.SplitHostPort(strings.TrimSpace(hostport))
	if err != nil {
		return net.ResolveUDPAddr("udp", hostport)
	}
	port, err := strconv.Atoi(p)
	if err != nil || port <= 0 || port > 65535 {
		return net.ResolveUDPAddr("udp", hostport)
	}
	return ResolveUDPAddr(ctx, h, port)
}
