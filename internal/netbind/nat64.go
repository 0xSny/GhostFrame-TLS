package netbind

import (
	"context"
	"errors"
	"net"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ErrIPv6Disabled is returned when a direct resolution only has IPv6 addresses
// while IPv6 is disabled on a non-pure-IPv6 interface.
var ErrIPv6Disabled = errors.New("netbind: ipv6 disabled")

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

func isDefaultLookupHostIPsFn(fn func(context.Context, string) ([]net.IP, error)) bool {
	if fn == nil {
		return true
	}
	return reflect.ValueOf(fn).Pointer() == reflect.ValueOf(defaultLookupHostIPs).Pointer()
}

func defaultLookupIPv6(ctx context.Context, host string) ([]net.IP, error) {
	ips, err := DirectLookupHostIPs(ctx, host)
	if err != nil {
		return nil, err
	}
	out := make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		if ip != nil && ip.To4() == nil && ip.To16() != nil && !IsFakeIP(ip) {
			out = append(out, ip)
		}
	}
	if len(out) == 0 {
		return nil, &net.DNSError{Err: "no direct IPv6 address found", Name: host, IsNotFound: true}
	}
	return out, nil
}

func defaultLookupHostIPs(ctx context.Context, host string) ([]net.IP, error) {
	return DirectLookupHostIPs(ctx, host)
}

// ResetNAT64Cache clears any cached carrier NAT64 /96 prefix and direct DNS cache
// so the next dial re-evaluates DNS64/ipv4only.arpa after a network transition (Wi-Fi <-> 4G/5G).
func ResetNAT64Cache() {
	nat64Mu.Lock()
	nat64HasPrefix = false
	nat64Prefix = [12]byte{}
	nat64ExpiresAt = time.Time{}
	nat64Mu.Unlock()
	ClearDirectDNSCache()
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
		clean, _ := filterNonFakeIPs(ips)
		for _, ip := range clean {
			if ip.To4() == nil && ip.To16() != nil {
				return ip.String()
			}
		}
		if len(clean) > 0 {
			if ip4 := clean[0].To4(); ip4 != nil {
				if prefix, ok := DiscoverNAT64Prefix(ctx); ok {
					if synth := SynthesizeNAT64IPv4(prefix, ip4); synth != nil {
						return synth.String()
					}
				}
			}
			return clean[0].String()
		}
	}
	return h
}

// ResolveTCPHostPort returns host:port with automatic NAT64 IPv6 synthesis on pure-IPv6 networks.
func ResolveTCPHostPort(ctx context.Context, host string, port int) string {
	return net.JoinHostPort(ResolveTargetHost(ctx, host), strconv.Itoa(port))
}

// ResolveUDPAddr resolves host:port with automatic NAT64 IPv6 synthesis on pure-IPv6 networks
// using physical-interface-bound direct DNS (bypassing net.DefaultResolver).
func ResolveUDPAddr(ctx context.Context, host string, port int) (*net.UDPAddr, error) {
	_, ua, err := ResolveDirectUDPAddr(ctx, net.JoinHostPort(host, strconv.Itoa(port)), true)
	return ua, err
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
// NAT64 IPv6 synthesis on pure-IPv6 networks (bypassing net.DefaultResolver).
func ResolveUDPTarget(ctx context.Context, hostport string) (*net.UDPAddr, error) {
	_, ua, err := ResolveDirectUDPAddr(ctx, hostport, true)
	return ua, err
}

// DirectEndpoint represents a resolved concrete dial network ("tcp4"/"tcp6") and ip:port address.
type DirectEndpoint struct {
	DialNet string
	Addr    string
}

func resolveDirectEndpointMulti(ctx context.Context, hostport, familyPrefix string, allowIPv6 bool) (dialNets []string, resolvedIPs []net.IP, zone string, port int, err error) {
	h, pStr, splitErr := net.SplitHostPort(strings.TrimSpace(hostport))
	if splitErr != nil {
		return nil, nil, "", 0, splitErr
	}
	port, err = strconv.Atoi(pStr)
	if err != nil || port <= 0 || port > 65535 {
		return nil, nil, "", 0, errors.New("netbind: invalid target port")
	}

	rawHost := strings.TrimSpace(strings.Trim(h, "[]"))
	if rawHost == "" {
		return nil, nil, "", 0, errors.New("netbind: empty target host")
	}
	hostNoZone := rawHost
	if zIdx := strings.IndexByte(rawHost, '%'); zIdx >= 0 {
		hostNoZone = rawHost[:zIdx]
		zone = rawHost[zIdx+1:]
	}

	nat64Mu.RLock()
	pureFn := isPureIPv6PhysicalFn
	lookupFn := lookupHostIPsFn
	nat64Mu.RUnlock()
	pureV6 := pureFn != nil && pureFn()

	if strings.EqualFold(hostNoZone, "localhost") {
		if pureV6 {
			return []string{familyPrefix + "6"}, []net.IP{net.IPv6loopback}, "", port, nil
		}
		return []string{familyPrefix + "4"}, []net.IP{net.IPv4(127, 0, 0, 1)}, "", port, nil
	}

	if ip := net.ParseIP(hostNoZone); ip != nil {
		if IsFakeIP(ip) {
			return nil, nil, "", 0, ErrFakeIPBlocked
		}
		if ip4 := ip.To4(); ip4 != nil {
			if pureV6 {
				if pref, ok := DiscoverNAT64Prefix(ctx); ok {
					if synth := SynthesizeNAT64IPv4(pref, ip4); synth != nil {
						return []string{familyPrefix + "6"}, []net.IP{synth}, "", port, nil
					}
				}
				return nil, nil, "", 0, errors.New("netbind: NAT64 synthesis failed on pure-IPv6 interface")
			}
			return []string{familyPrefix + "4"}, []net.IP{ip4}, "", port, nil
		}
		if !allowIPv6 && !pureV6 && !ip.IsLoopback() {
			return nil, nil, "", 0, ErrIPv6Disabled
		}
		return []string{familyPrefix + "6"}, []net.IP{ip}, zone, port, nil
	}

	var ips []net.IP
	if !allowIPv6 && !pureV6 && lookupFn != nil {
		// Use explicit IPv4 ("ip4") direct DNS lookup when IPv6 is disabled to avoid wasted AAAA queries.
		nat64Mu.RLock()
		isDefault := isDefaultLookupHostIPsFn(lookupFn)
		nat64Mu.RUnlock()
		if isDefault {
			ips, err = DirectLookupHostIPsFamily(ctx, hostNoZone, "ip4")
		} else {
			ips, err = lookupFn(ctx, hostNoZone)
		}
	} else {
		ips, err = lookupFn(ctx, hostNoZone)
	}
	if err != nil {
		return nil, nil, "", 0, err
	}
	clean, hadFake := filterNonFakeIPs(ips)
	if len(clean) == 0 {
		if hadFake {
			return nil, nil, "", 0, ErrFakeIPBlocked
		}
		return nil, nil, "", 0, &net.DNSError{Err: "no direct IP resolved", Name: hostNoZone, IsNotFound: true}
	}

	var v4List, v6List []net.IP
	for _, ip := range clean {
		if ip4 := ip.To4(); ip4 != nil {
			v4List = append(v4List, ip4)
		} else {
			v6List = append(v6List, ip)
		}
	}

	if pureV6 {
		for _, ip6 := range v6List {
			dialNets = append(dialNets, familyPrefix+"6")
			resolvedIPs = append(resolvedIPs, ip6)
		}
		if len(v4List) > 0 {
			if pref, ok := DiscoverNAT64Prefix(ctx); ok {
				for _, ip4 := range v4List {
					if synth := SynthesizeNAT64IPv4(pref, ip4); synth != nil {
						dialNets = append(dialNets, familyPrefix+"6")
						resolvedIPs = append(resolvedIPs, synth)
					}
				}
			}
		}
		if len(resolvedIPs) > 0 {
			return dialNets, resolvedIPs, "", port, nil
		}
		return nil, nil, "", 0, errors.New("netbind: no usable IPv6/NAT64 address for pure-IPv6 interface")
	}

	for _, ip4 := range v4List {
		dialNets = append(dialNets, familyPrefix+"4")
		resolvedIPs = append(resolvedIPs, ip4)
	}
	if allowIPv6 {
		for _, ip6 := range v6List {
			dialNets = append(dialNets, familyPrefix+"6")
			resolvedIPs = append(resolvedIPs, ip6)
		}
	}
	if len(resolvedIPs) > 0 {
		return dialNets, resolvedIPs, "", port, nil
	}
	if len(v6List) > 0 && !allowIPv6 {
		return nil, nil, "", 0, ErrIPv6Disabled
	}
	return nil, nil, "", 0, &net.DNSError{Err: "no usable direct IP resolved", Name: hostNoZone, IsNotFound: true}
}

func resolveDirectEndpoint(ctx context.Context, hostport, familyPrefix string, allowIPv6 bool) (dialNet string, resolvedIP net.IP, zone string, port int, err error) {
	dialNets, resolvedIPs, z, port, err := resolveDirectEndpointMulti(ctx, hostport, familyPrefix, allowIPv6)
	if err != nil {
		return "", nil, "", 0, err
	}
	return dialNets[0], resolvedIPs[0], z, port, nil
}

// ResolveDirectTCPAddrs resolves addr ("host:port") into an ordered slice of concrete IP literal
// targets ("ip:port") and networks ("tcp4" or "tcp6") for sequential multi-IP tolerance.
func ResolveDirectTCPAddrs(ctx context.Context, addr string, allowIPv6 bool) ([]DirectEndpoint, error) {
	dialNets, resolvedIPs, zone, port, err := resolveDirectEndpointMulti(ctx, addr, "tcp", allowIPv6)
	if err != nil {
		return nil, err
	}
	out := make([]DirectEndpoint, 0, len(resolvedIPs))
	portStr := strconv.Itoa(port)
	for i, ip := range resolvedIPs {
		hostStr := ip.String()
		if zone != "" && ip.To4() == nil {
			hostStr = hostStr + "%" + zone
		}
		out = append(out, DirectEndpoint{
			DialNet: dialNets[i],
			Addr:    net.JoinHostPort(hostStr, portStr),
		})
	}
	return out, nil
}

// ResolveDirectTCPAddr resolves addr ("host:port") into a concrete IP literal string ("ip:port")
// and matching network ("tcp4" or "tcp6") using physical-interface-bound direct DNS, Fake-IP
// rejection, and pure-IPv6 NAT64 synthesis. It never delegates host resolution to net.DefaultResolver.
func ResolveDirectTCPAddr(ctx context.Context, addr string, allowIPv6 bool) (dialNet string, resolvedAddr string, err error) {
	eps, err := ResolveDirectTCPAddrs(ctx, addr, allowIPv6)
	if err != nil {
		return "", "", err
	}
	return eps[0].DialNet, eps[0].Addr, nil
}

// ResolveDirectUDPAddr resolves addr ("host:port") into a concrete *net.UDPAddr and matching network
// ("udp4" or "udp6") using physical-interface-bound direct DNS, Fake-IP rejection, and pure-IPv6
// NAT64 synthesis.
func ResolveDirectUDPAddr(ctx context.Context, addr string, allowIPv6 bool) (dialNet string, resolvedUDP *net.UDPAddr, err error) {
	dialNet, ip, zone, port, err := resolveDirectEndpoint(ctx, addr, "udp", allowIPv6)
	if err != nil {
		return "", nil, err
	}
	return dialNet, &net.UDPAddr{IP: ip, Port: port, Zone: zone}, nil
}
