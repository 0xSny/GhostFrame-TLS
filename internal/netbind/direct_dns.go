package netbind

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	directDNSDialTimeout = 2500 * time.Millisecond
	directDNSCacheTTL    = 60 * time.Second
	directDNSCacheMax    = 512
)

var (
	directDNSv4Servers = []string{"223.5.5.5:53", "119.29.29.29:53"}
	directDNSv6Servers = []string{"[2400:3200::1]:53", "[2402:4e00::]:53"}

	directDNSCacheMu sync.Mutex
	directDNSCache   = make(map[string]directDNSCacheEntry)

	directDNSInflightMu sync.Mutex
	directDNSInflight   = make(map[string]*directDNSInFlightCall)

	// Overridable in unit tests to point physical direct DNS lookups at a local mock DNS server.
	directDNSServersOverride []string
)

type directDNSCacheEntry struct {
	ips       []net.IP
	expiresAt time.Time
}

type directDNSInFlightCall struct {
	done chan struct{}
	ips  []net.IP
	err  error
}

// ClearDirectDNSCache purges all cached direct DNS answers. Called automatically when
// network interfaces change or ResetNAT64Cache runs.
func ClearDirectDNSCache() {
	directDNSCacheMu.Lock()
	clear(directDNSCache)
	directDNSCacheMu.Unlock()
}

func cloneIPSlice(ips []net.IP) []net.IP {
	if len(ips) == 0 {
		return nil
	}
	out := make([]net.IP, len(ips))
	for i, ip := range ips {
		out[i] = append(net.IP(nil), ip...)
	}
	return out
}

func filterNonFakeIPs(ips []net.IP) (clean []net.IP, sawFake bool) {
	if len(ips) == 0 {
		return nil, false
	}
	seen := make(map[string]struct{}, len(ips))
	for _, ip := range ips {
		if ip == nil || ip.IsUnspecified() || ip.IsMulticast() {
			continue
		}
		if IsFakeIP(ip) {
			sawFake = true
			continue
		}
		key := ip.String()
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		clean = append(clean, append(net.IP(nil), ip...))
	}
	return clean, sawFake
}

func directDNSServersForPhysical() []string {
	directDNSCacheMu.Lock()
	override := append([]string(nil), directDNSServersOverride...)
	directDNSCacheMu.Unlock()
	if len(override) > 0 {
		return override
	}

	hasV4, hasV6 := PhysicalInterfaceFamilies()
	if IsPureIPv6Physical() || (!hasV4 && hasV6) {
		return append([]string(nil), directDNSv6Servers...)
	}
	servers := make([]string, 0, len(directDNSv4Servers)+len(directDNSv6Servers))
	if hasV4 || !hasV6 {
		servers = append(servers, directDNSv4Servers...)
	}
	if hasV6 {
		servers = append(servers, directDNSv6Servers...)
	}
	return servers
}

func selectDNSUpstreamDial(network, serverAddr string) (dialNet, target string) {
	target = strings.TrimSpace(serverAddr)
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		target = net.JoinHostPort(strings.Trim(target, "[]"), "53")
		host, _, _ = net.SplitHostPort(target)
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	isTCP := strings.HasPrefix(network, "tcp")
	base := "udp"
	if isTCP {
		base = "tcp"
	}
	if ip != nil {
		if ip.To4() != nil {
			return base + "4", target
		}
		return base + "6", target
	}
	return base, target
}

func newDirectResolver(serverAddr string) *net.Resolver {
	srv := strings.TrimSpace(serverAddr)
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			chosen := srv
			if chosen == "" {
				servers := directDNSServersForPhysical()
				if len(servers) > 0 {
					chosen = servers[0]
				} else {
					chosen = directDNSv4Servers[0]
				}
			}
			dialNet, target := selectDNSUpstreamDial(network, chosen)
			d := net.Dialer{
				Timeout: directDNSDialTimeout,
				Control: Control,
			}
			return d.DialContext(ctx, dialNet, target)
		},
	}
}

// DirectResolver returns a pure-Go *net.Resolver bound to the physical interface via Control,
// bypassing iOS mDNSResponder and NEDNSSettings Fake-IP (198.18.0.1).
func DirectResolver() *net.Resolver {
	return newDirectResolver("")
}

func getCachedDirectDNS(key string) ([]net.IP, bool) {
	now := time.Now()
	directDNSCacheMu.Lock()
	defer directDNSCacheMu.Unlock()
	ent, ok := directDNSCache[key]
	if !ok {
		return nil, false
	}
	if now.After(ent.expiresAt) {
		delete(directDNSCache, key)
		return nil, false
	}
	return cloneIPSlice(ent.ips), true
}

func putCachedDirectDNS(key string, ips []net.IP) {
	if key == "" || len(ips) == 0 {
		return
	}
	now := time.Now()
	directDNSCacheMu.Lock()
	defer directDNSCacheMu.Unlock()
	if len(directDNSCache) >= directDNSCacheMax {
		for k, ent := range directDNSCache {
			if now.After(ent.expiresAt) {
				delete(directDNSCache, k)
			}
		}
		for len(directDNSCache) >= directDNSCacheMax {
			for k := range directDNSCache {
				delete(directDNSCache, k)
				break
			}
		}
	}
	directDNSCache[key] = directDNSCacheEntry{
		ips:       cloneIPSlice(ips),
		expiresAt: now.Add(directDNSCacheTTL),
	}
}

// DirectLookupHostIPs resolves host via the physical-interface-bound pure-Go resolver against
// public direct DNS servers (223.5.5.5 / 119.29.29.29 on IPv4; 2400:3200::1 / 2402:4e00:: on IPv6),
// filtering any Fake-IP answers and caching up to 512 entries for 60s.
func DirectLookupHostIPs(ctx context.Context, host string) ([]net.IP, error) {
	return DirectLookupHostIPsFamily(ctx, host, "ip")
}

// DirectLookupHostIPsFamily resolves host using the requested address family ("ip4" or "ip")
// with in-flight singleflight coalescing and 60s positive caching.
func DirectLookupHostIPsFamily(ctx context.Context, host, network string) ([]net.IP, error) {
	h := strings.TrimSpace(host)
	h = strings.Trim(h, "[]")
	if h == "" {
		return nil, &net.DNSError{Err: "empty host", Name: host}
	}
	fam := strings.TrimSpace(strings.ToLower(network))
	if fam != "ip4" && fam != "ip6" {
		fam = "ip"
	}
	if strings.EqualFold(h, "localhost") {
		if fam == "ip4" {
			return []net.IP{net.IPv4(127, 0, 0, 1)}, nil
		}
		if IsPureIPv6Physical() {
			return []net.IP{net.IPv6loopback, net.IPv4(127, 0, 0, 1)}, nil
		}
		return []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}, nil
	}
	if ip := parseAddressIP(h); ip != nil {
		if IsFakeIP(ip) {
			return nil, ErrFakeIPBlocked
		}
		return []net.IP{append(net.IP(nil), ip...)}, nil
	}

	cacheKey := fam + "|" + strings.ToLower(strings.TrimSuffix(h, "."))
	if cached, ok := getCachedDirectDNS(cacheKey); ok {
		return cached, nil
	}

	// Singleflight dedup: coalesce concurrent lookups for the same domain+family.
	directDNSInflightMu.Lock()
	if call, ok := directDNSInflight[cacheKey]; ok {
		directDNSInflightMu.Unlock()
		if ctx == nil {
			<-call.done
		} else {
			select {
			case <-call.done:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		return cloneIPSlice(call.ips), call.err
	}
	call := &directDNSInFlightCall{done: make(chan struct{})}
	directDNSInflight[cacheKey] = call
	directDNSInflightMu.Unlock()

	if ctx == nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
	}

	servers := directDNSServersForPhysical()
	var lastErr error
	sawFake := false

	for _, srv := range servers {
		perTryCtx := ctx
		var cancelTry context.CancelFunc
		if _, hasDeadline := ctx.Deadline(); !hasDeadline {
			perTryCtx, cancelTry = context.WithTimeout(ctx, directDNSDialTimeout)
		}
		ips, err := newDirectResolver(srv).LookupIP(perTryCtx, fam, h)
		if cancelTry != nil {
			cancelTry()
		}
		if err != nil {
			lastErr = err
			if ctx.Err() != nil {
				break
			}
			continue
		}
		clean, hadFake := filterNonFakeIPs(ips)
		if hadFake {
			sawFake = true
		}
		if len(clean) > 0 {
			putCachedDirectDNS(cacheKey, clean)
			call.ips = clean
			directDNSInflightMu.Lock()
			delete(directDNSInflight, cacheKey)
			directDNSInflightMu.Unlock()
			close(call.done)
			return cloneIPSlice(clean), nil
		}
	}

	var resErr error
	if sawFake {
		resErr = ErrFakeIPBlocked
	} else if lastErr != nil {
		resErr = lastErr
	} else {
		resErr = &net.DNSError{Err: "no non-fake direct DNS addresses found", Name: h, IsNotFound: true}
	}
	call.err = resErr
	directDNSInflightMu.Lock()
	delete(directDNSInflight, cacheKey)
	directDNSInflightMu.Unlock()
	close(call.done)
	return nil, resErr
}
