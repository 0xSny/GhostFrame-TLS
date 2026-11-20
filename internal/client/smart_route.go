package client

import (
	"container/list"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"sync"
	"time"

	"ghostframe/internal/netbind"
)

const (
	smartRouteCacheCap     = 4096
	smartRouteCacheTTL     = 10 * time.Minute
	smartDNSProbeTimeout   = 350 * time.Millisecond
	defaultRecentRouteCap  = 80
)

// RecentRouteEntry records a recent routing decision for the Connection Inspector UI.
type RecentRouteEntry struct {
	Time   string `json:"time"`
	Target string `json:"target"`
	Host   string `json:"host"`
	Action string `json:"action"` // DIRECT | PROXY | REJECT
	Reason string `json:"reason"`
}

type recentRouteRing struct {
	mu      sync.Mutex
	cap     int
	entries []RecentRouteEntry
	lastAt  time.Time
}

func newRecentRouteRing(capacity int) *recentRouteRing {
	if capacity <= 0 {
		capacity = defaultRecentRouteCap
	}
	return &recentRouteRing{
		cap:     capacity,
		entries: make([]RecentRouteEntry, 0, capacity),
	}
}

func (r *recentRouteRing) Push(target, host string, act RouteAction, reason string) {
	actStr := strings.ToUpper(act.String())
	now := time.Now()

	r.mu.Lock()
	defer r.mu.Unlock()
	if n := len(r.entries); n > 0 {
		last := r.entries[n-1]
		if last.Host == host && last.Action == actStr && last.Reason == reason && now.Sub(r.lastAt) < 1500*time.Millisecond {
			return
		}
	}
	entry := RecentRouteEntry{
		Time:   now.Format("15:04:05"),
		Target: target,
		Host:   host,
		Action: actStr,
		Reason: reason,
	}
	if len(r.entries) >= r.cap {
		copy(r.entries, r.entries[1:])
		r.entries[len(r.entries)-1] = entry
	} else {
		r.entries = append(r.entries, entry)
	}
	r.lastAt = now
}

func (r *recentRouteRing) EntriesNewestFirst() []RecentRouteEntry {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]RecentRouteEntry, len(r.entries))
	for i := range r.entries {
		out[i] = r.entries[len(r.entries)-1-i]
	}
	return out
}

type smartRouteEntry struct {
	host     string
	act      RouteAction
	reason   string
	directIP string
	wireResp []byte
	wireAt   time.Time
	expires  time.Time
}

type smartInFlightCall struct {
	done chan struct{}
	res  smartRouteEntry
}

type smartRouteCache struct {
	mu      sync.Mutex
	cap     int
	lru     *list.List
	entries map[string]*list.Element
	inflight map[string]*smartInFlightCall
	nowFn   func() time.Time
}

func newSmartRouteCache(capacity int) *smartRouteCache {
	if capacity <= 0 {
		capacity = smartRouteCacheCap
	}
	return &smartRouteCache{
		cap:      capacity,
		lru:      list.New(),
		entries:  make(map[string]*list.Element, 256),
		inflight: make(map[string]*smartInFlightCall),
		nowFn:    time.Now,
	}
}

func (c *smartRouteCache) Get(host string) (smartRouteEntry, bool) {
	now := c.nowFn()
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.entries[host]
	if !ok {
		return smartRouteEntry{}, false
	}
	ent := el.Value.(*smartRouteEntry)
	if now.After(ent.expires) {
		c.lru.Remove(el)
		delete(c.entries, host)
		return smartRouteEntry{}, false
	}
	c.lru.MoveToFront(el)
	cp := *ent
	if len(ent.wireResp) > 0 {
		cp.wireResp = append([]byte(nil), ent.wireResp...)
	}
	return cp, true
}

func (c *smartRouteCache) Put(ent smartRouteEntry) {
	if ent.host == "" {
		return
	}
	ent.expires = c.nowFn().Add(smartRouteCacheTTL)
	if len(ent.wireResp) > 0 {
		ent.wireResp = append([]byte(nil), ent.wireResp...)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.entries[ent.host]; ok {
		dst := el.Value.(*smartRouteEntry)
		*dst = ent
		c.lru.MoveToFront(el)
		return
	}
	for c.lru.Len() >= c.cap {
		back := c.lru.Back()
		if back == nil {
			break
		}
		old := back.Value.(*smartRouteEntry)
		delete(c.entries, old.host)
		c.lru.Remove(back)
	}
	val := ent
	el := c.lru.PushFront(&val)
	c.entries[ent.host] = el
}

func (c *smartRouteCache) Clear() {
	c.mu.Lock()
	c.lru.Init()
	c.entries = make(map[string]*list.Element, 256)
	c.mu.Unlock()
}

var poisonedIPv4CIDRs = func() []*net.IPNet {
	// Known GFW / Fake-IP / non-public ranges never valid as direct CN answers.
	cidrs := []string{
		"198.18.0.0/15",  // Benchmark / TUN Fake-IP space
		"31.13.64.0/18",  // Facebook poisoning block
		"69.63.176.0/20", // Facebook poisoning block
		"157.240.0.0/16", // Meta poisoning block
		"199.16.156.0/22",
		"199.59.148.0/22",
		"104.244.40.0/21",
	}
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, s := range cidrs {
		if _, n, err := net.ParseCIDR(s); err == nil {
			out = append(out, n)
		}
	}
	return out
}()

var poisonedIPv4Singles = map[[4]byte]struct{}{
	{8, 7, 198, 45}:     {},
	{37, 61, 54, 158}:   {},
	{46, 82, 174, 68}:   {},
	{59, 24, 3, 173}:    {},
	{78, 16, 49, 15}:    {},
	{93, 46, 8, 89}:     {},
	{128, 121, 146, 100}: {},
	{159, 24, 3, 173}:   {},
	{159, 106, 121, 75}: {},
	{203, 98, 7, 65}:    {},
	{243, 185, 187, 39}: {},
}

func isValidPublicNonPoisonedIPv4(ip net.IP) (net.IP, bool) {
	ip4 := ip.To4()
	if ip4 == nil || isLANIP(ip4) {
		return nil, false
	}
	var key [4]byte
	copy(key[:], ip4)
	if _, bad := poisonedIPv4Singles[key]; bad {
		return nil, false
	}
	for _, n := range poisonedIPv4CIDRs {
		if n.Contains(ip4) {
			return nil, false
		}
	}
	return ip4, true
}

// DirectCNDNSFunc resolves host via direct CN DNS and returns raw wire response + parsed A IPs.
type DirectCNDNSFunc func(ctx context.Context, host string) (ips []net.IP, wireResp []byte, err error)

// SetDirectCNResolverForTest injects a deterministic CN DNS resolver for unit testing.
func (e *Engine) SetDirectCNResolverForTest(fn DirectCNDNSFunc) {
	e.mu.Lock()
	e.directCNResolveFn = fn
	e.mu.Unlock()
	if e.smartCache != nil {
		e.smartCache.Clear()
	}
}

var (
	cnProbeTargetMu   sync.Mutex
	cnProbeTargetHook func(network, addr string)
)

func setCNProbeTargetHook(fn func(network, addr string)) {
	cnProbeTargetMu.Lock()
	cnProbeTargetHook = fn
	cnProbeTargetMu.Unlock()
}

func defaultDirectCNProbe(ctx context.Context, host string) ([]net.IP, []byte, error) {
	var idBuf [2]byte
	_, _ = rand.Read(idBuf[:])
	qid := binary.BigEndian.Uint16(idBuf[:])
	query, err := BuildDNSQuery(qid, host, 1)
	if err != nil {
		return nil, nil, err
	}

	baseHosts := []string{"223.5.5.5", "119.29.29.29"}
	servers := make([]string, 0, 4)
	for _, h := range baseHosts {
		if ua, rerr := netbind.ResolveUDPAddr(ctx, h, 53); rerr == nil && ua != nil {
			servers = append(servers, ua.String())
		} else {
			servers = append(servers, net.JoinHostPort(h, "53"))
		}
	}
	if netbind.IsPureIPv6Physical() {
		servers = append(servers, "[2400:3200::1]:53", "[2402:4e00::]:53")
	}
	type probeRes struct {
		ips  []net.IP
		wire []byte
		err  error
	}
	ch := make(chan probeRes, len(servers))

	for _, srv := range servers {
		go func(target string) {
			cnProbeTargetMu.Lock()
			hook := cnProbeTargetHook
			cnProbeTargetMu.Unlock()
			if hook != nil {
				hook("udp", target)
			}
			d := net.Dialer{Timeout: smartDNSProbeTimeout, Control: netbind.Control}
			c, dialErr := d.DialContext(ctx, "udp", target)
			if dialErr != nil {
				ch <- probeRes{err: dialErr}
				return
			}
			defer c.Close()
			if dl, ok := ctx.Deadline(); ok {
				_ = c.SetDeadline(dl)
			} else {
				_ = c.SetDeadline(time.Now().Add(smartDNSProbeTimeout))
			}
			if _, werr := c.Write(query); werr != nil {
				ch <- probeRes{err: werr}
				return
			}
			var buf [1500]byte
			n, rerr := c.Read(buf[:])
			if rerr != nil || n < 12 || buf[0] != idBuf[0] || buf[1] != idBuf[1] {
				ch <- probeRes{err: errors.New("cn dns probe failed")}
				return
			}
			v4, _, _, okParse := ParseDNSResponse(buf[:n])
			if !okParse || len(v4) == 0 {
				ch <- probeRes{err: errors.New("cn dns empty A answer")}
				return
			}
			out := make([]byte, n)
			copy(out, buf[:n])
			ch <- probeRes{ips: v4, wire: out}
		}(srv)
	}

	var lastErr error
	for range servers {
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		case r := <-ch:
			if r.err == nil && len(r.ips) > 0 {
				return r.ips, r.wire, nil
			}
			if r.err != nil {
				lastErr = r.err
			}
		}
	}
	if lastErr == nil {
		lastErr = errors.New("cn dns unresolved")
	}
	return nil, nil, lastErr
}

func (e *Engine) probeUnknownDomainSmart(hostLower string) smartRouteEntry {
	if cached, ok := e.smartCache.Get(hostLower); ok {
		return cached
	}

	// Singleflight dedup per domain so parallel flows share a single 350ms DNS probe.
	e.smartCache.mu.Lock()
	if call, busy := e.smartCache.inflight[hostLower]; busy {
		e.smartCache.mu.Unlock()
		<-call.done
		return call.res
	}
	call := &smartInFlightCall{done: make(chan struct{})}
	e.smartCache.inflight[hostLower] = call
	e.smartCache.mu.Unlock()

	defer func() {
		e.smartCache.mu.Lock()
		delete(e.smartCache.inflight, hostLower)
		e.smartCache.mu.Unlock()
		close(call.done)
	}()

	e.mu.RLock()
	fn := e.directCNResolveFn
	e.mu.RUnlock()
	if fn == nil {
		fn = defaultDirectCNProbe
	}

	ctx, cancel := context.WithTimeout(context.Background(), smartDNSProbeTimeout)
	ips, wireResp, err := fn(ctx, hostLower)
	cancel()

	ent := smartRouteEntry{
		host:   hostLower,
		act:    ActionProxy,
		reason: "proxy:dns-timeout",
	}
	if err == nil && len(ips) > 0 {
		foundPublic := false
		for _, ip := range ips {
			ip4, valid := isValidPublicNonPoisonedIPv4(ip)
			if !valid {
				continue
			}
			foundPublic = true
			if e.router.IsDirectIPv4(ip4) {
				ent.act = ActionDirect
				ent.reason = "direct:cn-dns"
				ent.directIP = ip4.String()
				ent.wireResp = wireResp
				ent.wireAt = time.Now()
				break
			}
		}
		if ent.act != ActionDirect {
			if foundPublic {
				ent.reason = "proxy:geoip-overseas"
			} else {
				ent.reason = "proxy:dns-filtered"
			}
		}
	}

	e.smartCache.Put(ent)
	call.res = ent
	return ent
}

func splitHostPortSafe(target string) (host, port string) {
	if h, p, err := net.SplitHostPort(target); err == nil {
		return strings.Trim(strings.TrimSpace(h), "[]"), p
	}
	return strings.Trim(strings.TrimSpace(target), "[]"), ""
}

// DecideSmartRoute classifies routeTarget under active RouteMode, running a 350ms
// direct CN DNS GeoIP pre-probe ONLY for unknown candidate domains under RouteRule.
// Known proxy rules strictly skip local DNS queries (zero DNS leaks).
func (e *Engine) DecideSmartRoute(dialTarget, routeTarget string) (act RouteAction, resolvedDialTarget, reason string) {
	e.mu.RLock()
	mode := e.config.RouteMode
	e.mu.RUnlock()

	resolvedDialTarget = dialTarget
	act, reason, unknownDomain := e.router.evaluateStatic(mode, routeTarget)

	hostRaw, _ := splitHostPortSafe(routeTarget)
	hostLower := strings.ToLower(strings.TrimSuffix(hostRaw, "."))

	if unknownDomain && hostLower != "" {
		ent := e.probeUnknownDomainSmart(hostLower)
		act = ent.act
		reason = ent.reason
		if act == ActionDirect && ent.directIP != "" {
			dialHost, dialPort := splitHostPortSafe(dialTarget)
			if dialPort != "" && net.ParseIP(dialHost) == nil {
				resolvedDialTarget = net.JoinHostPort(ent.directIP, dialPort)
			} else if dialPort != "" {
				if ip := net.ParseIP(dialHost); ip != nil && isFakeOrVirtualIP(ip) {
					resolvedDialTarget = net.JoinHostPort(ent.directIP, dialPort)
				}
			}
		}
	}

	act, reason = e.router.RecordDecision(act, reason)
	if e.recentRoutes != nil && hostLower != "" {
		e.recentRoutes.Push(routeTarget, hostLower, act, reason)
	}
	return act, resolvedDialTarget, reason
}

// ResolveSmartDNS evaluates a LAN/router DNS query without leaking known overseas domains.
// For unknown domains under Rule mode that resolve within 350ms to a valid Mainland China IP,
// it returns ActionDirect along with the cached CN DNS wire packet (with txID patched).
func (e *Engine) ResolveSmartDNS(mode RouteMode, qname string, txID []byte) (act RouteAction, wireResp []byte, reason string) {
	hostLower := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(qname), "."))
	hostport := net.JoinHostPort(hostLower, "443")

	act, reason, unknownDomain := e.router.evaluateStatic(mode, hostport)
	if unknownDomain && hostLower != "" {
		ent := e.probeUnknownDomainSmart(hostLower)
		act = ent.act
		reason = ent.reason
		if act == ActionDirect && len(ent.wireResp) >= 12 && time.Since(ent.wireAt) <= 30*time.Second {
			wireResp = append([]byte(nil), ent.wireResp...)
			if len(txID) >= 2 {
				wireResp[0], wireResp[1] = txID[0], txID[1]
			}
		}
	}

	act, reason = e.router.RecordDecision(act, reason)
	if e.recentRoutes != nil && hostLower != "" {
		e.recentRoutes.Push(hostLower+":53", hostLower, act, reason)
	}
	return act, wireResp, reason
}

func isFakeOrVirtualIP(ip net.IP) bool {
	ip4 := ip.To4()
	return ip4 != nil && ip4[0] == 198 && (ip4[1] == 18 || ip4[1] == 19)
}

// RecentRoutes returns up to 80 recent routing decisions newest-first.
func (e *Engine) RecentRoutes() []RecentRouteEntry {
	if e.recentRoutes == nil {
		return nil
	}
	return e.recentRoutes.EntriesNewestFirst()
}

// AppendCustomRule inserts ruleLine (e.g. "DOMAIN-SUFFIX,xxx.com,DIRECT") at highest
// precedence (replacing any existing rule for the same target) and clears smart cache.
func (e *Engine) AppendCustomRule(ruleLine string) error {
	ln := strings.TrimSpace(ruleLine)
	if ln == "" {
		return errors.New("empty rule")
	}
	if len(ParseCustomRules([]string{ln})) == 0 {
		return errors.New("invalid rule syntax (expected TYPE,VALUE,DIRECT|PROXY|REJECT)")
	}
	newParts := strings.Split(ln, ",")
	newType := strings.ToUpper(strings.TrimSpace(newParts[0]))
	newVal := strings.ToLower(strings.TrimSpace(newParts[1]))

	e.mu.RLock()
	existing := make([]string, len(e.config.CustomRules))
	copy(existing, e.config.CustomRules)
	e.mu.RUnlock()

	updated := make([]string, 0, len(existing)+1)
	updated = append(updated, ln)
	for _, old := range existing {
		parts := strings.Split(strings.TrimSpace(old), ",")
		if len(parts) >= 2 && strings.EqualFold(strings.TrimSpace(parts[0]), newType) && strings.EqualFold(strings.TrimSpace(parts[1]), newVal) {
			continue
		}
		updated = append(updated, old)
	}
	return e.SetCustomRules(updated)
}
