package client

import (
	"encoding/binary"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// RouteMode controls client split-tunneling behavior.
type RouteMode string

const (
	RouteRule   RouteMode = "rule"   // RuleSet + GeoIP-CN direct + auto system proxy
	RouteGlobal RouteMode = "global" // All traffic (except loopback) via GhostFrame + auto system proxy
	RouteCore   RouteMode = "core"   // Port-only mode (10808/10809 via tunnel, never touches system proxy)
	RouteDirect RouteMode = "direct" // Legacy config alias automatically mapped to RouteCore
)

// RouteAction is the per-request forwarding decision.
type RouteAction int

const (
	ActionProxy RouteAction = iota
	ActionDirect
	ActionReject
)

func (a RouteAction) String() string {
	switch a {
	case ActionDirect:
		return "direct"
	case ActionReject:
		return "reject"
	default:
		return "proxy"
	}
}

type ipRange struct {
	lo uint32
	hi uint32
}

// Router classifies destinations without triggering local DNS lookups for domains.
type Router struct {
	cnRanges        []ipRange
	cnIPv6          []ipv6Range
	lanSuffixMap    map[string]string
	proxySuffixMap  map[string]string
	directSuffixMap map[string]string
	compact         atomic.Pointer[CompactRuleBundle]

	customMu    sync.RWMutex
	customRules []CustomRule

	directHits atomic.Uint64
	proxyHits  atomic.Uint64
	rejectHits atomic.Uint64
}

var privateIPv4CIDRs = []string{
	"0.0.0.0/8",
	"10.0.0.0/8",
	"100.64.0.0/10",
	"127.0.0.0/8",
	"169.254.0.0/16",
	"172.16.0.0/12",
	"192.168.0.0/16",
}

// NewRouter constructs a Router preloaded with APNIC CN CIDRs, curated rules, and the embedded compact KSLR index.
func NewRouter() *Router {
	return NewRouterWithDataDir("")
}

// NewRouterWithDataDir constructs a Router preferring <dataDir>/rules_bundle.zlib when valid on disk.
func NewRouterWithDataDir(dataDir string) *Router {
	raw := make([]ipRange, 0, len(privateIPv4CIDRs)+6000)
	for _, s := range privateIPv4CIDRs {
		_, ipNet, err := net.ParseCIDR(s)
		if err != nil {
			continue
		}
		ip4 := ipNet.IP.To4()
		if ip4 == nil {
			continue
		}
		lo := binary.BigEndian.Uint32(ip4)
		mask := binary.BigEndian.Uint32(ipNet.Mask)
		hi := lo | ^mask
		raw = append(raw, ipRange{lo: lo, hi: hi})
	}
	raw = appendBuiltinCNRanges(raw)
	sort.Slice(raw, func(i, j int) bool {
		if raw[i].lo == raw[j].lo {
			return raw[i].hi < raw[j].hi
		}
		return raw[i].lo < raw[j].lo
	})
	merged := make([]ipRange, 0, len(raw))
	for _, r := range raw {
		n := len(merged)
		if n > 0 && uint64(merged[n-1].hi)+1 >= uint64(r.lo) {
			if r.hi > merged[n-1].hi {
				merged[n-1].hi = r.hi
			}
			continue
		}
		merged = append(merged, r)
	}

	lanMap := make(map[string]string, len(builtinLanSuffixes))
	for _, sfx := range builtinLanSuffixes {
		lanMap[strings.ToLower(sfx)] = "lan"
	}
	proxyMap := make(map[string]string, len(builtinProxyRules))
	for _, seed := range builtinProxyRules {
		proxyMap[strings.ToLower(seed.domain)] = seed.tag
	}
	directMap := make(map[string]string, len(builtinDirectRules))
	for _, seed := range builtinDirectRules {
		directMap[strings.ToLower(seed.domain)] = seed.tag
	}

	r := &Router{
		cnRanges:        merged,
		cnIPv6:          appendBuiltinCNIPv6Ranges(nil),
		lanSuffixMap:    lanMap,
		proxySuffixMap:  proxyMap,
		directSuffixMap: directMap,
	}
	if b := LoadCompactRuleBundleFromDir(dataDir); b != nil {
		r.compact.Store(b)
	}
	return r
}

// SetCompactBundle atomically swaps the zero-pointer 64-bit hash rule index at runtime.
func (r *Router) SetCompactBundle(b *CompactRuleBundle) {
	if b != nil {
		r.compact.Store(b)
	}
}

// SetCustomRules atomically replaces user-supplied custom routing rules.
func (r *Router) SetCustomRules(rules []CustomRule) {
	cp := make([]CustomRule, len(rules))
	copy(cp, rules)
	r.customMu.Lock()
	r.customRules = cp
	r.customMu.Unlock()
}

// Stats returns embedded rule capacities and cumulative decision hit counters.
func (r *Router) Stats() RuleStats {
	r.customMu.RLock()
	customN := len(r.customRules)
	r.customMu.RUnlock()
	b := r.compact.Load()
	proxyN := len(r.proxySuffixMap)
	directN := len(r.directSuffixMap)
	src := "embedded"
	var upd int64
	if b != nil {
		proxyN += len(b.ProxyHashes)
		directN += len(b.DirectHashes)
		if b.Source != "" {
			src = b.Source
		}
		upd = b.UpdatedAt
	}
	return RuleStats{
		Version:        BuiltinRuleSetVersion,
		BuiltinDomains: proxyN + directN,
		BuiltinCIDRs:   len(r.cnRanges) + len(r.cnIPv6),
		CustomRules:    customN,
		DirectHits:     r.directHits.Load(),
		ProxyHits:      r.proxyHits.Load(),
		RejectHits:     r.rejectHits.Load(),
		ProxyDomains:   proxyN,
		DirectDomains:  directN,
		RulesSource:    src,
		RulesUpdatedAt: upd,
	}
}

func (r *Router) isDirectIPv4(ip4 net.IP) bool {
	v := binary.BigEndian.Uint32(ip4)
	idx := sort.Search(len(r.cnRanges), func(i int) bool {
		return r.cnRanges[i].hi >= v
	})
	return idx < len(r.cnRanges) && r.cnRanges[idx].lo <= v
}

// IsDirectIPv4 reports whether ip4 belongs to LAN or Mainland China IPv4 ranges.
func (r *Router) IsDirectIPv4(ip4 net.IP) bool {
	ip4 = ip4.To4()
	if ip4 == nil {
		return false
	}
	return r.isDirectIPv4(ip4)
}

func (r *Router) isDirectIPv6(ip net.IP) bool {
	ip16 := ip.To16()
	if ip16 == nil || ip.To4() != nil {
		return false
	}
	for _, n := range r.cnIPv6 {
		if n.contains(ip16) {
			return true
		}
	}
	return false
}

func lookupSuffixMap(hostLower string, m map[string]string) (string, bool) {
	if hostLower == "" {
		return "", false
	}
	if tag, ok := m[hostLower]; ok {
		return tag, true
	}
	for i := 0; i < len(hostLower); i++ {
		if hostLower[i] == '.' && i+1 < len(hostLower) {
			if tag, ok := m[hostLower[i+1:]]; ok {
				return tag, true
			}
		}
	}
	return "", false
}

func isLANIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	if ip4 := ip.To4(); ip4 != nil {
		// 0.0.0.0/8 and RFC 6598 CGNAT 100.64.0.0/10
		if ip4[0] == 0 || (ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127) {
			return true
		}
	}
	return false
}

func (r *Router) matchCustomRule(hostLower string, ip net.IP) (CustomRule, bool) {
	r.customMu.RLock()
	rules := r.customRules
	r.customMu.RUnlock()

	for _, rule := range rules {
		switch rule.Type {
		case "DOMAIN":
			if hostLower == rule.Value {
				return rule, true
			}
		case "DOMAIN-SUFFIX":
			v := rule.Value
			if hostLower == v || (len(hostLower) > len(v) && strings.HasSuffix(hostLower, v) && hostLower[len(hostLower)-len(v)-1] == '.') {
				return rule, true
			}
		case "DOMAIN-KEYWORD":
			if hostLower != "" && strings.Contains(hostLower, rule.Value) {
				return rule, true
			}
		case "IP-CIDR":
			if ip != nil && rule.CIDR != nil && rule.CIDR.Contains(ip) {
				return rule, true
			}
		}
	}
	return CustomRule{}, false
}

// RecordDecision increments rule hit counters and returns (act, reason).
func (r *Router) RecordDecision(act RouteAction, reason string) (RouteAction, string) {
	switch act {
	case ActionDirect:
		r.directHits.Add(1)
	case ActionReject:
		r.rejectHits.Add(1)
	default:
		r.proxyHits.Add(1)
	}
	return act, reason
}

// Decide evaluates destination hostport under mode WITHOUT calling DNS lookup on domains.
func (r *Router) Decide(mode RouteMode, hostport string) RouteAction {
	act, _ := r.DecideWithReason(mode, hostport)
	return act
}

// DecideWithReason evaluates destination hostport under mode and returns (action, ruleTag)
// with zero heap allocations on suffix lookups and zero local DNS leaks.
func (r *Router) DecideWithReason(mode RouteMode, hostport string) (RouteAction, string) {
	act, reason, _ := r.evaluateStatic(mode, hostport)
	return r.RecordDecision(act, reason)
}

// evaluateStatic checks all built-in and custom rules without mutating hit counters.
// unknownDomain is true only when RouteRule receives a non-IP hostname that matches no built-in or custom rule.
func (r *Router) evaluateStatic(mode RouteMode, hostport string) (act RouteAction, reason string, unknownDomain bool) {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		host = hostport
	}
	host = strings.TrimSuffix(strings.TrimSpace(strings.Trim(host, "[]")), ".")
	hostLower := strings.ToLower(host)

	// Internal management domain ALWAYS goes through the GhostFrame tunnel.
	if hostLower == "gft.internal.panel" {
		return ActionProxy, "internal:panel", false
	}

	switch mode {
	case RouteCore, RouteDirect, RouteGlobal:
		// Keep loopback direct so local GUI/apps never loop into VPS; everything else uses tunnel.
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			return ActionDirect, "lan", false
		}
		if hostLower == "localhost" {
			return ActionDirect, "lan", false
		}
		return ActionProxy, "mode:global", false

	default: // RouteRule
		ip := net.ParseIP(host)
		if rule, ok := r.matchCustomRule(hostLower, ip); ok {
			return rule.Action, rule.Tag, false
		}

		if ip != nil {
			if isLANIP(ip) {
				return ActionDirect, "lan", false
			}
			if ip4 := ip.To4(); ip4 != nil {
				if r.isDirectIPv4(ip4) {
					return ActionDirect, "geoip:cn", false
				}
				return ActionProxy, "geoip:overseas", false
			}
			if r.isDirectIPv6(ip) {
				return ActionDirect, "geoip:cn", false
			}
			return ActionProxy, "geoip:overseas", false
		}

		if tag, ok := lookupSuffixMap(hostLower, r.lanSuffixMap); ok {
			return ActionDirect, tag, false
		}
		// Evaluate curated Proxy & Direct overrides before 100K compact hash tables.
		if tag, ok := lookupSuffixMap(hostLower, r.proxySuffixMap); ok {
			return ActionProxy, tag, false
		}
		if tag, ok := lookupSuffixMap(hostLower, r.directSuffixMap); ok {
			return ActionDirect, tag, false
		}
		if b := r.compact.Load(); b != nil {
			if b.ContainsProxySuffix(hostLower) {
				return ActionProxy, "proxy:ruleset", false
			}
			if strings.HasSuffix(hostLower, ".cn") {
				return ActionDirect, "direct:cn", false
			}
			if b.ContainsDirectSuffix(hostLower) {
				return ActionDirect, "direct:cn-ruleset", false
			}
		} else if strings.HasSuffix(hostLower, ".cn") {
			return ActionDirect, "direct:cn", false
		}
		// Unknown hostname: caller runs Tunnel-First GeoIP pre-probe or falls back directly to proxy.
		return ActionProxy, "final:proxy", true
	}
}
