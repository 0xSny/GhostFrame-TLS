package client

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
)

func buildMockAResponse(qid uint16, host string, ips ...net.IP) []byte {
	q, err := BuildDNSQuery(qid, host, 1)
	if err != nil {
		return nil
	}
	resp := make([]byte, len(q), len(q)+16*len(ips))
	copy(resp, q)
	binary.BigEndian.PutUint16(resp[2:4], 0x8180)
	binary.BigEndian.PutUint16(resp[4:6], 1)
	binary.BigEndian.PutUint16(resp[6:8], uint16(len(ips)))
	for _, ip := range ips {
		ip4 := ip.To4()
		if ip4 == nil {
			continue
		}
		var ans [16]byte
		ans[0] = 0xC0
		ans[1] = 0x0C
		binary.BigEndian.PutUint16(ans[2:4], 1)
		binary.BigEndian.PutUint16(ans[4:6], 1)
		binary.BigEndian.PutUint32(ans[6:10], 120)
		binary.BigEndian.PutUint16(ans[10:12], 4)
		copy(ans[12:16], ip4)
		resp = append(resp, ans[:]...)
	}
	return resp
}

func TestCompleteAPNICAndDomesticCloudGeoIP(t *testing.T) {
	r := NewRouter()

	directIPs := []string{
		"81.68.100.1:443",  // Tencent Cloud
		"82.156.10.1:443",  // Tencent Cloud
		"43.132.1.1:443",   // Tencent Cloud / WeChat MiniGame
		"159.75.10.1:443",  // Tencent Cloud
		"175.24.10.1:443",  // Tencent Cloud
		"129.204.10.1:443", // Tencent Cloud
		"8.130.10.1:443",   // Alibaba Cloud
		"47.100.10.1:443",  // Alibaba Cloud
		"114.114.114.114:53",
		"[2408:8207:1::1]:443",
		"[2409:8a00::1]:443",
		"[240e:1f:1::1]:443",
		"[2001:da8::1]:443",
	}
	for _, hp := range directIPs {
		if act, reason := r.DecideWithReason(RouteRule, hp); act != ActionDirect || reason != "geoip:cn" {
			t.Fatalf("expected geoip:cn DIRECT for %s, got (%v, %q)", hp, act, reason)
		}
	}

	overseasIPs := []string{
		"1.1.1.1:443",
		"8.8.8.8:53",
		"[2606:4700:4700::1111]:443",
	}
	for _, hp := range overseasIPs {
		if act, reason := r.DecideWithReason(RouteRule, hp); act != ActionProxy || reason != "geoip:overseas" {
			t.Fatalf("expected geoip:overseas PROXY for %s, got (%v, %q)", hp, act, reason)
		}
	}

	// Curated WeChat mini-game and domestic cloud RuleSet domains must hit direct without DNS.
	miniGameDomains := []string{
		"servicewechat.com:443",
		"sub.weixinbridge.com:443",
		"wx.qlogo.cn:443",
		"cdn.qcloudcdn.com:443",
		"img.hortorgames.com:443",
		"login.4399.com:443",
		"res.tuyoo.com:443",
		"oss.myhuaweicloud.com:443",
		"cdn.bytecdntp.com:443",
		"static.tapimg.com:443",
	}
	for _, d := range miniGameDomains {
		if act := r.Decide(RouteRule, d); act != ActionDirect {
			t.Fatalf("expected direct RuleSet match for %s, got %v", d, act)
		}
	}
}

func TestSmartRouteUnknownDomainCNDNSPreProbeZeroProxyLeak(t *testing.T) {
	SetNoSysProxy(true)
	eng, err := NewEngine("")
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}
	defer eng.Close()

	var dnsCalls atomic.Int32
	eng.SetDirectCNResolverForTest(func(ctx context.Context, host string) ([]net.IP, []byte, error) {
		dnsCalls.Add(1)
		switch host {
		case "minigame.cn-thirdparty.example":
			ip := net.ParseIP("43.132.88.9")
			return []net.IP{ip}, buildMockAResponse(0xABCD, host, ip), nil
		case "api.overseas-unknown.example":
			ip := net.ParseIP("104.18.20.30")
			return []net.IP{ip}, buildMockAResponse(0xABCE, host, ip), nil
		case "poisoned.unknown.example":
			return []net.IP{net.ParseIP("31.13.64.5"), net.ParseIP("198.18.0.5"), net.ParseIP("127.0.0.1")}, nil, nil
		default:
			return nil, nil, context.DeadlineExceeded
		}
	})

	// 1. Known overseas builtinProxyRules MUST NOT trigger local CN DNS!
	for _, proxyHost := range []string{"www.google.com:443", "api.openai.com:443", "github.com:443", "t.me:443"} {
		act, _, reason := eng.DecideSmartRoute(proxyHost, proxyHost)
		if act != ActionProxy || reason == "" {
			t.Fatalf("expected proxy for %s, got (%v, %q)", proxyHost, act, reason)
		}
	}
	if calls := dnsCalls.Load(); calls != 0 {
		t.Fatalf("known proxy domains leaked %d local DNS queries!", calls)
	}

	// 2. Unknown CN mini-game domain resolves within 350ms to Tencent 43.132.88.9 -> DIRECT + resolved IP.
	act, resolvedDial, reason := eng.DecideSmartRoute("198.18.1.9:443", "minigame.cn-thirdparty.example:443")
	if act != ActionDirect || reason != "direct:cn-dns" || resolvedDial != "43.132.88.9:443" {
		t.Fatalf("expected smart direct for CN unknown domain, got (%v, %q, %q)", act, resolvedDial, reason)
	}
	if calls := dnsCalls.Load(); calls != 1 {
		t.Fatalf("expected 1 CN DNS probe, got %d", calls)
	}

	// Subsequent query must hit 10m LRU cache without triggering another DNS probe.
	act2, wire, _ := eng.ResolveSmartDNS(RouteRule, "minigame.cn-thirdparty.example", []byte{0x55, 0x66})
	if act2 != ActionDirect || len(wire) < 12 || wire[0] != 0x55 || wire[1] != 0x66 {
		t.Fatalf("expected cached direct DNS wire response with patched txID, got act=%v len=%d", act2, len(wire))
	}
	if calls := dnsCalls.Load(); calls != 1 {
		t.Fatalf("expected cache hit with 0 extra DNS probes, got %d", calls)
	}

	// 3. Unknown overseas domain resolves to overseas IP -> ActionProxy.
	actOver, _, reasonOver := eng.DecideSmartRoute("api.overseas-unknown.example:443", "api.overseas-unknown.example:443")
	if actOver != ActionProxy || reasonOver != "proxy:geoip-overseas" {
		t.Fatalf("expected overseas smart proxy, got (%v, %q)", actOver, reasonOver)
	}

	// 4. Poisoned/Fake-IP/Loopback answers must never qualify as CN direct.
	actPois, _, reasonPois := eng.DecideSmartRoute("poisoned.unknown.example:443", "poisoned.unknown.example:443")
	if actPois != ActionProxy || reasonPois != "proxy:dns-filtered" {
		t.Fatalf("expected filtered proxy for poisoned DNS, got (%v, %q)", actPois, reasonPois)
	}

	// 5. AppendCustomRule overrides smart decision and clears cache immediately.
	if err := eng.AppendCustomRule("DOMAIN-SUFFIX,minigame.cn-thirdparty.example,PROXY"); err != nil {
		t.Fatalf("AppendCustomRule failed: %v", err)
	}
	actOverride, _, reasonOverride := eng.DecideSmartRoute("minigame.cn-thirdparty.example:443", "minigame.cn-thirdparty.example:443")
	if actOverride != ActionProxy || reasonOverride != "custom:domain-suffix" {
		t.Fatalf("expected custom rule override PROXY, got (%v, %q)", actOverride, reasonOverride)
	}

	// 6. Verify 80-entry bounded RecentRoutes inspector ring.
	for i := 0; i < 95; i++ {
		eng.DecideSmartRoute("www.google.com:443", fmt.Sprintf("h%d.example.cn:443", i))
	}
	recent := eng.RecentRoutes()
	if len(recent) != defaultRecentRouteCap {
		t.Fatalf("expected recent_routes capped at %d, got %d", defaultRecentRouteCap, len(recent))
	}
}
