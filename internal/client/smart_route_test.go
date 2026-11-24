package client

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
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

	// Curated WeChat mini-game, domestic SDKs, and embedded cn_domains.zlib must hit direct without DNS.
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
		"sdk.cocos.com:443",
		"cdn.egret.com:443",
		"res.layaair.com:443",
		"e.tapdb.net:443",
		"log.thinkingdata.cn:443",
		"errlog.umeng.com:443",
		"ulogs.umengcloud.com:443",
		"sdk.getui.com:443",
		"stats.jpush.cn:443",
		"api.leancloud.cn:443",
		"cloud.bmob.cn:443",
		"dn-qbox.qbox.me:443",
		"img.clouddn.com:443",
		"static.qnssl.com:443",
		"www.aixifan.com:443",
		"www.acfun.cn:443",
		"www.aliyun.com:443",
	}
	for _, d := range miniGameDomains {
		if act := r.Decide(RouteRule, d); act != ActionDirect {
			t.Fatalf("expected direct RuleSet match for %s, got %v", d, act)
		}
	}

	// Leak-test sites and domestic DoH endpoints MUST NEVER route direct.
	mustProxy := []string{
		"ping0.cc:443",
		"sub.ipleak.net:443",
		"dnsleaktest.com:443",
		"browserleaks.com:443",
		"bash.ws:443",
		"whoer.net:443",
		"ip-api.com:443",
		"ipinfo.io:443",
		"ip.sb:443",
		"ipify.org:443",
		"ident.me:443",
		"scamalytics.com:443",
		"ipdata.co:443",
		"ipgeolocation.io:443",
		"astrill.com:443",
		"expressvpn.com:443",
		"surfshark.com:443",
		"mullvad.net:443",
		"cloudflareclient.com:443",
		"dns.alidns.com:443",
		"doh.pub:443",
		"sm2.doh.pub:443",
	}
	for _, d := range mustProxy {
		if act := r.Decide(RouteRule, d); act != ActionProxy {
			t.Fatalf("expected ActionProxy for %s, got %v", d, act)
		}
	}
	if rs := r.Stats(); rs.BuiltinDomains < 100000 {
		t.Fatalf("expected >= 100000 embedded BuiltinDomains from rules_bundle.zlib, got %d", rs.BuiltinDomains)
	}
}

func TestSmartRouteUnknownDomainTunnelFirstZeroCNLeak(t *testing.T) {
	SetNoSysProxy(true)
	eng, err := NewEngine("")
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}
	defer eng.Close()

	// 0. When tunnel is offline and no test hook is installed, unknown domains MUST fall back to
	// ActionProxy with 0 CN DNS calls and MUST NOT poison cache once tunnel connects later.
	var cnCallsOffline atomic.Int32
	eng.SetDirectCNResolverForTest(func(ctx context.Context, host string) ([]net.IP, []byte, error) {
		cnCallsOffline.Add(1)
		return nil, nil, context.DeadlineExceeded
	})
	actOff, _, reasonOff := eng.DecideSmartRoute("minigame.cn-thirdparty.example:443", "minigame.cn-thirdparty.example:443")
	if actOff != ActionProxy || reasonOff != "proxy:tunnel-offline" {
		t.Fatalf("expected offline tunnel proxy fallback, got (%v, %q)", actOff, reasonOff)
	}
	if cnCallsOffline.Load() != 0 {
		t.Fatalf("offline tunnel leaked %d CN DNS calls!", cnCallsOffline.Load())
	}

	var tunnelCalls atomic.Int32
	var cnCalls atomic.Int32
	eng.SetTunnelDNSResolverForTest(func(ctx context.Context, host string) ([]net.IP, error) {
		tunnelCalls.Add(1)
		switch host {
		case "minigame.cn-thirdparty.example", "minigame-timeout.cn-thirdparty.example":
			return []net.IP{net.ParseIP("81.68.10.20")}, nil // Tencent Cloud Shanghai
		case "leak-check-9981.unknown-overseas-test.org", "random-uuid.leaktest-example.com":
			return []net.IP{net.ParseIP("104.18.20.30")}, nil // Overseas IP
		case "poisoned.unknown.example":
			return []net.IP{net.ParseIP("31.13.64.5"), net.ParseIP("198.18.0.5"), net.ParseIP("127.0.0.1")}, nil
		default:
			return nil, context.DeadlineExceeded
		}
	})
	eng.SetDirectCNResolverForTest(func(ctx context.Context, host string) ([]net.IP, []byte, error) {
		cnCalls.Add(1)
		switch host {
		case "minigame.cn-thirdparty.example":
			ip := net.ParseIP("43.132.88.9")
			return []net.IP{ip}, buildMockAResponse(0xABCD, host, ip), nil
		default:
			return nil, nil, context.DeadlineExceeded
		}
	})

	// 1. Known overseas builtinProxyRules & leak-test sites MUST NOT trigger tunnel OR CN DNS!
	for _, proxyHost := range []string{
		"www.google.com:443", "api.openai.com:443", "github.com:443", "t.me:443",
		"ping0.cc:443", "a1b2c3.ipleak.net:443", "browserleaks.com:443", "dns.alidns.com:443", "doh.pub:443",
	} {
		act, _, reason := eng.DecideSmartRoute(proxyHost, proxyHost)
		if act != ActionProxy || reason == "" {
			t.Fatalf("expected proxy for %s, got (%v, %q)", proxyHost, act, reason)
		}
	}
	if tunnelCalls.Load() != 0 || cnCalls.Load() != 0 {
		t.Fatalf("known proxy domains triggered pre-probes: tunnel=%d cn=%d", tunnelCalls.Load(), cnCalls.Load())
	}

	// 2. Random unknown overseas domain MUST query tunnel DNS ONLY and invoke directCNResolveFn STRICTLY 0 times!
	for _, unknownHost := range []string{
		"leak-check-9981.unknown-overseas-test.org:443",
		"random-uuid.leaktest-example.com:443",
	} {
		actLeak, _, reasonLeak := eng.DecideSmartRoute(unknownHost, unknownHost)
		if actLeak != ActionProxy || reasonLeak != "proxy:geoip-overseas" {
			t.Fatalf("expected overseas smart proxy for %s, got (%v, %q)", unknownHost, actLeak, reasonLeak)
		}
	}
	if calls := cnCalls.Load(); calls != 0 {
		t.Fatalf("CRITICAL DNS LEAK: directCNResolveFn called %d times for unknown overseas domain (must be 0)!", calls)
	}

	// 3. Timeout/poisoned tunnel DNS results MUST also go ActionProxy with STRICTLY 0 CN DNS calls!
	actTmo, _, _ := eng.DecideSmartRoute("timeout-999.unknown-overseas-test.org:443", "timeout-999.unknown-overseas-test.org:443")
	actPois, _, reasonPois := eng.DecideSmartRoute("poisoned.unknown.example:443", "poisoned.unknown.example:443")
	if actTmo != ActionProxy || actPois != ActionProxy || reasonPois != "proxy:dns-filtered" {
		t.Fatalf("expected proxy for timeout/poisoned, got tmo=%v pois=(%v,%q)", actTmo, actPois, reasonPois)
	}
	if calls := cnCalls.Load(); calls != 0 {
		t.Fatalf("CRITICAL DNS LEAK: directCNResolveFn called %d times on timeout/poisoned (must be 0)!", calls)
	}

	// 4. Unknown CN mini-game domain resolves via tunnel DNS to 81.68.10.20 (Tencent Shanghai),
	// then refreshes nearby CN CDN IP 43.132.88.9 via directCNResolveFn -> ActionDirect.
	act, resolvedDial, reason := eng.DecideSmartRoute("198.18.1.9:443", "minigame.cn-thirdparty.example:443")
	if act != ActionDirect || reason != "direct:cn-dns" || resolvedDial != "43.132.88.9:443" {
		t.Fatalf("expected smart direct with local CDN IP, got (%v, %q, %q)", act, resolvedDial, reason)
	}
	if calls := cnCalls.Load(); calls != 1 {
		t.Fatalf("expected 1 CN CDN refresh probe for confirmed CN domain, got %d", calls)
	}

	// Subsequent query hits cache without triggering extra tunnel or CN probes.
	act2, wire, _ := eng.ResolveSmartDNS(RouteRule, "minigame.cn-thirdparty.example", []byte{0x55, 0x66})
	if act2 != ActionDirect || len(wire) < 12 || wire[0] != 0x55 || wire[1] != 0x66 {
		t.Fatalf("expected cached direct DNS wire response with patched txID, got act=%v len=%d", act2, len(wire))
	}
	if cnCalls.Load() != 1 {
		t.Fatalf("expected cache hit with 0 extra CN DNS probes, got %d", cnCalls.Load())
	}

	// If local CN CDN refresh times out on a confirmed CN domain, keep ActionDirect and dial tunnel's CN IP (81.68.10.20).
	actFallback, dialFallback, _ := eng.DecideSmartRoute("198.18.1.10:443", "minigame-timeout.cn-thirdparty.example:443")
	if actFallback != ActionDirect || dialFallback != "81.68.10.20:443" {
		t.Fatalf("expected fallback to tunnel CN IP 81.68.10.20:443 on CN CDN timeout, got (%v, %q)", actFallback, dialFallback)
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

func TestCompactRuleSetMemoryUnder2MiBAndHotReload(t *testing.T) {
	// 1. Verify HeapInuse delta for decoding the embedded >=100k zero-pointer KSLR bundle stays < 2 MiB.
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	bundle, err := DecodeCompactRuleBundle(embeddedRulesBundleZlib, "bench", 0)
	if err != nil {
		t.Fatalf("DecodeCompactRuleBundle failed: %v", err)
	}
	if bundle.TotalCount() < 100000 {
		t.Fatalf("expected >= 100000 compact entries, got %d", bundle.TotalCount())
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	var deltaHeapInuse int64
	if after.HeapInuse > before.HeapInuse {
		deltaHeapInuse = int64(after.HeapInuse - before.HeapInuse)
	}
	if deltaHeapInuse >= 2<<20 {
		t.Fatalf("compact rule bundle HeapInuse delta too large: %d bytes (>= 2 MiB)", deltaHeapInuse)
	}
	runtime.KeepAlive(bundle)

	// 2. Verify online Rule-Provider hot reload persists to <dataDir>/rules_bundle.zlib and swaps Router immediately.
	customBlob, _, _, _, err := EncodeCompactRuleBundle(
		[]string{"hotreload-proxy.example"},
		[]string{"hotreload-direct.example"},
	)
	if err != nil {
		t.Fatalf("EncodeCompactRuleBundle failed: %v", err)
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(customBlob)
	}))
	defer ts.Close()

	SetNoSysProxy(true)
	cfgDir := t.TempDir()
	eng, err := NewEngine(filepath.Join(cfgDir, "client.json"))
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}
	defer eng.Close()

	st, err := eng.UpdateRuleBundle(context.Background(), ts.URL+"/rules_bundle.zlib")
	if err != nil {
		t.Fatalf("UpdateRuleBundle failed: %v", err)
	}
	if st.RulesSource != "local" {
		t.Fatalf("expected RulesSource=local after hot reload, got %q", st.RulesSource)
	}
	if _, statErr := os.Stat(filepath.Join(cfgDir, ruleBundleFileName)); statErr != nil {
		t.Fatalf("expected persisted rules_bundle.zlib on disk: %v", statErr)
	}
	if act := eng.router.Decide(RouteRule, "cdn.hotreload-direct.example:443"); act != ActionDirect {
		t.Fatalf("expected hot-reloaded ActionDirect, got %v", act)
	}
	if act := eng.router.Decide(RouteRule, "sub.hotreload-proxy.example:443"); act != ActionProxy {
		t.Fatalf("expected hot-reloaded ActionProxy, got %v", act)
	}

	// Reloading NewEngine from the same cfgDir must automatically load local rules_bundle.zlib.
	eng2, err := NewEngine(filepath.Join(cfgDir, "client.json"))
	if err != nil {
		t.Fatalf("NewEngine reload failed: %v", err)
	}
	defer eng2.Close()
	if act := eng2.router.Decide(RouteRule, "cdn.hotreload-direct.example:443"); act != ActionDirect {
		t.Fatalf("expected persisted ActionDirect after restart, got %v", act)
	}
}

func TestSelectProxyDialTargetPrefersSniffedDomain(t *testing.T) {
	if got := selectProxyDialTarget("104.244.42.197:443", "www.google.com:443"); got != "www.google.com:443" {
		t.Fatalf("expected sniffed domain over poisoned IP, got %q", got)
	}
	if got := selectProxyDialTarget("[2001:db8::1]:443", "www.google.com:443"); got != "www.google.com:443" {
		t.Fatalf("expected sniffed domain over IPv6 target, got %q", got)
	}
	if got := selectProxyDialTarget("1.1.1.1:443", ""); got != "1.1.1.1:443" {
		t.Fatalf("expected raw IP fallback when no domain sniffed, got %q", got)
	}
	if got := selectProxyDialTarget("1.1.1.1:443", "1.1.1.1:443"); got != "1.1.1.1:443" {
		t.Fatalf("expected raw IP preserved when routeTarget is IP, got %q", got)
	}
}

func BenchmarkCompactRuleSetMemory(b *testing.B) {
	b.ReportAllocs()
	var totalDelta uint64
	for i := 0; i < b.N; i++ {
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		bundle, err := DecodeCompactRuleBundle(embeddedRulesBundleZlib, "bench", 0)
		if err != nil {
			b.Fatal(err)
		}
		if bundle.TotalCount() < 100000 {
			b.Fatalf("expected >= 100000 rules, got %d", bundle.TotalCount())
		}
		runtime.GC()
		runtime.ReadMemStats(&after)
		if after.HeapInuse > before.HeapInuse {
			totalDelta += after.HeapInuse - before.HeapInuse
		}
		runtime.KeepAlive(bundle)
	}
	if b.N > 0 {
		avgDelta := totalDelta / uint64(b.N)
		b.ReportMetric(float64(avgDelta)/(1024*1024), "HeapInuseMiB")
		if avgDelta >= 2<<20 {
			b.Fatalf("HeapInuse delta %.2f MiB exceeds 2 MiB budget", float64(avgDelta)/(1024*1024))
		}
	}
}
