package client

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ghostframe/internal/gft"
)

func buildTestDNSAnswer(id uint16, ttlSec uint32, ip4 net.IP) []byte {
	q, _ := BuildDNSQuery(id, "example.com", 1)
	resp := make([]byte, len(q))
	copy(resp, q)
	binary.BigEndian.PutUint16(resp[2:4], 0x8180) // QR=1, NOERROR
	binary.BigEndian.PutUint16(resp[6:8], 1)      // ANCOUNT=1
	resp = append(resp, 0xC0, 0x0C)               // name pointer
	resp = binary.BigEndian.AppendUint16(resp, 1) // TYPE A
	resp = binary.BigEndian.AppendUint16(resp, 1) // CLASS IN
	resp = binary.BigEndian.AppendUint32(resp, ttlSec)
	resp = binary.BigEndian.AppendUint16(resp, 4)
	resp = append(resp, ip4.To4()...)
	return resp
}

func TestRouterZeroDNSLeak(t *testing.T) {
	r := NewRouter()
	cases := []struct {
		hostport string
		want     RouteAction
	}{
		{"www.baidu.com:443", ActionDirect},
		{"v.qq.com:443", ActionDirect},
		{"foo.com.cn:80", ActionDirect},
		{"www.google.com:443", ActionProxy},
		{"api.openai.com:443", ActionProxy},
		{"nonexistent-domain-never-resolve.test:443", ActionProxy},
		{"114.114.114.114:53", ActionDirect},
		{"1.1.1.1:53", ActionProxy},
		{"127.0.0.1:8080", ActionDirect},
	}
	for _, tc := range cases {
		if got := r.Decide(RouteRule, tc.hostport); got != tc.want {
			t.Fatalf("Decide(Rule, %q) = %v, want %v", tc.hostport, got, tc.want)
		}
	}
}

func TestTunnelDNSResolverCacheAndTTL(t *testing.T) {
	res := NewTunnelDNSResolver()
	pktLowTTL := buildTestDNSAnswer(42, 5, net.IPv4(93, 184, 216, 34))
	v4, v6, minTTL, ok := ParseDNSResponse(pktLowTTL)
	if !ok || len(v4) != 1 || len(v6) != 0 || minTTL != tunnelDNSMinTTL {
		t.Fatalf("unexpected low-TTL DNS parse: ok=%v v4=%v ttl=%v", ok, v4, minTTL)
	}
	pktHighTTL := buildTestDNSAnswer(43, 86400, net.IPv4(1, 1, 1, 1))
	_, _, hiTTL, ok := ParseDNSResponse(pktHighTTL)
	if !ok || hiTTL != tunnelDNSMaxTTL {
		t.Fatalf("expected clamped max TTL 600s, got %v", hiTTL)
	}

	// Verify 4096-entry LRU eviction capacity enforcement
	for i := 0; i < tunnelDNSCacheCap+200; i++ {
		res.storeCached(fmt.Sprintf("host-%d.example", i), []net.IP{net.IPv4(8, 8, 8, 8)}, nil, 120*time.Second)
	}
	if res.Len() != tunnelDNSCacheCap {
		t.Fatalf("expected LRU cache len capped at %d, got %d", tunnelDNSCacheCap, res.Len())
	}
	if _, _, found := res.LookupCached("host-0.example"); found {
		t.Fatal("expected evicted oldest host-0.example not found")
	}
	if _, _, found := res.LookupCached("host-4295.example"); !found {
		t.Fatal("expected recent entry present in LRU cache")
	}
}

func TestLoopbackProxySelfHeal(t *testing.T) {
	SetNoSysProxy(true)
	backup := filepath.Join(t.TempDir(), "sysproxy_backup.json")

	// 1. Dirty loopback state WITHOUT backup (simulates crash/power loss) MUST self-heal to disabled
	applyMockSystemProxySnapshot(ProxySnapshot{Enabled: true, Server: "127.0.0.1:10809"})
	if !IsLocalLoopbackProxy("127.0.0.1:10809") || !IsLocalLoopbackProxy("http=localhost:10809;https=localhost:10809") {
		t.Fatal("IsLocalLoopbackProxy failed to match loopback proxies")
	}
	if IsLocalLoopbackProxy("10.0.0.2:8080") {
		t.Fatal("non-loopback proxy falsely classified as loopback")
	}

	recovered, err := RecoverSystemProxyIfDirtyFor(backup, "127.0.0.1:10809")
	if err != nil || !recovered {
		t.Fatalf("expected startup self-heal of orphaned loopback proxy, recovered=%v err=%v", recovered, err)
	}
	if snap := queryMockSystemProxy(); snap.Enabled {
		t.Fatalf("expected orphaned loopback proxy disabled after self-heal, got %+v", snap)
	}

	// 2. EnableSystemProxyWithBackup MUST refuse to poison sysproxy_backup.json with stale loopback proxy
	applyMockSystemProxySnapshot(ProxySnapshot{Enabled: true, Server: "127.0.0.1:10809"})
	if err := EnableSystemProxyWithBackup("127.0.0.1:10809", backup); err != nil {
		t.Fatal(err)
	}
	if _, serr := os.Stat(backup); serr != nil {
		t.Fatal("expected backup file written")
	}
	if err := DisableAndRestoreSystemProxy(backup); err != nil {
		t.Fatal(err)
	}
	if snap := queryMockSystemProxy(); snap.Enabled {
		t.Fatalf("dirty loopback proxy leaked into restore snapshot: %+v", snap)
	}
}

func TestLogRingBufferAndMaskSensitiveText(t *testing.T) {
	ring := NewLogRingBuffer(1000)
	for i := 0; i < 1500; i++ {
		ring.Push(LogEntry{Time: "00:00:00", Message: fmt.Sprintf("msg-%d", i)})
	}
	entries := ring.Entries()
	if len(entries) != 1000 {
		t.Fatalf("expected capped 1000 ring entries, got %d", len(entries))
	}
	if entries[0].Message != "msg-500" || entries[999].Message != "msg-1499" {
		t.Fatalf("unexpected ring window bounds: first=%q last=%q", entries[0].Message, entries[999].Message)
	}

	raw := `Connecting 38.105.30.170:443 psk="SUPER_SECRET_PSK_123456" uri=gft3://eyJoIjoiMS4yLjMuNCJ9#test local=127.0.0.1:10809 host=secret.node.example`
	masked := MaskSensitiveText(raw, "secret.node.example")
	for _, leak := range []string{"38.105.30.170", "SUPER_SECRET_PSK_123456", "eyJoIjoiMS4yLjMuNCJ9", "secret.node.example"} {
		if strings.Contains(masked, leak) {
			t.Fatalf("sensitive string %q leaked into diagnostic mask: %s", leak, masked)
		}
	}
	if !strings.Contains(masked, "127.0.0.1") {
		t.Fatalf("local loopback lost unnecessarily: %s", masked)
	}
}

func TestSOCKS5AndHTTPProxyRuleRawIPSNISniff(t *testing.T) {
	SetNoSysProxy(true)
	eng, err := NewEngine("")
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()

	// Verify ShouldSniffSNI applies ONLY to Rule mode + public IP + TLS ports
	if err := eng.SetRouteMode(RouteRule); err != nil {
		t.Fatal(err)
	}
	if !eng.ShouldSniffSNI("104.244.42.1:443") || !eng.ShouldSniffSNI("172.217.160.14:8443") {
		t.Fatal("expected raw public IP on TLS port in Rule mode to enable SNI sniffing")
	}
	if eng.ShouldSniffSNI("127.0.0.1:443") || eng.ShouldSniffSNI("192.168.1.1:443") || eng.ShouldSniffSNI("104.244.42.1:80") || eng.ShouldSniffSNI("www.google.com:443") {
		t.Fatal("unexpected SNI sniff trigger on private IP, non-TLS port, or domain name")
	}

	// Build a minimal TLS ClientHello with SNI=www.baidu.com -> RouteRule must classify Direct!
	sniBytes := []byte("www.baidu.com")
	sniEntryLen := 1 + 2 + len(sniBytes)
	extLen := 2 + sniEntryLen
	var ext []byte
	ext = binary.BigEndian.AppendUint16(ext, 0x0000)
	ext = binary.BigEndian.AppendUint16(ext, uint16(extLen))
	ext = binary.BigEndian.AppendUint16(ext, uint16(sniEntryLen))
	ext = append(ext, 0x00)
	ext = binary.BigEndian.AppendUint16(ext, uint16(len(sniBytes)))
	ext = append(ext, sniBytes...)
	var body []byte
	body = append(body, 0x03, 0x03)
	body = append(body, make([]byte, 32)...)
	body = append(body, 0x00, 0x00, 0x02, 0x13, 0x01, 0x01, 0x00)
	body = binary.BigEndian.AppendUint16(body, uint16(len(ext)))
	body = append(body, ext...)
	hs := append([]byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	rec := append([]byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}, hs...)

	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	go func() {
		_, _ = c1.Write(rec)
		_, _ = c1.Write([]byte("TRAIL"))
		_ = c1.Close()
	}()
	sni, rc := gft.SniffTLSSNI(c2, 80*time.Millisecond)
	if sni != "www.baidu.com" {
		t.Fatalf("expected www.baidu.com, got %q", sni)
	}
	if act := eng.RouteDecision(net.JoinHostPort(sni, "443")); act != ActionDirect {
		t.Fatalf("expected RouteRule to classify sniffed CN SNI as ActionDirect, got %v", act)
	}
	got, _ := io.ReadAll(rc)
	if !bytes.Equal(got, append(rec, []byte("TRAIL")...)) {
		t.Fatalf("expected lossless rewind (%dB), got %dB", len(rec)+5, len(got))
	}
}

func TestRuleSetCategoriesAndCustomOverride(t *testing.T) {
	r := NewRouter()

	cases := []struct {
		target string
		want   RouteAction
		prefix string
	}{
		{"chatgpt.com:443", ActionProxy, "proxy:ai"},
		{"gemini.google.com:443", ActionProxy, "proxy:ai"},
		{"www.youtube.com:443", ActionProxy, "proxy:google"},
		{"api.github.com:443", ActionProxy, "proxy:dev"},
		{"t.me:443", ActionProxy, "proxy:social"},
		{"www.netflix.com:443", ActionProxy, "proxy:streaming"},
		{"www.xiaohongshu.com:443", ActionDirect, "direct:cn"},
		{"chat.deepseek.com:443", ActionDirect, "direct:cn-ai"},
		{"open.feishu.cn:443", ActionDirect, "direct:cn"},
		{"p01-caldav.icloud.com.cn:443", ActionDirect, "direct:apple-cn"},
		{"dl.delivery.mp.microsoft.com:443", ActionDirect, "direct:ms-cn"},
		{"cache1.steamcontent.com:443", ActionDirect, "direct:steam-cn"},
		{"nas.local:5000", ActionDirect, "lan"},
		{"100.64.10.2:8080", ActionDirect, "lan"},
		{"223.5.5.5:53", ActionDirect, "geoip:cn"},
		{"8.8.8.8:53", ActionProxy, "geoip:overseas"},
		{"unknown-overseas-site.io:443", ActionProxy, "final:proxy"},
	}

	for _, tc := range cases {
		act, reason := r.DecideWithReason(RouteRule, tc.target)
		if act != tc.want || !strings.HasPrefix(reason, tc.prefix) {
			t.Fatalf("DecideWithReason(%q) = (%v, %q), want (%v, prefix %q)",
				tc.target, act, reason, tc.want, tc.prefix)
		}
	}

	custom := ParseCustomRules([]string{
		"# custom overrides",
		"DOMAIN,chatgpt.com,DIRECT",
		"DOMAIN-SUFFIX,baidu.com,PROXY",
		"DOMAIN-KEYWORD,tracker-ad,REJECT",
		"IP-CIDR,203.0.113.0/24,REJECT,no-resolve",
	})
	if len(custom) != 4 {
		t.Fatalf("expected 4 custom rules, got %d", len(custom))
	}
	r.SetCustomRules(custom)

	if act, reason := r.DecideWithReason(RouteRule, "chatgpt.com:443"); act != ActionDirect || reason != "custom:domain" {
		t.Fatalf("custom DOMAIN override failed: got (%v, %q)", act, reason)
	}
	if act, reason := r.DecideWithReason(RouteRule, "pan.baidu.com:443"); act != ActionProxy || reason != "custom:domain-suffix" {
		t.Fatalf("custom DOMAIN-SUFFIX override failed: got (%v, %q)", act, reason)
	}
	if act, reason := r.DecideWithReason(RouteRule, "eu.tracker-ad.net:443"); act != ActionReject || reason != "custom:domain-keyword" {
		t.Fatalf("custom DOMAIN-KEYWORD REJECT failed: got (%v, %q)", act, reason)
	}
	if act, reason := r.DecideWithReason(RouteRule, "203.0.113.42:443"); act != ActionReject || reason != "custom:ip-cidr" {
		t.Fatalf("custom IP-CIDR REJECT failed: got (%v, %q)", act, reason)
	}

	st := r.Stats()
	if st.Version != BuiltinRuleSetVersion || st.BuiltinDomains < 150 || st.CustomRules != 4 || st.DirectHits == 0 || st.ProxyHits == 0 || st.RejectHits != 2 {
		t.Fatalf("unexpected RuleStats: %+v", st)
	}
}

func TestNodeSelfLoopRejectedInHTTPProxyAndSOCKS5(t *testing.T) {
	SetNoSysProxy(true)
	eng, err := NewEngine("")
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()

	nodeLink := &gft.Link{
		Host:   "198.51.100.50",
		Port:   443,
		PSK:    "T8URkR/djwieb24xrR35JuOMrfA7mfLsu1lsaR79ZWw=",
		Remark: "TestLoopNode",
	}
	if err := eng.SetLink(nodeLink); err != nil {
		t.Fatal(err)
	}

	if !eng.IsNodeHost("198.51.100.50:443") || !eng.IsNodeHost("198.51.100.50:8443") {
		t.Fatal("expected configured node IP to match IsNodeHost across ports")
	}
	if eng.ShouldSniffSNI("198.51.100.50:443") {
		t.Fatal("expected ShouldSniffSNI=false for configured node IP")
	}
	for _, mode := range []RouteMode{RouteRule, RouteGlobal, RouteCore} {
		act, reason := eng.router.DecideWithReason(mode, "198.51.100.50:443")
		if act != ActionReject || reason != "anti-loop:node-host" {
			t.Fatalf("mode %s: expected (ActionReject, anti-loop:node-host), got (%v, %q)", mode, act, reason)
		}
	}

	ackCalled := false
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	_, act, _, ackSent, oerr := eng.OpenStreamWithOptionalSNISniff(c1, "198.51.100.50:443", func() error {
		ackCalled = true
		return nil
	})
	if act != ActionReject || ackSent || ackCalled || !errors.Is(oerr, errNodeLoopRejected) {
		t.Fatalf("expected OpenStreamWithOptionalSNISniff to reject node self-loop before ack: act=%v ackSent=%v ackCalled=%v err=%v", act, ackSent, ackCalled, oerr)
	}

	// Simulate connected state and verify SOCKS5 CONNECT & UDP ASSOCIATE reject node self-loop without touching sched.
	eng.mu.Lock()
	eng.state = StateConnected
	eng.sched = &gft.ApexScheduler{}
	eng.mu.Unlock()
	defer func() {
		eng.mu.Lock()
		eng.sched = nil
		eng.state = StateDisconnected
		eng.mu.Unlock()
	}()

	srv := NewSOCKS5Server("127.0.0.1:0", eng)
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	conn, err := net.DialTimeout("tcp", srv.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	_, _ = conn.Write([]byte{0x05, 0x01, 0x00})
	var greet [2]byte
	if _, err := io.ReadFull(conn, greet[:]); err != nil {
		t.Fatal(err)
	}
	req := []byte{0x05, 0x01, 0x00, 0x01, 198, 51, 100, 50, 0x01, 0xBB}
	_, _ = conn.Write(req)
	var rep [10]byte
	if _, err := io.ReadFull(conn, rep[:]); err != nil {
		t.Fatal(err)
	}
	if rep[1] == 0x00 {
		t.Fatalf("expected SOCKS5 CONNECT targeting node IP to be rejected, got success reply")
	}

	// Verify SOCKS5 UDP ASSOCIATE also rejects packets targeting configured node IP.
	udpCtrl, err := net.DialTimeout("tcp", srv.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer udpCtrl.Close()
	_ = udpCtrl.SetDeadline(time.Now().Add(2 * time.Second))
	_, _ = udpCtrl.Write([]byte{0x05, 0x01, 0x00})
	if _, err := io.ReadFull(udpCtrl, greet[:]); err != nil {
		t.Fatal(err)
	}
	_, _ = udpCtrl.Write([]byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	var udpRep [10]byte
	if _, err := io.ReadFull(udpCtrl, udpRep[:]); err != nil {
		t.Fatal(err)
	}
	if udpRep[1] != 0x00 {
		t.Fatalf("expected UDP ASSOCIATE handshake OK, got rep=%v", udpRep)
	}
	relayPort := binary.BigEndian.Uint16(udpRep[8:10])
	relayConn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(relayPort)})
	if err != nil {
		t.Fatal(err)
	}
	defer relayConn.Close()
	// RSV(2)=0, FRAG(1)=0, ATYP=1(IPv4), IP=198.51.100.50, PORT=443, PAYLOAD="LOOP"
	udpPkt := []byte{0, 0, 0, 1, 198, 51, 100, 50, 0x01, 0xBB, 'L', 'O', 'O', 'P'}
	if tgt, pl, derr := gft.DecodeAddr(udpPkt[3:]); derr != nil || tgt != "198.51.100.50:443" || string(pl) != "LOOP" {
		t.Fatalf("DecodeAddr sanity check failed: tgt=%q pl=%q err=%v", tgt, pl, derr)
	}
	deadline := time.Now().Add(1500 * time.Millisecond)
	foundUDPBlock := false
	for time.Now().Before(deadline) {
		if wn, werr := relayConn.Write(udpPkt); werr != nil {
			t.Fatalf("relayConn.Write failed (wn=%d): %v", wn, werr)
		}
		for _, entry := range eng.Logs() {
			if strings.Contains(entry.Message, "[Anti-Loop] Rejected UDP") {
				foundUDPBlock = true
				break
			}
		}
		if foundUDPBlock {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if !foundUDPBlock {
		_ = udpCtrl.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		var b1 [1]byte
		_, ctrlErr := udpCtrl.Read(b1[:])
		t.Fatalf("expected SOCKS5 UDP packet targeting node IP to be rejected with [Anti-Loop] log; laddr=%v raddr=%v blocked=%d logs=%+v udpRep=%v isNode=%v ctrlErr=%v", relayConn.LocalAddr(), relayConn.RemoteAddr(), eng.AntiLoopBlockedCount(), eng.Logs(), udpRep, eng.IsNodeHost("198.51.100.50:443"), ctrlErr)
	}
}

func TestTargetTrafficTrackerTop10AndHighUploadAlert(t *testing.T) {
	SetNoSysProxy(true)
	eng, err := NewEngine("")
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()

	for i := 1; i <= 12; i++ {
		tgt := fmt.Sprintf("host%02d.example.com:443", i)
		eng.RecordTargetTraffic(tgt, uint64(i)*1024*1024, uint64(i)*512*1024)
	}
	// Push >20 MB within 10s to trigger TrafficAlert
	eng.RecordTargetTraffic("stealer.example.net:443", 21*1024*1024, 4096)
	eng.RecordTargetTraffic("stealer.example.net:443", 1024, 0) // within 10s cooldown -> must not duplicate

	top := eng.TopUploadTargets(10)
	if len(top) != 10 {
		t.Fatalf("expected 10 top upload entries, got %d", len(top))
	}
	if top[0].Target != "stealer.example.net:443" || top[1].Target != "host12.example.com:443" {
		t.Fatalf("unexpected TopUpload ordering: #1=%s #2=%s", top[0].Target, top[1].Target)
	}

	alerts := 0
	for _, entry := range eng.Logs() {
		if strings.Contains(entry.Message, "[TrafficAlert] High upload: stealer.example.net:443") {
			alerts++
		}
	}
	if alerts != 1 {
		t.Fatalf("expected exactly 1 [TrafficAlert] log within cooldown, got %d", alerts)
	}

	snap := eng.BuildDiagnosticSnapshot()
	idxTop := strings.Index(snap, "--- Top-10 Upload Targets ---")
	idxLogs := strings.Index(snap, "--- Recent Kernel Logs")
	if idxTop < 0 || idxLogs < 0 || idxTop > idxLogs {
		t.Fatalf("expected Top-10 Upload Targets at top before Recent Kernel Logs in diag snapshot:\n%s", snap)
	}
	if !strings.Contains(snap, "stealer.example.net:443") {
		t.Fatalf("expected stealer.example.net:443 inside diag snapshot")
	}
}
