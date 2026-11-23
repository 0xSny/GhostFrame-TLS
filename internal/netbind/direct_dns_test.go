package netbind

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestIsFakeIP(t *testing.T) {
	yes := []string{
		"198.18.0.1",
		"198.18.12.34",
		"198.19.0.1",
		"198.19.255.254",
		"::ffff:198.18.1.10",
		"fd18:c612::1",
		"fd18:c612::dead:beef",
	}
	for _, s := range yes {
		if !IsFakeIP(net.ParseIP(s)) {
			t.Fatalf("expected IsFakeIP(%s) == true", s)
		}
	}

	no := []string{
		"198.17.255.254",
		"198.20.0.1",
		"223.5.5.5",
		"127.0.0.1",
		"fd18:c612:0:1::1",
		"2400:3200::1",
		"64:ff9b::2669:1eaa",
	}
	for _, s := range no {
		if IsFakeIP(net.ParseIP(s)) {
			t.Fatalf("expected IsFakeIP(%s) == false", s)
		}
	}
	if IsFakeIP(nil) {
		t.Fatal("expected IsFakeIP(nil) == false")
	}
}

func startMockUDPDNSServer(t *testing.T, handler func(qname string, qtype uint16) [][]byte) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen mock udp dns: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })

	go func() {
		buf := make([]byte, 1500)
		for {
			n, addr, rerr := pc.ReadFrom(buf)
			if rerr != nil {
				return
			}
			if n < 12 {
				continue
			}
			qname, qtype, qend := parseTestDNSQuestion(buf[:n])
			if qend <= 12 {
				continue
			}
			resp := make([]byte, qend, 512)
			copy(resp, buf[:qend])
			// QR=1, RA=1, QDCOUNT=1, ANCOUNT=len(answers), NSCOUNT=0, ARCOUNT=0 (strip OPT EDNS0 from request)
			resp[2] = 0x81
			resp[3] = 0x80
			binary.BigEndian.PutUint16(resp[4:6], 1)
			answers := handler(qname, qtype)
			binary.BigEndian.PutUint16(resp[6:8], uint16(len(answers)))
			binary.BigEndian.PutUint16(resp[8:10], 0)
			binary.BigEndian.PutUint16(resp[10:12], 0)
			for _, ipBytes := range answers {
				var rr [12]byte
				binary.BigEndian.PutUint16(rr[0:2], 0xc00c)
				if len(ipBytes) == 16 {
					binary.BigEndian.PutUint16(rr[2:4], 28) // AAAA
				} else {
					binary.BigEndian.PutUint16(rr[2:4], 1) // A
				}
				binary.BigEndian.PutUint16(rr[4:6], 1)   // IN
				binary.BigEndian.PutUint32(rr[6:10], 60) // TTL
				binary.BigEndian.PutUint16(rr[10:12], uint16(len(ipBytes)))
				resp = append(resp, rr[:]...)
				resp = append(resp, ipBytes...)
			}
			_, _ = pc.WriteTo(resp, addr)
		}
	}()
	return pc.LocalAddr().String()
}

func parseTestDNSQuestion(pkt []byte) (qname string, qtype uint16, qend int) {
	pos := 12
	var labels []string
	for pos < len(pkt) {
		l := int(pkt[pos])
		pos++
		if l == 0 {
			break
		}
		if pos+l > len(pkt) {
			return "", 0, 0
		}
		labels = append(labels, string(pkt[pos:pos+l]))
		pos += l
	}
	if pos+4 > len(pkt) {
		return "", 0, 0
	}
	return strings.ToLower(strings.Join(labels, ".")), binary.BigEndian.Uint16(pkt[pos : pos+2]), pos + 4
}

func TestDirectLookupHostIPsFiltersFakeIPAndCapsCache(t *testing.T) {
	ClearDirectDNSCache()
	t.Cleanup(func() {
		directDNSCacheMu.Lock()
		directDNSServersOverride = nil
		directDNSCacheMu.Unlock()
		ClearDirectDNSCache()
	})

	srvAddr := startMockUDPDNSServer(t, func(qname string, qtype uint16) [][]byte {
		if qname == "poison-only.example.cn" {
			if qtype == 1 {
				return [][]byte{{198, 18, 0, 99}, {198, 19, 1, 2}}
			}
			if qtype == 28 {
				return [][]byte{net.ParseIP("fd18:c612::88").To16()}
			}
			return nil
		}
		if qtype == 1 {
			return [][]byte{{198, 18, 0, 5}, {223, 5, 5, 5}}
		}
		return nil
	})

	directDNSCacheMu.Lock()
	directDNSServersOverride = []string{srvAddr}
	directDNSCacheMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 1. Mixed answer containing 198.18.0.5 + real 223.5.5.5 must strip Fake-IP.
	ips, err := DirectLookupHostIPs(ctx, "mixed.example.cn")
	if err != nil {
		t.Fatalf("DirectLookupHostIPs(mixed.example.cn) failed: %v", err)
	}
	if len(ips) != 1 || !ips[0].Equal(net.IPv4(223, 5, 5, 5)) {
		t.Fatalf("expected only [223.5.5.5], got %v", ips)
	}

	// 2. Poison-only Fake-IP answers must return ErrFakeIPBlocked.
	if _, err := DirectLookupHostIPs(ctx, "poison-only.example.cn"); !errors.Is(err, ErrFakeIPBlocked) {
		t.Fatalf("expected ErrFakeIPBlocked for Fake-IP-only DNS response, got %v", err)
	}

	// 3. Cache bound must stay <= directDNSCacheMax (512) and ResetNAT64Cache clears it.
	for i := 0; i < 600; i++ {
		putCachedDirectDNS("host-"+strconv.Itoa(i)+".cn", []net.IP{net.IPv4(223, 5, 5, 5)})
	}
	directDNSCacheMu.Lock()
	cacheLen := len(directDNSCache)
	directDNSCacheMu.Unlock()
	if cacheLen > directDNSCacheMax {
		t.Fatalf("expected directDNSCache bounded <= %d, got %d", directDNSCacheMax, cacheLen)
	}
	ResetNAT64Cache()
	directDNSCacheMu.Lock()
	afterClear := len(directDNSCache)
	directDNSCacheMu.Unlock()
	if afterClear != 0 {
		t.Fatalf("expected ResetNAT64Cache to clear directDNSCache, remaining=%d", afterClear)
	}
}

func TestResolveDirectTCPAndUDPAddr(t *testing.T) {
	restore := SetNAT64TestHooks(
		func() bool { return true },
		func(ctx context.Context, host string) ([]net.IP, error) {
			if host == "ipv4only.arpa" {
				return []net.IP{net.ParseIP("2001:db8:64:1::192.0.0.170")}, nil
			}
			return nil, nil
		},
		func(ctx context.Context, host string) ([]net.IP, error) {
			switch host {
			case "v4only.example.cn":
				return []net.IP{net.ParseIP("198.18.0.1"), net.ParseIP("110.242.68.66")}, nil
			case "dual.example.cn":
				return []net.IP{net.ParseIP("110.242.68.66"), net.ParseIP("2408:871a:2100:2::1")}, nil
			case "fakepoisondom.example.cn":
				return []net.IP{net.ParseIP("198.19.0.10"), net.ParseIP("fd18:c612::10")}, nil
			}
			return nil, nil
		},
	)
	defer restore()

	ctx := context.Background()

	// Fake-IP literals must be rejected.
	for _, fakeHP := range []string{"198.18.1.5:443", "198.19.2.3:80", "[fd18:c612::42]:443"} {
		if _, _, err := ResolveDirectTCPAddr(ctx, fakeHP, true); !errors.Is(err, ErrFakeIPBlocked) {
			t.Fatalf("ResolveDirectTCPAddr(%s) expected ErrFakeIPBlocked, got %v", fakeHP, err)
		}
		if _, _, err := ResolveDirectUDPAddr(ctx, fakeHP, true); !errors.Is(err, ErrFakeIPBlocked) {
			t.Fatalf("ResolveDirectUDPAddr(%s) expected ErrFakeIPBlocked, got %v", fakeHP, err)
		}
	}

	// Poisoned domain returning only Fake-IPs must be rejected.
	if _, _, err := ResolveDirectTCPAddr(ctx, "fakepoisondom.example.cn:443", true); !errors.Is(err, ErrFakeIPBlocked) {
		t.Fatalf("expected ErrFakeIPBlocked for poisoned domain, got %v", err)
	}

	// Under pure IPv6 physical interface:
	// - v4-only domain synthesizes carrier NAT64 IPv6 over tcp6/udp6.
	dNet, addrStr, err := ResolveDirectTCPAddr(ctx, "v4only.example.cn:443", false)
	if err != nil || dNet != "tcp6" || addrStr != "[2001:db8:64:1::6ef2:4442]:443" {
		t.Fatalf("pure-IPv6 NAT64 domain TCP mismatch: net=%q addr=%q err=%v", dNet, addrStr, err)
	}
	uNet, ua, err := ResolveDirectUDPAddr(ctx, "110.242.68.66:53", false)
	if err != nil || uNet != "udp6" || ua == nil || ua.String() != "[2001:db8:64:1::6ef2:4442]:53" {
		t.Fatalf("pure-IPv6 NAT64 literal UDP mismatch: net=%q ua=%v err=%v", uNet, ua, err)
	}
	// - dual-stack domain prefers native AAAA on pure-IPv6 cellular.
	dNetDual, addrDual, err := ResolveDirectTCPAddr(ctx, "dual.example.cn:443", false)
	if err != nil || dNetDual != "tcp6" || addrDual != "[2408:871a:2100:2::1]:443" {
		t.Fatalf("pure-IPv6 dual-stack domain mismatch: net=%q addr=%q err=%v", dNetDual, addrDual, err)
	}

	// Switch back to dual-stack / IPv4 Wi-Fi:
	restore2 := SetNAT64TestHooks(
		func() bool { return false },
		nil,
		func(ctx context.Context, host string) ([]net.IP, error) {
			if host == "v6only.example.cn" {
				return []net.IP{net.ParseIP("2408:871a:2100:2::1")}, nil
			}
			return []net.IP{net.ParseIP("110.242.68.66"), net.ParseIP("2408:871a:2100:2::1")}, nil
		},
	)
	defer restore2()

	if _, _, err := ResolveDirectTCPAddr(ctx, "v6only.example.cn:443", false); !errors.Is(err, ErrIPv6Disabled) {
		t.Fatalf("expected ErrIPv6Disabled for AAAA-only domain when allowIPv6=false, got %v", err)
	}
	if _, _, err := ResolveDirectTCPAddr(ctx, "[::1]:8080", false); err != nil {
		t.Fatalf("expected loopback ::1 allowed even when allowIPv6=false, got %v", err)
	}
	dNetV4, addrV4, err := ResolveDirectTCPAddr(ctx, "dual.example.cn:443", false)
	if err != nil || dNetV4 != "tcp4" || addrV4 != "110.242.68.66:443" {
		t.Fatalf("expected tcp4 A-record resolution on non-pure-IPv6, got net=%q addr=%q err=%v", dNetV4, addrV4, err)
	}
}

func TestDirectLookupHostIPsSingleflightAndIPv4Family(t *testing.T) {
	ClearDirectDNSCache()
	t.Cleanup(func() {
		directDNSCacheMu.Lock()
		directDNSServersOverride = nil
		directDNSCacheMu.Unlock()
		ClearDirectDNSCache()
	})

	var aQueries atomic.Int32
	var aaaaQueries atomic.Int32
	srvAddr := startMockUDPDNSServer(t, func(qname string, qtype uint16) [][]byte {
		if qtype == 28 {
			aaaaQueries.Add(1)
			return [][]byte{net.ParseIP("2408:871a:2100:2::1").To16()}
		}
		if qtype == 1 {
			aQueries.Add(1)
			time.Sleep(60 * time.Millisecond)
			return [][]byte{{110, 242, 68, 66}, {110, 242, 68, 67}}
		}
		return nil
	})
	directDNSCacheMu.Lock()
	directDNSServersOverride = []string{srvAddr}
	directDNSCacheMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Concurrent IPv4-only lookups must coalesce via singleflight to a single A query and 0 AAAA queries.
	const workers = 10
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			ips, err := DirectLookupHostIPsFamily(ctx, "sf.example.cn", "ip4")
			if err != nil {
				errs <- err
				return
			}
			if len(ips) != 2 {
				errs <- errors.New("expected 2 IPv4 addresses")
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if q := aQueries.Load(); q != 1 {
		t.Fatalf("expected exactly 1 coalesced A query, got %d", q)
	}
	if q6 := aaaaQueries.Load(); q6 != 0 {
		t.Fatalf("expected 0 AAAA queries for ip4 family, got %d", q6)
	}
}
