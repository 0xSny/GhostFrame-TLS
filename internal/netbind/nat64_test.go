package netbind

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestExtractAndSynthesizeNAT64(t *testing.T) {
	cases := []struct {
		name     string
		ipv4only string
		wantPref [12]byte
		target   string
		wantOut  string
		ok       bool
	}{
		{
			name:     "well-known 64:ff9b::192.0.0.170",
			ipv4only: "64:ff9b::192.0.0.170",
			wantPref: [12]byte{0x00, 0x64, 0xff, 0x9b},
			target:   "38.105.30.170",
			wantOut:  "64:ff9b::2669:1eaa",
			ok:       true,
		},
		{
			name:     "carrier prefix 2001:db8:6464::192.0.0.171",
			ipv4only: "2001:db8:6464::192.0.0.171",
			wantPref: [12]byte{0x20, 0x01, 0x0d, 0xb8, 0x64, 0x64},
			target:   "1.2.3.4",
			wantOut:  "2001:db8:6464::102:304",
			ok:       true,
		},
		{
			name:     "non-rfc7050 v6 rejected",
			ipv4only: "2001:4860:4860::8888",
			ok:       false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ip := net.ParseIP(tc.ipv4only)
			pref, ok := ExtractNAT64Prefix(ip)
			if ok != tc.ok {
				t.Fatalf("ExtractNAT64Prefix(%s) ok=%v want=%v", tc.ipv4only, ok, tc.ok)
			}
			if !tc.ok {
				return
			}
			if pref != tc.wantPref {
				t.Fatalf("prefix mismatch: got %x want %x", pref, tc.wantPref)
			}
			synth := SynthesizeNAT64IPv4(pref, net.ParseIP(tc.target))
			if synth == nil || synth.String() != tc.wantOut {
				t.Fatalf("SynthesizeNAT64IPv4(%s) got %v want %s", tc.target, synth, tc.wantOut)
			}
		})
	}
}

func TestNAT64DialAndHopResolutionLoop(t *testing.T) {
	origPure := isPureIPv6PhysicalFn
	origV6 := lookupIPv6Fn
	origHost := lookupHostIPsFn
	t.Cleanup(func() {
		isPureIPv6PhysicalFn = origPure
		lookupIPv6Fn = origV6
		lookupHostIPsFn = origHost
		ResetNAT64Cache()
	})

	var pureIPv6 atomic.Bool
	pureIPv6.Store(true)
	isPureIPv6PhysicalFn = pureIPv6.Load

	carrierPrefix := "2001:db8:64:1::"
	lookupIPv6Fn = func(ctx context.Context, host string) ([]net.IP, error) {
		if host == "ipv4only.arpa" {
			return []net.IP{net.ParseIP(carrierPrefix + "192.0.0.170")}, nil
		}
		return nil, nil
	}
	lookupHostIPsFn = func(ctx context.Context, host string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("198.51.100.42")}, nil
	}
	ResetNAT64Cache()

	// 1. TCP-uTLS dial to literal IPv4 must synthesize carrier NAT64 IPv6.
	hp := ResolveTCPHostPort(context.Background(), "198.51.100.42", 443)
	if hp != "[2001:db8:64:1::c633:642a]:443" {
		t.Fatalf("unexpected TCP NAT64 target: %s", hp)
	}

	// 2. Kestrel-RTC initial Dial & HopWithPortRange UDP resolution must synthesize NAT64 IPv6 for every new hop port.
	u1, err := ResolveUDPAddr(context.Background(), "198.51.100.42", 30868)
	if err != nil {
		t.Fatalf("ResolveUDPAddr initial failed: %v", err)
	}
	u2, err := ResolveUDPAddr(context.Background(), "198.51.100.42", 31200)
	if err != nil {
		t.Fatalf("ResolveUDPAddr hop failed: %v", err)
	}
	if u1.IP.To4() != nil || u1.Port != 30868 || u2.IP.To4() != nil || u2.Port != 31200 || !u1.IP.Equal(u2.IP) {
		t.Fatalf("expected consistent synthesized NAT64 IPv6 across hop ports: u1=%v u2=%v", u1, u2)
	}

	// 3. Domain target under pure-IPv6 cellular must synthesize IPv4 DNS answer via NAT64 too.
	domTCP := ResolveTCPHostPort(context.Background(), "edge.example.com", 443)
	if domTCP != "[2001:db8:64:1::c633:642a]:443" {
		t.Fatalf("unexpected domain NAT64 target: %s", domTCP)
	}

	// 4. Transition back to IPv4 Wi-Fi + SetPreferredInterface must immediately reset NAT64 cache.
	pureIPv6.Store(false)
	SetPreferredInterface("en0")
	if got := ResolveTCPHostPort(context.Background(), "198.51.100.42", 443); got != "198.51.100.42:443" {
		t.Fatalf("expected IPv4 target after Wi-Fi handoff, got %s", got)
	}
}

func TestNAT64SetPreferredInterfaceAndFallbackShortTTL(t *testing.T) {
	restore := SetNAT64TestHooks(
		func() bool { return true },
		func(ctx context.Context, host string) ([]net.IP, error) {
			return nil, context.DeadlineExceeded
		},
		nil,
	)
	defer restore()

	// When ipv4only.arpa lookup fails, DiscoverNAT64Prefix falls back to 64:ff9b::/96 with short 2s TTL.
	pref, ok := DiscoverNAT64Prefix(context.Background())
	if !ok || pref != wellKnownNAT64Prefix {
		t.Fatalf("expected fallback 64:ff9b:: prefix, got ok=%v pref=%v", ok, pref)
	}
	nat64Mu.RLock()
	rem := time.Until(nat64ExpiresAt)
	nat64Mu.RUnlock()
	if rem <= 0 || rem > 2*time.Second+100*time.Millisecond {
		t.Fatalf("expected short <=2s TTL on fallback prefix, got remaining=%v", rem)
	}

	// Now simulate operator prefix appearing; SetPreferredInterface must clear cache immediately.
	var calls atomic.Int32
	restore2 := SetNAT64TestHooks(
		func() bool { return true },
		func(ctx context.Context, host string) ([]net.IP, error) {
			calls.Add(1)
			return []net.IP{net.ParseIP("2001:db8:64:2::192.0.0.171")}, nil
		},
		nil,
	)
	defer restore2()

	SetPreferredInterface("pdp_ip0")
	pref2, ok2 := DiscoverNAT64Prefix(context.Background())
	if !ok2 || pref2 == wellKnownNAT64Prefix || calls.Load() != 1 {
		t.Fatalf("expected SetPreferredInterface to reset NAT64 cache and re-discover prefix: ok=%v calls=%d pref=%v", ok2, calls.Load(), pref2)
	}
	nat64Mu.RLock()
	rem2 := time.Until(nat64ExpiresAt)
	nat64Mu.RUnlock()
	if rem2 < 25*time.Second {
		t.Fatalf("expected ~30s TTL on discovered operator prefix, got remaining=%v", rem2)
	}
}
