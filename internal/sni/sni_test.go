package sni

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestPoolHasNoMajorVendorDefaultsAndCoversFourRegions(t *testing.T) {
	pool := LoadPool("")
	for _, reg := range OrderedRegions {
		if len(pool[reg]) < 5 {
			t.Fatalf("region %s expected >= 5 candidates, got %d", reg, len(pool[reg]))
		}
	}
	for _, c := range FlattenPool(pool) {
		if c.Domain == "www.microsoft.com" || c.Domain == "www.apple.com" || c.Domain == "www.cloudflare.com" {
			t.Fatalf("prohibited centralized CDN/vendor default found in pool: %s", c.Domain)
		}
	}
}

func TestProbeFiltersCDNAndSelfIPAndSelectsTopK(t *testing.T) {
	selfIP := "198.51.100.10"
	obsMap := map[string]ProbeObservation{
		"self.example": {
			IPs:         []net.IP{net.ParseIP(selfIP)},
			TLSVersion:  tls.VersionTLS13,
			ALPN:        "h2",
			Issuer:      "Let's Encrypt",
			HandshakeRT: 3 * time.Millisecond,
		},
		"cdn-cf.example": {
			IPs:         []net.IP{net.ParseIP("93.184.216.34")},
			TLSVersion:  tls.VersionTLS13,
			ALPN:        "h2",
			Issuer:      "Google Trust Services",
			Headers:     http.Header{"Server": []string{"cloudflare"}, "Cf-Ray": []string{"88abc-NRT"}},
			HandshakeRT: 4 * time.Millisecond,
		},
		"cdn-fastly.example": {
			IPs:         []net.IP{net.ParseIP("93.184.216.35")},
			TLSVersion:  tls.VersionTLS13,
			ALPN:        "h2",
			Issuer:      "GlobalSign",
			Headers:     http.Header{"X-Served-By": []string{"cache-nrt-fastly"}},
			HandshakeRT: 5 * time.Millisecond,
		},
		"tls12-only.example": {
			IPs:         []net.IP{net.ParseIP("93.184.216.36")},
			TLSVersion:  tls.VersionTLS12,
			ALPN:        "http/1.1",
			HandshakeRT: 5 * time.Millisecond,
		},
		"ftp.jaist.ac.jp": {
			IPs:         []net.IP{net.ParseIP("150.65.7.130")},
			TLSVersion:  tls.VersionTLS13,
			ALPN:        "h2",
			Issuer:      "National Institute of Informatics",
			Headers:     http.Header{"Server": []string{"Apache"}},
			HandshakeRT: 6 * time.Millisecond,
		},
		"ftp.riken.jp": {
			IPs:         []net.IP{net.ParseIP("134.160.38.1")},
			TLSVersion:  tls.VersionTLS13,
			ALPN:        "h2",
			Issuer:      "Let's Encrypt",
			Headers:     http.Header{"Server": []string{"nginx"}},
			HandshakeRT: 11 * time.Millisecond,
		},
		"slow-univ.example": {
			IPs:         []net.IP{net.ParseIP("130.1.1.1")},
			TLSVersion:  tls.VersionTLS13,
			ALPN:        "h2",
			Issuer:      "DigiCert",
			Headers:     http.Header{"Server": []string{"nginx"}},
			HandshakeRT: 75 * time.Millisecond,
		},
	}

	cands := []Candidate{
		{Region: "JP", Domain: "self.example"},
		{Region: "JP", Domain: "cdn-cf.example"},
		{Region: "JP", Domain: "cdn-fastly.example"},
		{Region: "JP", Domain: "tls12-only.example"},
		{Region: "APAC-JP-KR", Domain: "ftp.jaist.ac.jp"},
		{Region: "APAC-JP-KR", Domain: "ftp.riken.jp"},
		{Region: "EU", Domain: "slow-univ.example"},
	}

	results := ProbeAll(context.Background(), cands, ProbeOptions{
		SelfPublicIP: selfIP,
		ObserveFn: func(_ context.Context, d string) ProbeObservation {
			return obsMap[d]
		},
	})

	sorted := QualifiedSorted(results)
	if len(sorted) != 3 {
		t.Fatalf("expected exactly 3 qualified non-CDN origins, got %d: %+v", len(sorted), sorted)
	}
	if sorted[0].Domain != "ftp.jaist.ac.jp" || sorted[2].Domain != "slow-univ.example" || !sorted[2].LatencyWarn {
		t.Fatalf("unexpected sorted order or latency warning: %+v", sorted)
	}

	// Ensure SelectTopKRandom picks within Top-2 when k=2
	for i := 0; i < 10; i++ {
		pick, err := SelectTopKRandom(results, 2)
		if err != nil {
			t.Fatal(err)
		}
		if pick.Domain != "ftp.jaist.ac.jp" && pick.Domain != "ftp.riken.jp" {
			t.Fatalf("expected top-2 pick, got %s", pick.Domain)
		}
	}
}

func TestSelectNearestLowestLatencyPrefersNearbyCluster(t *testing.T) {
	results := []ProbeResult{
		{Region: "EU", Domain: "ftp.fau.de", Qualified: true, HandshakeRTT: 145 * time.Millisecond},
		{Region: "APAC-JP-KR", Domain: "ftp.jaist.ac.jp", Qualified: true, HandshakeRTT: 118 * time.Millisecond},
		{Region: "NA", Domain: "mirrors.ocf.berkeley.edu", Qualified: true, HandshakeRTT: 9 * time.Millisecond},
		{Region: "NA", Domain: "mirror.arizona.edu", Qualified: true, HandshakeRTT: 16 * time.Millisecond},
		{Region: "NA", Domain: "mirrors.mit.edu", Qualified: true, HandshakeRTT: 62 * time.Millisecond},
	}

	for i := 0; i < 30; i++ {
		pick, err := SelectNearestLowestLatency(results)
		if err != nil {
			t.Fatal(err)
		}
		if pick.Domain != "mirrors.ocf.berkeley.edu" && pick.Domain != "mirror.arizona.edu" {
			t.Fatalf("expected nearby low-latency NA cluster (<=21ms), got %s (%v)", pick.Domain, pick.HandshakeRTT)
		}
	}

	// Verify FlattenPool has 340+ verified entries and interleaves all regions round-robin.
	pool := LoadPool("")
	flat := FlattenPool(pool)
	if len(flat) < 340 {
		t.Fatalf("expected expanded pool to have >=340 candidates, got %d", len(flat))
	}
	if len(pool["NA-WEST"]) < 150 {
		t.Fatalf("expected NA-WEST pool to have >=150 LA/SJ/US-West candidates, got %d", len(pool["NA-WEST"]))
	}
	seenFirstWave := make(map[string]bool)
	for i := 0; i < len(OrderedRegions); i++ {
		seenFirstWave[flat[i].Region] = true
	}
	if len(seenFirstWave) != len(OrderedRegions) {
		t.Fatalf("expected first %d candidates to cover all regions round-robin, got %+v", len(OrderedRegions), flat[:len(OrderedRegions)])
	}
	sampled := SamplePerRegion(pool, 16)
	if len(sampled) != len(OrderedRegions)*16 {
		t.Fatalf("expected SamplePerRegion(16) to yield %d candidates, got %d", len(OrderedRegions)*16, len(sampled))
	}
}
