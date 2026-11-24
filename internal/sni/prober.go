package sni

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"ghostframe/internal/netbind"
)

const (
	defaultConcurrency      = 32
	defaultTotalBudget      = 7 * time.Second
	perOriginTimeout        = 2200 * time.Millisecond
	defaultSamplePerRegion  = 16
)

var cdnKeywords = []string{
	"cloudflare",
	"fastly",
	"akamai",
	"cloudfront",
	"imperva",
	"incapsula",
	"sucuri",
	"keycdn",
	"bunnycdn",
	"edgecast",
	"cdn77",
	"gcore",
}

// ProbeResult captures all 4 hygiene & latency checks for one SNI candidate.
type ProbeResult struct {
	Region       string        `json:"region"`
	Domain       string        `json:"domain"`
	ResolvedIP   string        `json:"resolved_ip"`
	DNSOK        bool          `json:"dns_ok"`
	DNSErr       string        `json:"dns_err,omitempty"`
	TLS13H2OK    bool          `json:"tls13_h2_ok"`
	TLSErr       string        `json:"tls_err,omitempty"`
	CertIssuer   string        `json:"cert_issuer"`
	Protocol     string        `json:"protocol"`
	CDNDetected  bool          `json:"cdn_detected"`
	CDNReason    string        `json:"cdn_reason,omitempty"`
	HandshakeRTT time.Duration `json:"handshake_rtt"`
	LatencyWarn  bool          `json:"latency_warn"` // > 50ms warning
	Qualified    bool          `json:"qualified"`
	Error        string        `json:"error,omitempty"`
}

// ProbeObservation describes a single probed target response for custom/mock probers.
type ProbeObservation struct {
	IPs         []net.IP
	TLSVersion  uint16
	ALPN        string
	Issuer      string
	Subject     string
	SANs        []string
	Headers     http.Header
	HandshakeRT time.Duration
	Err         error
}

// ProbeOptions controls concurrency, timeouts, self-IP exclusion, and optional test hooks.
type ProbeOptions struct {
	SelfPublicIP string
	Concurrency  int
	TotalTimeout time.Duration
	ExtraPath    string

	// Optional hook replacing live network lookup/TLS/HTTP inspection in tests.
	ObserveFn func(ctx context.Context, domain string) ProbeObservation
}

// ProbeOne runs all 4 required checks against a single domain:
//  1. DNS validity (public IP != SelfPublicIP)
//  2. Port 443 TLS 1.3 + ALPN h2 negotiation
//  3. CDN fingerprint detection (cert issuer/SAN & HTTP headers)
//  4. Handshake RTT latency classification (<20ms ideal, >50ms warning)
func ProbeOne(ctx context.Context, region, domain string, opts ProbeOptions) ProbeResult {
	res := ProbeResult{Region: region, Domain: domain}
	obs := ProbeObservation{}
	if opts.ObserveFn != nil {
		obs = opts.ObserveFn(ctx, domain)
	} else {
		obs = observeLiveOrigin(ctx, domain)
	}
	if obs.Err != nil {
		res.Error = obs.Err.Error()
		res.DNSErr = obs.Err.Error()
		return res
	}

	// Check 1: DNS validity (non-private, non-loopback, != SelfPublicIP)
	selfIP := net.ParseIP(strings.TrimSpace(opts.SelfPublicIP))
	var chosen net.IP
	for _, ip := range obs.IPs {
		if ip == nil {
			continue
		}
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
			continue
		}
		if selfIP != nil && ip.Equal(selfIP) {
			res.DNSErr = "domain resolves to this VPS's own public IP"
			res.Error = res.DNSErr
			return res
		}
		if chosen == nil || (chosen.To4() == nil && ip.To4() != nil) {
			chosen = ip
		}
	}
	if chosen == nil {
		if res.DNSErr == "" {
			res.DNSErr = "no usable public IP returned"
		}
		res.Error = res.DNSErr
		return res
	}
	res.DNSOK = true
	res.ResolvedIP = chosen.String()

	// Check 2: TLS 1.3 + ALPN h2
	res.CertIssuer = obs.Issuer
	res.Protocol = obs.ALPN
	if obs.TLSVersion != tls.VersionTLS13 {
		res.TLSErr = fmt.Sprintf("TLS version 0x%04x != TLS 1.3", obs.TLSVersion)
		res.Error = res.TLSErr
		return res
	}
	if obs.ALPN != "h2" {
		res.TLSErr = fmt.Sprintf("ALPN=%q (h2 required)", obs.ALPN)
		res.Error = res.TLSErr
		return res
	}
	res.TLS13H2OK = true
	res.HandshakeRTT = obs.HandshakeRT
	res.LatencyWarn = obs.HandshakeRT > 50*time.Millisecond

	// Check 3: CDN exclusion across certificate fields and HTTP response headers
	if cdnHit := detectCDN(obs.Issuer, obs.Subject, obs.SANs, obs.Headers); cdnHit != "" {
		res.CDNDetected = true
		res.CDNReason = cdnHit
		res.Error = "CDN detected: " + cdnHit
		return res
	}

	res.Qualified = true
	return res
}

func detectCDN(issuer, subject string, sans []string, hdrs http.Header) string {
	meta := strings.ToLower(issuer + " " + subject + " " + strings.Join(sans, " "))
	for _, kw := range cdnKeywords {
		if strings.Contains(meta, kw) {
			return "cert/" + kw
		}
	}
	if hdrs == nil {
		return ""
	}
	if hdrs.Get("CF-Ray") != "" {
		return "header/CF-Ray (cloudflare)"
	}
	for _, key := range []string{"Server", "Via", "X-Served-By", "X-Cache", "X-CDN"} {
		val := strings.ToLower(strings.Join(hdrs.Values(key), " "))
		if val == "" {
			continue
		}
		for _, kw := range cdnKeywords {
			if strings.Contains(val, kw) {
				return fmt.Sprintf("header/%s=%s", key, kw)
			}
		}
	}
	return ""
}

func observeLiveOrigin(ctx context.Context, domain string) ProbeObservation {
	var obs ProbeObservation
	subCtx, cancel := context.WithTimeout(ctx, perOriginTimeout)
	defer cancel()
	ctx = subCtx
	r := &net.Resolver{PreferGo: true}
	ipAddrs, err := r.LookupIPAddr(ctx, domain)
	if err != nil {
		obs.Err = err
		return obs
	}
	for _, ia := range ipAddrs {
		obs.IPs = append(obs.IPs, ia.IP)
	}
	var dialIP net.IP
	for _, ip := range obs.IPs {
		if ip.To4() != nil && !ip.IsPrivate() && !ip.IsLoopback() {
			dialIP = ip
			break
		}
	}
	if dialIP == nil && len(obs.IPs) > 0 {
		dialIP = obs.IPs[0]
	}
	if dialIP == nil {
		obs.Err = errors.New("dns resolution empty")
		return obs
	}

	dialer := &net.Dialer{Timeout: 2500 * time.Millisecond, Control: netbind.Control}
	t0 := time.Now()
	raw, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(dialIP.String(), "443"))
	if err != nil {
		obs.Err = err
		return obs
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = raw.SetDeadline(deadline)
	}
	tcfg := &tls.Config{
		ServerName:         domain,
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{"h2", "http/1.1"},
		InsecureSkipVerify: false,
	}
	tc := tls.Client(raw, tcfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		obs.Err = err
		return obs
	}
	obs.HandshakeRT = time.Since(t0)
	cs := tc.ConnectionState()
	obs.TLSVersion = cs.Version
	obs.ALPN = cs.NegotiatedProtocol
	if len(cs.PeerCertificates) > 0 {
		leaf := cs.PeerCertificates[0]
		obs.Issuer = issuerLabel(leaf.Issuer.CommonName, leaf.Issuer.Organization)
		obs.Subject = leaf.Subject.CommonName
		obs.SANs = leaf.DNSNames
	}
	_ = tc.Close()

	// Lightweight HTTPS HEAD check for CDN headers using a short sub-timeout.
	hc := &http.Client{
		Timeout: 1800 * time.Millisecond,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{Timeout: 1200 * time.Millisecond, Control: netbind.Control}).DialContext,
			TLSClientConfig: &tls.Config{
				ServerName: domain,
				MinVersion: tls.VersionTLS13,
			},
			ForceAttemptHTTP2: true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	if req, rerr := http.NewRequestWithContext(ctx, http.MethodHead, "https://"+domain+"/", nil); rerr == nil {
		req.Header.Set("User-Agent", "Mozilla/5.0")
		if resp, herr := hc.Do(req); herr == nil {
			obs.Headers = resp.Header.Clone()
			_ = resp.Body.Close()
		}
	}
	return obs
}

func issuerLabel(cn string, org []string) string {
	if len(org) > 0 && org[0] != "" {
		if cn != "" && cn != org[0] {
			return org[0] + " (" + cn + ")"
		}
		return org[0]
	}
	return cn
}

// ProbeAll concurrently probes candidate origins across all regions (max 32 workers, 7s total budget).
// When candidates is empty, samples up to 16 random origins per region (80 total) for fast full-geography coverage.
func ProbeAll(ctx context.Context, candidates []Candidate, opts ProbeOptions) []ProbeResult {
	if len(candidates) == 0 {
		candidates = SamplePerRegion(LoadPool(opts.ExtraPath), defaultSamplePerRegion)
	}
	conc := opts.Concurrency
	if conc <= 0 {
		conc = defaultConcurrency
	}
	budget := opts.TotalTimeout
	if budget <= 0 {
		budget = defaultTotalBudget
	}
	probeCtx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()

	jobs := make(chan int, len(candidates))
	results := make([]ProbeResult, len(candidates))
	for i := range candidates {
		jobs <- i
	}
	close(jobs)

	var wg sync.WaitGroup
	workers := conc
	if len(candidates) < workers {
		workers = len(candidates)
	}
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				c := candidates[idx]
				results[idx] = ProbeOne(probeCtx, c.Region, c.Domain, opts)
			}
		}()
	}
	wg.Wait()
	return results
}

// QualifiedSorted filters qualified non-CDN origins and sorts ascending by HandshakeRTT.
func QualifiedSorted(results []ProbeResult) []ProbeResult {
	var out []ProbeResult
	for _, r := range results {
		if r.Qualified {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].HandshakeRTT < out[j].HandshakeRTT
	})
	return out
}

// SelectTopKRandom selects one origin at random (via crypto/rand) from the fastest k qualified sites.
func SelectTopKRandom(results []ProbeResult, k int) (ProbeResult, error) {
	sorted := QualifiedSorted(results)
	if len(sorted) == 0 {
		return ProbeResult{}, errors.New("no qualified non-CDN TLS 1.3 + H2 SNI candidates reachable")
	}
	if k <= 0 || k > len(sorted) {
		k = len(sorted)
	}
	idxBig, err := rand.Int(rand.Reader, big.NewInt(int64(k)))
	if err != nil {
		return sorted[0], nil
	}
	return sorted[int(idxBig.Int64())], nil
}

// SelectNearestLowestLatency picks a qualified non-CDN TLS 1.3 + H2 origin from the tight
// nearby-latency cluster around the fastest reachable origin (within max(best*1.5, best+12ms),
// capped at best+25ms, up to Top-3), so every VPS automatically chooses a geographically close
// low-latency mirror while retaining mild diversity among equally fast local mirrors.
func SelectNearestLowestLatency(results []ProbeResult) (ProbeResult, error) {
	sorted := QualifiedSorted(results)
	if len(sorted) == 0 {
		return ProbeResult{}, errors.New("no qualified non-CDN TLS 1.3 + H2 SNI candidates reachable")
	}
	best := sorted[0].HandshakeRTT
	cutoff := best + 12*time.Millisecond
	if scaled := (best * 3) / 2; scaled > cutoff {
		cutoff = scaled
	}
	if maxCutoff := best + 25*time.Millisecond; cutoff > maxCutoff {
		cutoff = maxCutoff
	}
	limit := 1
	for i := 1; i < len(sorted) && i < 3; i++ {
		if sorted[i].HandshakeRTT <= cutoff {
			limit = i + 1
		} else {
			break
		}
	}
	if limit <= 1 {
		return sorted[0], nil
	}
	idxBig, err := rand.Int(rand.Reader, big.NewInt(int64(limit)))
	if err != nil {
		return sorted[0], nil
	}
	return sorted[int(idxBig.Int64())], nil
}

// AutoSelectSNI runs full-region concurrent pool probing and returns a nearest lowest-latency non-CDN domain.
func AutoSelectSNI(ctx context.Context, selfPublicIP string) (ProbeResult, []ProbeResult, error) {
	all := ProbeAll(ctx, nil, ProbeOptions{SelfPublicIP: selfPublicIP})
	pick, err := SelectNearestLowestLatency(all)
	return pick, all, err
}

// DetectSelfPublicIP attempts to learn the host's public IP for DNS self-pointing validation.
func DetectSelfPublicIP(ctx context.Context) string {
	endpoints := []string{
		"https://api.ipify.org",
		"https://ifconfig.me/ip",
	}
	hc := &http.Client{Timeout: 2 * time.Second}
	for _, u := range endpoints {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			continue
		}
		resp, err := hc.Do(req)
		if err != nil {
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 128))
		_ = resp.Body.Close()
		ip := net.ParseIP(strings.TrimSpace(string(b)))
		if ip != nil {
			return ip.String()
		}
	}
	return ""
}

// CheckDomainPointsToIP verifies that domain has an A/AAAA record resolving to targetIP.
func CheckDomainPointsToIP(ctx context.Context, domain, targetIP string) (bool, []string, error) {
	r := &net.Resolver{PreferGo: true}
	ips, err := r.LookupIPAddr(ctx, domain)
	if err != nil {
		return false, nil, err
	}
	want := net.ParseIP(strings.TrimSpace(targetIP))
	var resolved []string
	matched := false
	for _, ia := range ips {
		resolved = append(resolved, ia.IP.String())
		if want != nil && ia.IP.Equal(want) {
			matched = true
		}
	}
	return matched, resolved, nil
}
