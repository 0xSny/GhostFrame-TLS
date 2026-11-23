package client

import (
	"bytes"
	"compress/zlib"
	"context"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"ghostframe/internal/gft"
)

const (
	// DefaultRuleBundleURL points to the public pure-binary distribution release artifact.
	DefaultRuleBundleURL = "https://github.com/Spittingjiu/Ghost/releases/latest/download/rules_bundle.zlib"

	ruleBundleMagic      = "KSLR"
	ruleBundleVersion    = uint32(1)
	ruleBundleHeaderSize = 32
	maxRuleBundleBytes   = 6 << 20 // 6 MiB compressed safety cap
	maxRuleBundleEntries = 500000
	ruleBundleFileName   = "rules_bundle.zlib"
)

//go:embed rules_bundle.zlib
var embeddedRulesBundleZlib []byte

var (
	embeddedBundleOnce sync.Once
	embeddedBundlePtr  *CompactRuleBundle
)

// CompactRuleBundle stores sorted ascending 64-bit domain suffix hashes with zero heap pointers.
// At ~137k rules, runtime heap footprint is ~1.05 MiB with zero GC pointer scanning overhead.
type CompactRuleBundle struct {
	Salt         uint64
	ProxyHashes  []uint64
	DirectHashes []uint64
	Source       string // "embedded" or "local"
	UpdatedAt    int64
}

// TotalCount returns the total number of compact suffix entries (Proxy + Direct).
func (b *CompactRuleBundle) TotalCount() int {
	if b == nil {
		return 0
	}
	return len(b.ProxyHashes) + len(b.DirectHashes)
}

// HashDomain64 hashes host (ASCII-lowercased, stripped of trailing dots) using FNV-1a 64-bit
// followed by a SplitMix64 avalanche finalizer with zero heap allocations.
func HashDomain64(s string, salt uint64) uint64 {
	const (
		offset64 = 14695981039346656037
		prime64  = 1099511628211
	)
	n := len(s)
	for n > 0 && s[n-1] == '.' {
		n--
	}
	h := uint64(offset64) ^ salt
	for i := 0; i < n; i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		h ^= uint64(c)
		h *= prime64
	}
	h ^= h >> 30
	h *= 0xbf58476d1ce4e5b9
	h ^= h >> 27
	h *= 0x94d049bb133111eb
	h ^= h >> 31
	return h
}

func containsUint64Sorted(sorted []uint64, target uint64) bool {
	lo, hi := 0, len(sorted)
	for lo < hi {
		mid := int(uint(lo+hi) >> 1)
		if sorted[mid] < target {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	return lo < len(sorted) && sorted[lo] == target
}

func lookupHashSuffix(hostLower string, sorted []uint64, salt uint64) bool {
	if hostLower == "" || len(sorted) == 0 {
		return false
	}
	if containsUint64Sorted(sorted, HashDomain64(hostLower, salt)) {
		return true
	}
	for i := 0; i < len(hostLower); i++ {
		if hostLower[i] == '.' && i+1 < len(hostLower) {
			if containsUint64Sorted(sorted, HashDomain64(hostLower[i+1:], salt)) {
				return true
			}
		}
	}
	return false
}

// ContainsProxySuffix checks exact domain and all parent domain suffixes in ProxyHashes.
func (b *CompactRuleBundle) ContainsProxySuffix(hostLower string) bool {
	if b == nil {
		return false
	}
	return lookupHashSuffix(hostLower, b.ProxyHashes, b.Salt)
}

// ContainsDirectSuffix checks exact domain and all parent domain suffixes in DirectHashes.
func (b *CompactRuleBundle) ContainsDirectSuffix(hostLower string) bool {
	if b == nil {
		return false
	}
	return lookupHashSuffix(hostLower, b.DirectHashes, b.Salt)
}

// EncodeCompactRuleBundle computes collision-free sorted 64-bit hash slices for proxy & direct
// domain suffix sets and returns a zlib-compressed KSLR binary bundle.
func EncodeCompactRuleBundle(proxyDomains, directDomains []string) ([]byte, uint64, int, int, error) {
	proxyClean := normalizeDomainSlice(proxyDomains)
	directClean := normalizeDomainSlice(directDomains)

	// Disjointness invariant: Proxy strictly wins over Direct.
	proxySet := make(map[string]struct{}, len(proxyClean))
	for _, d := range proxyClean {
		proxySet[d] = struct{}{}
	}
	filteredDirect := directClean[:0]
	for _, d := range directClean {
		if _, dup := proxySet[d]; !dup {
			filteredDirect = append(filteredDirect, d)
		}
	}
	directClean = filteredDirect

	var salt uint64
	var pHashes, dHashes []uint64
	for attempt := 0; attempt < 64; attempt++ {
		s := uint64(attempt)
		pHashes = make([]uint64, len(proxyClean))
		dHashes = make([]uint64, len(directClean))
		for i, d := range proxyClean {
			pHashes[i] = HashDomain64(d, s)
		}
		for i, d := range directClean {
			dHashes[i] = HashDomain64(d, s)
		}
		sort.Slice(pHashes, func(i, j int) bool { return pHashes[i] < pHashes[j] })
		sort.Slice(dHashes, func(i, j int) bool { return dHashes[i] < dHashes[j] })

		if !hasDuplicateUint64(pHashes) && !hasDuplicateUint64(dHashes) && !hasCrossCollision(pHashes, dHashes) {
			salt = s
			goto encode
		}
	}
	return nil, 0, 0, 0, errors.New("rules: failed to find collision-free 64-bit salt")

encode:
	var out bytes.Buffer
	zw, err := zlib.NewWriterLevel(&out, zlib.BestCompression)
	if err != nil {
		return nil, 0, 0, 0, err
	}
	var hdr [ruleBundleHeaderSize]byte
	copy(hdr[0:4], ruleBundleMagic)
	binary.LittleEndian.PutUint32(hdr[4:8], ruleBundleVersion)
	binary.LittleEndian.PutUint64(hdr[8:16], salt)
	binary.LittleEndian.PutUint32(hdr[16:20], uint32(len(pHashes)))
	binary.LittleEndian.PutUint32(hdr[20:24], uint32(len(dHashes)))
	if _, err := zw.Write(hdr[:]); err != nil {
		_ = zw.Close()
		return nil, 0, 0, 0, err
	}
	if err := writeUint64SliceLE(zw, pHashes); err != nil {
		_ = zw.Close()
		return nil, 0, 0, 0, err
	}
	if err := writeUint64SliceLE(zw, dHashes); err != nil {
		_ = zw.Close()
		return nil, 0, 0, 0, err
	}
	if err := zw.Close(); err != nil {
		return nil, 0, 0, 0, err
	}
	return out.Bytes(), salt, len(pHashes), len(dHashes), nil
}

func normalizeDomainSlice(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, raw := range in {
		d := strings.TrimSpace(strings.ToLower(raw))
		d = strings.TrimPrefix(d, "+.")
		d = strings.TrimPrefix(d, ".")
		d = strings.TrimSuffix(d, ".")
		if d == "" || !strings.Contains(d, ".") {
			continue
		}
		if _, ok := seen[d]; ok {
			continue
		}
		seen[d] = struct{}{}
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}

func hasDuplicateUint64(sorted []uint64) bool {
	for i := 1; i < len(sorted); i++ {
		if sorted[i] == sorted[i-1] {
			return true
		}
	}
	return false
}

func hasCrossCollision(a, b []uint64) bool {
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		if a[i] == b[j] {
			return true
		}
		if a[i] < b[j] {
			i++
		} else {
			j++
		}
	}
	return false
}

func writeUint64SliceLE(w io.Writer, vals []uint64) error {
	var buf [4096 * 8]byte
	for off := 0; off < len(vals); {
		chunk := len(vals) - off
		if chunk > 4096 {
			chunk = 4096
		}
		for k := 0; k < chunk; k++ {
			binary.LittleEndian.PutUint64(buf[k*8:k*8+8], vals[off+k])
		}
		if _, err := w.Write(buf[:chunk*8]); err != nil {
			return err
		}
		off += chunk
	}
	return nil
}

func readUint64SliceLE(r io.Reader, count int) ([]uint64, error) {
	out := make([]uint64, count)
	var buf [4096 * 8]byte
	for off := 0; off < count; {
		chunk := count - off
		if chunk > 4096 {
			chunk = 4096
		}
		nBytes := chunk * 8
		if _, err := io.ReadFull(r, buf[:nBytes]); err != nil {
			return nil, err
		}
		for k := 0; k < chunk; k++ {
			out[off+k] = binary.LittleEndian.Uint64(buf[k*8 : k*8+8])
		}
		off += chunk
	}
	return out, nil
}

// DecodeCompactRuleBundle streams and validates a zlib-compressed KSLR bundle directly into
// pointer-free sorted uint64 slices without keeping uncompressed raw bytes on the heap.
func DecodeCompactRuleBundle(zlibData []byte, source string, updatedAt int64) (*CompactRuleBundle, error) {
	if len(zlibData) == 0 || len(zlibData) > maxRuleBundleBytes {
		return nil, errors.New("rules: invalid compressed bundle size")
	}
	zr, err := zlib.NewReader(bytes.NewReader(zlibData))
	if err != nil {
		return nil, fmt.Errorf("rules: zlib open failed: %w", err)
	}
	defer zr.Close()

	var hdr [ruleBundleHeaderSize]byte
	if _, err := io.ReadFull(zr, hdr[:]); err != nil {
		return nil, fmt.Errorf("rules: header read failed: %w", err)
	}
	if string(hdr[0:4]) != ruleBundleMagic {
		return nil, errors.New("rules: invalid KSLR magic")
	}
	ver := binary.LittleEndian.Uint32(hdr[4:8])
	if ver != ruleBundleVersion {
		return nil, fmt.Errorf("rules: unsupported bundle version %d", ver)
	}
	salt := binary.LittleEndian.Uint64(hdr[8:16])
	proxyN := int(binary.LittleEndian.Uint32(hdr[16:20]))
	directN := int(binary.LittleEndian.Uint32(hdr[20:24]))
	if proxyN < 0 || directN < 0 || proxyN+directN > maxRuleBundleEntries {
		return nil, errors.New("rules: entry count out of bounds")
	}

	pHashes, err := readUint64SliceLE(zr, proxyN)
	if err != nil {
		return nil, fmt.Errorf("rules: read proxy hashes failed: %w", err)
	}
	dHashes, err := readUint64SliceLE(zr, directN)
	if err != nil {
		return nil, fmt.Errorf("rules: read direct hashes failed: %w", err)
	}
	var tail [1]byte
	if n, rerr := zr.Read(tail[:]); n > 0 || (rerr != nil && !errors.Is(rerr, io.EOF)) {
		return nil, errors.New("rules: trailing bytes after bundle payload")
	}
	if !sort.SliceIsSorted(pHashes, func(i, j int) bool { return pHashes[i] < pHashes[j] }) ||
		!sort.SliceIsSorted(dHashes, func(i, j int) bool { return dHashes[i] < dHashes[j] }) {
		return nil, errors.New("rules: unsorted hash table")
	}
	return &CompactRuleBundle{
		Salt:         salt,
		ProxyHashes:  pHashes,
		DirectHashes: dHashes,
		Source:       source,
		UpdatedAt:    updatedAt,
	}, nil
}

func loadEmbeddedCompactRuleBundle() *CompactRuleBundle {
	embeddedBundleOnce.Do(func() {
		if len(embeddedRulesBundleZlib) == 0 {
			return
		}
		b, err := DecodeCompactRuleBundle(embeddedRulesBundleZlib, "embedded", 0)
		if err == nil {
			embeddedBundlePtr = b
		}
	})
	return embeddedBundlePtr
}

// LoadCompactRuleBundleFromDir loads <dataDir>/rules_bundle.zlib when present and valid,
// otherwise falling back cleanly to the embedded KSLR bundle.
func LoadCompactRuleBundleFromDir(dataDir string) *CompactRuleBundle {
	if dir := strings.TrimSpace(dataDir); dir != "" {
		p := filepath.Join(dir, ruleBundleFileName)
		if info, err := os.Stat(p); err == nil && info.Size() > 0 && info.Size() <= maxRuleBundleBytes {
			if raw, rerr := os.ReadFile(p); rerr == nil {
				if b, derr := DecodeCompactRuleBundle(raw, "local", info.ModTime().Unix()); derr == nil && b.TotalCount() > 0 {
					return b
				}
			}
		}
	}
	return loadEmbeddedCompactRuleBundle()
}

type dataStreamNetConn struct {
	gft.DataStream
}

type dummyAddr string

func (d dummyAddr) Network() string { return "tcp" }
func (d dummyAddr) String() string  { return string(d) }

func (c dataStreamNetConn) LocalAddr() net.Addr                { return dummyAddr("127.0.0.1:0") }
func (c dataStreamNetConn) RemoteAddr() net.Addr               { return dummyAddr(c.RemoteTarget()) }
func (c dataStreamNetConn) SetDeadline(t time.Time) error      { return nil }
func (c dataStreamNetConn) SetReadDeadline(t time.Time) error  { return nil }
func (c dataStreamNetConn) SetWriteDeadline(t time.Time) error { return nil }

func (e *Engine) fetchRuleBundleBytes(ctx context.Context, targetURL string) ([]byte, error) {
	var lastErr error
	// Try over encrypted tunnel first when connected (GitHub is often blocked directly in CN).
	if e.IsConnected() {
		tr := &http.Transport{
			DisableKeepAlives: true,
			DialContext: func(dctx context.Context, network, addr string) (net.Conn, error) {
				st, err := e.TunnelStream(addr)
				if err != nil {
					return nil, err
				}
				return dataStreamNetConn{DataStream: st}, nil
			},
		}
		if b, err := httpGetBounded(ctx, tr, targetURL, maxRuleBundleBytes); err == nil {
			tr.CloseIdleConnections()
			return b, nil
		} else {
			tr.CloseIdleConnections()
			lastErr = err
		}
	}

	// Fallback: direct physical interface dialer (e.g., when user configured a reachable mirror URL).
	trDirect := &http.Transport{
		DisableKeepAlives: true,
		DialContext:       e.DirectDialContext,
	}
	b, err := httpGetBounded(ctx, trDirect, targetURL, maxRuleBundleBytes)
	trDirect.CloseIdleConnections()
	if err == nil {
		return b, nil
	}
	if lastErr != nil {
		return nil, fmt.Errorf("tunnel fetch failed (%v); direct fetch failed (%v)", lastErr, err)
	}
	return nil, err
}

func httpGetBounded(ctx context.Context, tr *http.Transport, rawURL string, maxBytes int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Kestrel-RuleProvider/"+Version)
	cli := &http.Client{Transport: tr, Timeout: 25 * time.Second}
	resp, err := cli.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http status %d from %s", resp.StatusCode, rawURL)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > maxBytes {
		return nil, fmt.Errorf("rule bundle exceeds max size (%d bytes)", maxBytes)
	}
	return b, nil
}

// UpdateRuleBundle downloads, verifies, persists, and hot-reloads rules_bundle.zlib with zero restart.
func (e *Engine) UpdateRuleBundle(ctx context.Context, rawURL string) (RuleStats, error) {
	u := strings.TrimSpace(rawURL)
	if u == "" {
		e.mu.RLock()
		u = strings.TrimSpace(e.config.RuleBundleURL)
		e.mu.RUnlock()
	}
	if u == "" {
		u = DefaultRuleBundleURL
	}
	if ctx == nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), 25*time.Second)
		defer cancel()
	}

	raw, err := e.fetchRuleBundleBytes(ctx, u)
	if err != nil {
		return e.router.Stats(), err
	}
	return e.ApplyRuleBundleBytes(raw)
}

// ApplyRuleBundleBytes validates raw rules_bundle.zlib bytes, writes them to disk if a data dir
// is configured, swaps the router's active zero-pointer hash bundle, and clears smart DNS cache.
func (e *Engine) ApplyRuleBundleBytes(raw []byte) (RuleStats, error) {
	nowUnix := time.Now().Unix()
	bundle, err := DecodeCompactRuleBundle(raw, "local", nowUnix)
	if err != nil {
		return e.router.Stats(), err
	}
	if bundle.TotalCount() == 0 {
		return e.router.Stats(), errors.New("rules: empty bundle")
	}

	if dir := e.RuleDataDir(); dir != "" {
		_ = os.MkdirAll(dir, 0o700)
		dst := filepath.Join(dir, ruleBundleFileName)
		tmp := dst + ".tmp"
		if werr := os.WriteFile(tmp, raw, 0o644); werr != nil {
			return e.router.Stats(), werr
		}
		if rerr := os.Rename(tmp, dst); rerr != nil {
			_ = os.Remove(tmp)
			return e.router.Stats(), rerr
		}
	}

	e.router.SetCompactBundle(bundle)
	if e.smartCache != nil {
		e.smartCache.Clear()
	}
	runtime.GC()
	st := e.router.Stats()
	e.Logf("[RuleSet] Hot-reloaded compact bundle: %d domains (proxy=%d, direct=%d)",
		st.BuiltinDomains, st.ProxyDomains, st.DirectDomains)
	return st, nil
}
