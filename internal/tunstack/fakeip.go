package tunstack

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// FakeIPBase is the start of the benchmark/TUN fake-IP pool (198.18.1.1).
	// 198.18.0.1 is reserved for the TUN virtual DNS gateway and 198.18.0.2 for the local TUN interface.
	fakeIPStart = (198 << 24) | (18 << 16) | (1 << 8) | 1
	fakeIPEnd   = (198 << 24) | (18 << 16) | (254 << 8) | 254

	// Short 2s TTL guarantees apps re-resolve cleanly if PacketTunnel restarts or wakes from deep sleep.
	fakeIPDNSTTL uint32 = 2

	fakeCacheMagic   = "GFIP"
	fakeCacheVersion = 1
)

// FakeIPPool is a fixed-capacity ring-buffer mapping between queried hostnames and 198.18.x.x IPv4s,
// with optional atomic binary persistence so iOS OnDemand/sleep restarts preserve active Fake-IP mappings.
type FakeIPPool struct {
	mu       sync.RWMutex
	cap      int
	nextOff  uint32
	ipToHost map[uint32]string
	hostToIP map[string]uint32
	ring     []uint32
	ringPos  int

	nextOff6  uint64
	ip6ToHost map[uint64]string
	hostToIP6 map[string]uint64
	ring6     []uint64
	ring6Pos  int

	ipv6Enabled atomic.Bool
	cachePath   string
	dirty       bool
	stopCh      chan struct{}
	closeOnce   sync.Once
}

// NewFakeIPPool constructs an in-memory bounded Fake-IP pool (safe for iOS 50MB NetworkExtension cap).
func NewFakeIPPool(capacity int) *FakeIPPool {
	return NewFakeIPPoolWithPersistence(capacity, "")
}

// NewFakeIPPoolWithPersistence constructs a bounded Fake-IP pool that loads/saves mappings to cachePath.
func NewFakeIPPoolWithPersistence(capacity int, cachePath string) *FakeIPPool {
	if capacity <= 0 {
		capacity = 4096
	}
	maxSpan := int(fakeIPEnd - fakeIPStart + 1)
	if capacity > maxSpan {
		capacity = maxSpan
	}
	p := &FakeIPPool{
		cap:       capacity,
		ipToHost:  make(map[uint32]string, capacity/4),
		hostToIP:  make(map[string]uint32, capacity/4),
		ring:      make([]uint32, capacity),
		ip6ToHost: make(map[uint64]string, capacity/8),
		hostToIP6: make(map[string]uint64, capacity/8),
		ring6:     make([]uint64, capacity),
		cachePath: strings.TrimSpace(cachePath),
	}
	if p.cachePath != "" {
		_ = p.loadFromFile(p.cachePath)
		p.stopCh = make(chan struct{})
		go p.flushLoop()
	}
	return p
}

// SetIPv6Enabled toggles whether DNS AAAA queries receive Fake-IPv6 (fd18:c612::/64) answers or NODATA.
func (p *FakeIPPool) SetIPv6Enabled(on bool) {
	p.ipv6Enabled.Store(on)
}

// IPv6Enabled reports whether Fake-IPv6 AAAA allocation is currently enabled.
func (p *FakeIPPool) IPv6Enabled() bool {
	return p.ipv6Enabled.Load()
}

// Close flushes any dirty Fake-IP mappings to disk and stops background persistence.
func (p *FakeIPPool) Close() {
	p.closeOnce.Do(func() {
		if p.stopCh != nil {
			close(p.stopCh)
		}
		if p.cachePath != "" {
			_ = p.Flush()
		}
	})
}

func (p *FakeIPPool) flushLoop() {
	t := time.NewTicker(3 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-p.stopCh:
			return
		case <-t.C:
			_ = p.Flush()
		}
	}
}

// IsFakeIP reports whether ip falls inside 198.18.0.0/16 or fd18:c612::/64.
func IsFakeIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip4 := ip.To4(); ip4 != nil {
		return ip4[0] == 198 && ip4[1] == 18
	}
	return isFakeIPv6Slice(ip.To16())
}

func isFakeIPv6Slice(ip16 net.IP) bool {
	return len(ip16) == 16 &&
		ip16[0] == 0xfd && ip16[1] == 0x18 &&
		ip16[2] == 0xc6 && ip16[3] == 0x12 &&
		ip16[4] == 0 && ip16[5] == 0 &&
		ip16[6] == 0 && ip16[7] == 0
}

func suffixToFakeIPv6(sfx uint64) [16]byte {
	var b [16]byte
	b[0], b[1], b[2], b[3] = 0xfd, 0x18, 0xc6, 0x12
	binary.BigEndian.PutUint64(b[8:16], sfx)
	return b
}

// Allocate6 returns an existing or newly assigned fd18:c612::/64 Fake-IPv6 address for domain.
func (p *FakeIPPool) Allocate6(domain string) [16]byte {
	host := normalizeDomain(domain)
	p.mu.Lock()
	defer p.mu.Unlock()

	if sfx, ok := p.hostToIP6[host]; ok {
		return suffixToFakeIPv6(sfx)
	}

	if oldSfx := p.ring6[p.ring6Pos]; oldSfx != 0 {
		if oldHost, exists := p.ip6ToHost[oldSfx]; exists {
			delete(p.hostToIP6, oldHost)
			delete(p.ip6ToHost, oldSfx)
		}
	}

	// Reserve fd18:c612::1 (DNS gateway) and fd18:c612::2 (TUN local interface).
	sfx := 3 + (p.nextOff6 % 65000)
	p.nextOff6++
	if prevHost, exists := p.ip6ToHost[sfx]; exists {
		delete(p.hostToIP6, prevHost)
	}

	p.ip6ToHost[sfx] = host
	p.hostToIP6[host] = sfx
	p.ring6[p.ring6Pos] = sfx
	p.ring6Pos = (p.ring6Pos + 1) % len(p.ring6)
	return suffixToFakeIPv6(sfx)
}

// Allocate returns an existing or newly assigned 198.18.x.x IPv4 for domain.
func (p *FakeIPPool) Allocate(domain string) [4]byte {
	host := normalizeDomain(domain)
	p.mu.Lock()
	defer p.mu.Unlock()

	if u, ok := p.hostToIP[host]; ok {
		return uint32ToIPv4(u)
	}

	// Evict oldest slot if ring position is already occupied.
	if oldIP := p.ring[p.ringPos]; oldIP != 0 {
		if oldHost, exists := p.ipToHost[oldIP]; exists {
			delete(p.hostToIP, oldHost)
			delete(p.ipToHost, oldIP)
		}
	}

	span := uint32(fakeIPEnd - fakeIPStart + 1)
	ipU32 := fakeIPStart + (p.nextOff % span)
	p.nextOff++

	// Clean any stale mapping if cursor wrapped around.
	if prevHost, exists := p.ipToHost[ipU32]; exists {
		delete(p.hostToIP, prevHost)
	}

	p.ipToHost[ipU32] = host
	p.hostToIP[host] = ipU32
	p.ring[p.ringPos] = ipU32
	p.ringPos = (p.ringPos + 1) % p.cap
	p.dirty = true
	return uint32ToIPv4(ipU32)
}

// Lookup resolves a Fake-IP (IPv4 or IPv6) back to its original queried domain name.
func (p *FakeIPPool) Lookup(ip net.IP) (string, bool) {
	if ip == nil {
		return "", false
	}
	if ip4 := ip.To4(); ip4 != nil {
		if ip4[0] != 198 || ip4[1] != 18 {
			return "", false
		}
		u := binary.BigEndian.Uint32(ip4)
		p.mu.RLock()
		host, ok := p.ipToHost[u]
		p.mu.RUnlock()
		return host, ok
	}
	ip16 := ip.To16()
	if !isFakeIPv6Slice(ip16) {
		return "", false
	}
	sfx := binary.BigEndian.Uint64(ip16[8:16])
	p.mu.RLock()
	host, ok := p.ip6ToHost[sfx]
	p.mu.RUnlock()
	return host, ok
}

// Size returns the number of active Fake-IP entries.
func (p *FakeIPPool) Size() int {
	p.mu.RLock()
	n := len(p.ipToHost) + len(p.ip6ToHost)
	p.mu.RUnlock()
	return n
}

// Flush persists the current Fake-IP table to cachePath atomically if modified.
func (p *FakeIPPool) Flush() error {
	if p.cachePath == "" {
		return nil
	}

	p.mu.Lock()
	if !p.dirty {
		p.mu.Unlock()
		return nil
	}

	var raw bytes.Buffer
	var hdr [13]byte
	copy(hdr[0:4], fakeCacheMagic)
	hdr[4] = fakeCacheVersion
	binary.BigEndian.PutUint32(hdr[5:9], p.nextOff)
	binary.BigEndian.PutUint32(hdr[9:13], uint32(len(p.ring)))
	raw.Write(hdr[:])

	// Preserve chronological ring order up to capacity.
	written := 0
	var countBuf [4]byte
	entriesStart := raw.Len()
	raw.Write(countBuf[:]) // placeholder for exact entry count

	for step := 0; step < len(p.ring); step++ {
		idx := (p.ringPos + step) % len(p.ring)
		ipU32 := p.ring[idx]
		if ipU32 == 0 {
			continue
		}
		host, ok := p.ipToHost[ipU32]
		if !ok || host == "" || len(host) > 1024 {
			continue
		}
		var rec [6]byte
		binary.BigEndian.PutUint32(rec[0:4], ipU32)
		binary.BigEndian.PutUint16(rec[4:6], uint16(len(host)))
		raw.Write(rec[:])
		raw.WriteString(host)
		written++
	}
	p.dirty = false
	p.mu.Unlock()

	rawBytes := raw.Bytes()
	binary.BigEndian.PutUint32(rawBytes[entriesStart:entriesStart+4], uint32(written))

	dir := filepath.Dir(p.cachePath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	var payload []byte
	if strings.HasSuffix(strings.ToLower(p.cachePath), ".json") {
		type jsonCacheEntry struct {
			IP     string `json:"ip"`
			Domain string `json:"domain"`
		}
		type jsonCacheFile struct {
			NextOff uint32           `json:"next_off"`
			Entries []jsonCacheEntry `json:"entries"`
		}
		var recs []jsonCacheEntry
		pos := 17
		cnt := int(binary.BigEndian.Uint32(rawBytes[13:17]))
		for i := 0; i < cnt && pos+6 <= len(rawBytes); i++ {
			u := binary.BigEndian.Uint32(rawBytes[pos : pos+4])
			hl := int(binary.BigEndian.Uint16(rawBytes[pos+4 : pos+6]))
			pos += 6
			if hl <= 0 || pos+hl > len(rawBytes) {
				break
			}
			b4 := uint32ToIPv4(u)
			recs = append(recs, jsonCacheEntry{
				IP:     net.IPv4(b4[0], b4[1], b4[2], b4[3]).String(),
				Domain: string(rawBytes[pos : pos+hl]),
			})
			pos += hl
		}
		b, merr := json.Marshal(jsonCacheFile{
			NextOff: binary.BigEndian.Uint32(rawBytes[5:9]),
			Entries: recs,
		})
		if merr != nil {
			return merr
		}
		payload = b
	} else {
		var comp bytes.Buffer
		zw := zlib.NewWriter(&comp)
		if _, err := zw.Write(rawBytes); err != nil {
			_ = zw.Close()
			return err
		}
		if err := zw.Close(); err != nil {
			return err
		}
		payload = comp.Bytes()
	}

	tmp := p.cachePath + ".tmp"
	if err := os.WriteFile(tmp, payload, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p.cachePath)
}

func (p *FakeIPPool) loadFromFile(path string) error {
	rawFile, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if strings.HasSuffix(strings.ToLower(path), ".json") {
		var jc struct {
			NextOff uint32 `json:"next_off"`
			Entries []struct {
				IP     string `json:"ip"`
				Domain string `json:"domain"`
			} `json:"entries"`
		}
		if jerr := json.Unmarshal(rawFile, &jc); jerr == nil && len(jc.Entries) > 0 {
			p.mu.Lock()
			p.nextOff = jc.NextOff
			p.ipToHost = make(map[uint32]string, p.cap/4)
			p.hostToIP = make(map[string]uint32, p.cap/4)
			p.ring = make([]uint32, p.cap)
			p.ringPos = 0
			for _, ent := range jc.Entries {
				ip4 := net.ParseIP(ent.IP).To4()
				host := normalizeDomain(ent.Domain)
				if ip4 == nil || host == "" {
					continue
				}
				ipU32 := binary.BigEndian.Uint32(ip4)
				if ipU32 < fakeIPStart || ipU32 > fakeIPEnd {
					continue
				}
				if oldIP := p.ring[p.ringPos]; oldIP != 0 {
					if oh, exists := p.ipToHost[oldIP]; exists {
						delete(p.hostToIP, oh)
						delete(p.ipToHost, oldIP)
					}
				}
				if prevHost, exists := p.ipToHost[ipU32]; exists {
					delete(p.hostToIP, prevHost)
				}
				p.ipToHost[ipU32] = host
				p.hostToIP[host] = ipU32
				p.ring[p.ringPos] = ipU32
				p.ringPos = (p.ringPos + 1) % p.cap
			}
			p.dirty = false
			p.mu.Unlock()
			return nil
		}
	}
	zr, err := zlib.NewReader(bytes.NewReader(rawFile))
	if err != nil {
		return err
	}
	defer zr.Close()
	data, err := io.ReadAll(io.LimitReader(zr, 4<<20))
	if err != nil {
		return err
	}
	if len(data) < 17 || string(data[0:4]) != fakeCacheMagic || data[4] != fakeCacheVersion {
		return errors.New("tunstack: invalid fakeip cache header")
	}

	nextOff := binary.BigEndian.Uint32(data[5:9])
	entryCount := int(binary.BigEndian.Uint32(data[13:17]))
	pos := 17

	p.mu.Lock()
	defer p.mu.Unlock()

	p.nextOff = nextOff
	p.ipToHost = make(map[uint32]string, p.cap/4)
	p.hostToIP = make(map[string]uint32, p.cap/4)
	p.ring = make([]uint32, p.cap)
	p.ringPos = 0

	for i := 0; i < entryCount && pos+6 <= len(data); i++ {
		ipU32 := binary.BigEndian.Uint32(data[pos : pos+4])
		hLen := int(binary.BigEndian.Uint16(data[pos+4 : pos+6]))
		pos += 6
		if hLen <= 0 || pos+hLen > len(data) {
			break
		}
		if ipU32 >= fakeIPStart && ipU32 <= fakeIPEnd {
			host := normalizeDomain(string(data[pos : pos+hLen]))
			if host != "" {
				if oldIP := p.ring[p.ringPos]; oldIP != 0 {
					if oh, exists := p.ipToHost[oldIP]; exists {
						delete(p.hostToIP, oh)
						delete(p.ipToHost, oldIP)
					}
				}
				if prevHost, exists := p.ipToHost[ipU32]; exists {
					delete(p.hostToIP, prevHost)
				}
				p.ipToHost[ipU32] = host
				p.hostToIP[host] = ipU32
				p.ring[p.ringPos] = ipU32
				p.ringPos = (p.ringPos + 1) % p.cap
			}
		}
		pos += hLen
	}
	p.dirty = false
	return nil
}

func normalizeDomain(d string) string {
	d = strings.TrimSpace(strings.ToLower(d))
	return strings.TrimSuffix(d, ".")
}

func uint32ToIPv4(u uint32) [4]byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], u)
	return b
}

// HandleDNSQuery parses a raw RFC 1035 UDP DNS query and returns a Fake-IP response.
// - Type A (1): returns an allocated 198.18.x.x A record (TTL=2s).
// - Type AAAA (28) / HTTPS (65) / SVCB (64) / other: returns NOERROR (RCODE=0) with 0 answers (NODATA)
//   so dual-stack iOS clients immediately fall back to IPv4 Fake-IP without IPv6/QUIC leaks or NXDOMAIN stalls.
func (p *FakeIPPool) HandleDNSQuery(query []byte) ([]byte, bool) {
	if len(query) < 12 {
		return nil, false
	}
	qdCount := binary.BigEndian.Uint16(query[4:6])
	if qdCount == 0 {
		return nil, false
	}

	name, nextOff, ok := parseDNSName(query, 12)
	if !ok || nextOff+4 > len(query) {
		return nil, false
	}
	qtype := binary.BigEndian.Uint16(query[nextOff : nextOff+2])
	qclass := binary.BigEndian.Uint16(query[nextOff+2 : nextOff+4])
	qEnd := nextOff + 4

	// Build response header: QR=1, copy Opcode/RD, RA=1, RCODE=0 (NOERROR).
	reqFlags := binary.BigEndian.Uint16(query[2:4])
	respFlags := uint16(0x8080) | (reqFlags & 0x7900) // QR=1, RA=1, preserve Opcode+RD

	wantA := qtype == 1 && qclass == 1 && name != ""
	wantAAAA := qtype == 28 && qclass == 1 && name != "" && p.IPv6Enabled()
	wantAnswer := wantA || wantAAAA
	var fakeIP [4]byte
	var fakeIP6 [16]byte
	if wantA {
		if ip := net.ParseIP(name); ip != nil && ip.To4() != nil {
			copy(fakeIP[:], ip.To4())
		} else {
			fakeIP = p.Allocate(name)
		}
	} else if wantAAAA {
		if ip := net.ParseIP(strings.Trim(name, "[]")); ip != nil && ip.To4() == nil && ip.To16() != nil {
			copy(fakeIP6[:], ip.To16())
		} else {
			fakeIP6 = p.Allocate6(name)
		}
	}

	respCap := qEnd
	if wantA {
		respCap += 16
	} else if wantAAAA {
		respCap += 28
	}
	resp := make([]byte, qEnd, respCap)
	copy(resp[:qEnd], query[:qEnd])
	binary.BigEndian.PutUint16(resp[2:4], respFlags)
	binary.BigEndian.PutUint16(resp[4:6], 1) // QDCOUNT=1
	if wantAnswer {
		binary.BigEndian.PutUint16(resp[6:8], 1) // ANCOUNT=1
	} else {
		binary.BigEndian.PutUint16(resp[6:8], 0)
	}
	binary.BigEndian.PutUint16(resp[8:10], 0)  // NSCOUNT=0
	binary.BigEndian.PutUint16(resp[10:12], 0) // ARCOUNT=0

	if wantA {
		// Compressed pointer to QNAME at offset 12 (0xC00C), Type A, Class IN, TTL 2s, RDLENGTH 4.
		var ans [16]byte
		ans[0] = 0xC0
		ans[1] = 0x0C
		binary.BigEndian.PutUint16(ans[2:4], 1)            // TYPE A
		binary.BigEndian.PutUint16(ans[4:6], 1)            // CLASS IN
		binary.BigEndian.PutUint32(ans[6:10], fakeIPDNSTTL) // TTL 2s
		binary.BigEndian.PutUint16(ans[10:12], 4)
		copy(ans[12:16], fakeIP[:])
		resp = append(resp, ans[:]...)
	} else if wantAAAA {
		// Compressed pointer to QNAME at offset 12 (0xC00C), Type AAAA (28), Class IN, TTL 2s, RDLENGTH 16.
		var ans [28]byte
		ans[0] = 0xC0
		ans[1] = 0x0C
		binary.BigEndian.PutUint16(ans[2:4], 28)           // TYPE AAAA
		binary.BigEndian.PutUint16(ans[4:6], 1)            // CLASS IN
		binary.BigEndian.PutUint32(ans[6:10], fakeIPDNSTTL) // TTL 2s
		binary.BigEndian.PutUint16(ans[10:12], 16)
		copy(ans[12:28], fakeIP6[:])
		resp = append(resp, ans[:]...)
	}

	return resp, true
}

func parseDNSName(msg []byte, offset int) (string, int, bool) {
	if offset >= len(msg) {
		return "", 0, false
	}
	var b strings.Builder
	pos := offset
	jumps := 0
	endPos := 0
	jumped := false

	for pos < len(msg) {
		l := int(msg[pos])
		if l == 0 {
			if !jumped {
				endPos = pos + 1
			}
			return b.String(), endPos, true
		}
		if l&0xC0 == 0xC0 {
			if pos+1 >= len(msg) {
				return "", 0, false
			}
			ptr := int(binary.BigEndian.Uint16(msg[pos:pos+2]) & 0x3FFF)
			if !jumped {
				endPos = pos + 2
				jumped = true
			}
			pos = ptr
			jumps++
			if jumps > 8 {
				return "", 0, false
			}
			continue
		}
		if l > 63 || pos+1+l > len(msg) {
			return "", 0, false
		}
		if b.Len() > 0 {
			b.WriteByte('.')
		}
		b.Write(msg[pos+1 : pos+1+l])
		pos += 1 + l
	}
	return "", 0, false
}
