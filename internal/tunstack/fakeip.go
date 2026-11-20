package tunstack

import (
	"encoding/binary"
	"net"
	"strings"
	"sync"
)

const (
	// FakeIPBase is the start of the benchmark/TUN fake-IP pool (198.18.1.1).
	// 198.18.0.1 is reserved for the TUN virtual DNS gateway and 198.18.0.2 for the local TUN interface.
	fakeIPStart = (198 << 24) | (18 << 16) | (1 << 8) | 1
	fakeIPEnd   = (198 << 24) | (18 << 16) | (254 << 8) | 254
)

// FakeIPPool is a fixed-capacity ring-buffer mapping between queried hostnames and 198.18.x.x IPv4s.
type FakeIPPool struct {
	mu       sync.RWMutex
	cap      int
	nextOff  uint32
	ipToHost map[uint32]string
	hostToIP map[string]uint32
	ring     []uint32
	ringPos  int
}

// NewFakeIPPool constructs a bounded Fake-IP pool (safe for iOS 50MB NetworkExtension cap).
func NewFakeIPPool(capacity int) *FakeIPPool {
	if capacity <= 0 {
		capacity = 4096
	}
	maxSpan := int(fakeIPEnd - fakeIPStart + 1)
	if capacity > maxSpan {
		capacity = maxSpan
	}
	return &FakeIPPool{
		cap:      capacity,
		ipToHost: make(map[uint32]string, capacity/4),
		hostToIP: make(map[string]uint32, capacity/4),
		ring:     make([]uint32, capacity),
	}
}

// IsFakeIP reports whether ip falls inside 198.18.0.0/16.
func IsFakeIP(ip net.IP) bool {
	ip4 := ip.To4()
	return ip4 != nil && ip4[0] == 198 && ip4[1] == 18
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
	return uint32ToIPv4(ipU32)
}

// Lookup resolves a Fake-IP back to its original queried domain name.
func (p *FakeIPPool) Lookup(ip net.IP) (string, bool) {
	ip4 := ip.To4()
	if ip4 == nil || ip4[0] != 198 || ip4[1] != 18 {
		return "", false
	}
	u := binary.BigEndian.Uint32(ip4)
	p.mu.RLock()
	host, ok := p.ipToHost[u]
	p.mu.RUnlock()
	return host, ok
}

// Size returns the number of active Fake-IP entries.
func (p *FakeIPPool) Size() int {
	p.mu.RLock()
	n := len(p.ipToHost)
	p.mu.RUnlock()
	return n
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
// - Type A (1): returns an allocated 198.18.x.x A record (TTL=5s).
// - Type AAAA (28) / HTTPS (65) / SVCB (64) / other: returns NOERROR with 0 answers
//   so iOS clients cleanly fall back to IPv4 Fake-IP without IPv6/QUIC leaks.
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

	wantAnswer := qtype == 1 && qclass == 1 && name != ""
	var fakeIP [4]byte
	if wantAnswer {
		if ip := net.ParseIP(name); ip != nil && ip.To4() != nil {
			copy(fakeIP[:], ip.To4())
		} else {
			fakeIP = p.Allocate(name)
		}
	}

	respCap := qEnd
	if wantAnswer {
		respCap += 16
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

	if wantAnswer {
		// Compressed pointer to QNAME at offset 12 (0xC00C), Type A, Class IN, TTL 5s, RDLENGTH 4.
		var ans [16]byte
		ans[0] = 0xC0
		ans[1] = 0x0C
		binary.BigEndian.PutUint16(ans[2:4], 1)  // TYPE A
		binary.BigEndian.PutUint16(ans[4:6], 1)  // CLASS IN
		binary.BigEndian.PutUint32(ans[6:10], 5) // TTL 5s
		binary.BigEndian.PutUint16(ans[10:12], 4)
		copy(ans[12:16], fakeIP[:])
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
