package client

import (
	"container/list"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"sync"
	"time"

	"ghostframe/internal/gft"
)

const (
	tunnelDNSCacheCap = 4096
	tunnelDNSMinTTL   = 60 * time.Second
	tunnelDNSMaxTTL   = 600 * time.Second
)

type tunnelDNSEntry struct {
	key     string
	v4      []net.IP
	v6      []net.IP
	expires time.Time
}

// TunnelDNSResolver resolves domains through the encrypted GhostFrame tunnel (1.1.1.1:53 / 8.8.8.8:53)
// with a bounded 4096-entry LRU cache (TTL clamped 60..600s) and zero local OS DNS queries.
type TunnelDNSResolver struct {
	mu      sync.Mutex
	cap     int
	lru     *list.List
	entries map[string]*list.Element
	servers []string
	nowFn   func() time.Time
}

// NewTunnelDNSResolver creates an encrypted tunnel DNS resolver with 4096-entry LRU capacity.
func NewTunnelDNSResolver() *TunnelDNSResolver {
	return &TunnelDNSResolver{
		cap:     tunnelDNSCacheCap,
		lru:     list.New(),
		entries: make(map[string]*list.Element, 256),
		servers: []string{"1.1.1.1:53", "8.8.8.8:53"},
		nowFn:   time.Now,
	}
}

func (r *TunnelDNSResolver) LookupCached(host string) (v4 []net.IP, v6 []net.IP, ok bool) {
	h := normalizeDNSHost(host)
	if h == "" {
		return nil, nil, false
	}
	now := r.nowFn()
	r.mu.Lock()
	defer r.mu.Unlock()
	el, exists := r.entries[h]
	if !exists {
		return nil, nil, false
	}
	ent := el.Value.(*tunnelDNSEntry)
	if now.After(ent.expires) {
		r.lru.Remove(el)
		delete(r.entries, h)
		return nil, nil, false
	}
	r.lru.MoveToFront(el)
	return append([]net.IP(nil), ent.v4...), append([]net.IP(nil), ent.v6...), true
}

func (r *TunnelDNSResolver) storeCached(host string, v4, v6 []net.IP, ttl time.Duration) {
	h := normalizeDNSHost(host)
	if h == "" || (len(v4) == 0 && len(v6) == 0) {
		return
	}
	ttl = clampDNSTTL(ttl)
	exp := r.nowFn().Add(ttl)

	r.mu.Lock()
	defer r.mu.Unlock()
	if el, exists := r.entries[h]; exists {
		ent := el.Value.(*tunnelDNSEntry)
		ent.v4 = append([]net.IP(nil), v4...)
		ent.v6 = append([]net.IP(nil), v6...)
		ent.expires = exp
		r.lru.MoveToFront(el)
		return
	}
	for r.lru.Len() >= r.cap {
		back := r.lru.Back()
		if back == nil {
			break
		}
		old := back.Value.(*tunnelDNSEntry)
		delete(r.entries, old.key)
		r.lru.Remove(back)
	}
	ent := &tunnelDNSEntry{
		key:     h,
		v4:      append([]net.IP(nil), v4...),
		v6:      append([]net.IP(nil), v6...),
		expires: exp,
	}
	el := r.lru.PushFront(ent)
	r.entries[h] = el
}

// Len returns current cached DNS entries.
func (r *TunnelDNSResolver) Len() int {
	r.mu.Lock()
	n := len(r.entries)
	r.mu.Unlock()
	return n
}

func clampDNSTTL(ttl time.Duration) time.Duration {
	if ttl < tunnelDNSMinTTL {
		return tunnelDNSMinTTL
	}
	if ttl > tunnelDNSMaxTTL {
		return tunnelDNSMaxTTL
	}
	return ttl
}

func normalizeDNSHost(host string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
}

// ResolveThroughTunnel resolves host via the encrypted tunnel UDP path without invoking OS local DNS.
func (r *TunnelDNSResolver) ResolveThroughTunnel(ctx context.Context, sched *gft.ApexScheduler, host string) ([]net.IP, []net.IP, error) {
	if ip := net.ParseIP(strings.Trim(strings.TrimSpace(host), "[]")); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return []net.IP{v4}, nil, nil
		}
		return nil, []net.IP{ip}, nil
	}
	h := normalizeDNSHost(host)
	if h == "" {
		return nil, nil, errors.New("dns: empty host")
	}
	if v4, v6, ok := r.LookupCached(h); ok {
		return v4, v6, nil
	}
	if sched == nil {
		return nil, nil, errors.New("dns: tunnel scheduler unavailable")
	}

	var idBuf [2]byte
	_, _ = rand.Read(idBuf[:])
	qid := binary.BigEndian.Uint16(idBuf[:])
	queryA, err := BuildDNSQuery(qid, h, 1)
	if err != nil {
		return nil, nil, err
	}

	assoc, err := sched.OpenUDP()
	if err != nil {
		return nil, nil, err
	}
	defer assoc.Close()

	var lastErr error
	for _, srv := range r.servers {
		if err := assoc.SendTo(srv, queryA); err != nil {
			lastErr = err
			continue
		}
		timer := time.NewTimer(2500 * time.Millisecond)
		for {
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil, nil, ctx.Err()
			case <-timer.C:
				lastErr = context.DeadlineExceeded
				goto nextServer
			case pkt, ok := <-assoc.Recv():
				if !ok {
					timer.Stop()
					lastErr = errors.New("dns: assoc closed")
					goto nextServer
				}
				if len(pkt.Data) >= 2 && binary.BigEndian.Uint16(pkt.Data[:2]) == qid {
					v4, v6, minTTL, okParse := ParseDNSResponse(pkt.Data)
					if okParse && (len(v4) > 0 || len(v6) > 0) {
						timer.Stop()
						r.storeCached(h, v4, v6, minTTL)
						return v4, v6, nil
					}
				}
			}
		}
	nextServer:
	}
	if lastErr == nil {
		lastErr = errors.New("dns: no tunnel answer")
	}
	return nil, nil, lastErr
}

// BuildDNSQuery builds an RFC 1035 wire query packet (RD=1) for QNAME and QTYPE.
func BuildDNSQuery(id uint16, host string, qtype uint16) ([]byte, error) {
	h := normalizeDNSHost(host)
	if h == "" || len(h) > 253 {
		return nil, errors.New("dns: invalid host")
	}
	labels := strings.Split(h, ".")
	buf := make([]byte, 12, 64)
	binary.BigEndian.PutUint16(buf[0:2], id)
	binary.BigEndian.PutUint16(buf[2:4], 0x0100) // standard query, recursion desired
	binary.BigEndian.PutUint16(buf[4:6], 1)      // QDCOUNT=1
	for _, lb := range labels {
		if len(lb) == 0 || len(lb) > 63 {
			return nil, errors.New("dns: invalid label")
		}
		buf = append(buf, byte(len(lb)))
		buf = append(buf, lb...)
	}
	buf = append(buf, 0) // root terminator
	buf = binary.BigEndian.AppendUint16(buf, qtype)
	buf = binary.BigEndian.AppendUint16(buf, 1) // IN class
	return buf, nil
}

// ParseDNSResponse safely parses A/AAAA answers from an RFC 1035 DNS packet with loop guards.
func ParseDNSResponse(pkt []byte) (v4 []net.IP, v6 []net.IP, minTTL time.Duration, ok bool) {
	if len(pkt) < 12 {
		return nil, nil, 0, false
	}
	flags := binary.BigEndian.Uint16(pkt[2:4])
	if flags&0x8000 == 0 { // must be QR=1 response
		return nil, nil, 0, false
	}
	rcode := flags & 0x000F
	if rcode != 0 {
		return nil, nil, 0, false
	}
	qdCount := int(binary.BigEndian.Uint16(pkt[4:6]))
	anCount := int(binary.BigEndian.Uint16(pkt[6:8]))
	if qdCount > 16 || anCount > 64 {
		return nil, nil, 0, false
	}
	off := 12
	for i := 0; i < qdCount; i++ {
		next, okName := skipDNSName(pkt, off)
		if !okName || next+4 > len(pkt) {
			return nil, nil, 0, false
		}
		off = next + 4
	}
	minTTL = tunnelDNSMaxTTL
	hasTTL := false
	for i := 0; i < anCount; i++ {
		next, okName := skipDNSName(pkt, off)
		if !okName || next+10 > len(pkt) {
			break
		}
		rtype := binary.BigEndian.Uint16(pkt[next : next+2])
		rclass := binary.BigEndian.Uint16(pkt[next+2 : next+4])
		ttlSec := binary.BigEndian.Uint32(pkt[next+4 : next+8])
		rdLen := int(binary.BigEndian.Uint16(pkt[next+8 : next+10]))
		rdataOff := next + 10
		if rdataOff+rdLen > len(pkt) {
			break
		}
		if rclass == 1 {
			d := time.Duration(ttlSec) * time.Second
			switch {
			case rtype == 1 && rdLen == 4:
				ip := make(net.IP, 4)
				copy(ip, pkt[rdataOff:rdataOff+4])
				v4 = append(v4, ip)
				if !hasTTL || d < minTTL {
					minTTL = d
					hasTTL = true
				}
			case rtype == 28 && rdLen == 16:
				ip := make(net.IP, 16)
				copy(ip, pkt[rdataOff:rdataOff+16])
				v6 = append(v6, ip)
				if !hasTTL || d < minTTL {
					minTTL = d
					hasTTL = true
				}
			}
		}
		off = rdataOff + rdLen
	}
	if !hasTTL {
		minTTL = tunnelDNSMinTTL
	} else {
		minTTL = clampDNSTTL(minTTL)
	}
	return v4, v6, minTTL, len(v4) > 0 || len(v6) > 0
}

func skipDNSName(pkt []byte, off int) (int, bool) {
	n := len(pkt)
	cur := off
	jumps := 0
	for cur < n {
		l := int(pkt[cur])
		if l == 0 {
			return cur + 1, true
		}
		if l&0xC0 == 0xC0 {
			if cur+2 > n || jumps > 8 {
				return 0, false
			}
			// Do not follow pointers linearly here for field advance; pointer ends QNAME/NAME field.
			return cur + 2, true
		}
		if l&0xC0 != 0 || l > 63 || cur+1+l > n || jumps > 64 {
			return 0, false
		}
		cur += 1 + l
		jumps++
	}
	return 0, false
}
