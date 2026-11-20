package tproxy

import (
	"container/list"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"ghostframe/internal/client"
	"ghostframe/internal/netbind"
)

const (
	dnsCacheCap    = 1024
	dnsCacheMinTTL = 30 * time.Second
	dnsCacheMaxTTL = 300 * time.Second
)

type dnsCacheItem struct {
	key     string
	resp    []byte
	expires time.Time
}

// SplitDNSServer serves non-leaking UDP + TCP DNS for side-router transparent mode.
// Domestic / LAN domains query direct CN DNS over SO_MARK sockets; overseas domains
// always resolve through the encrypted GhostFrame tunnel with zero local fallback.
type SplitDNSServer struct {
	addr       string
	engine     *client.Engine
	modeFn     func() GatewayMode
	directMu   sync.RWMutex
	directDNS  []string
	filterAAAA atomic.Bool

	udpConn *net.UDPConn
	tcpLn   net.Listener
	closed  chan struct{}
	closeMu sync.Mutex

	cacheMu sync.Mutex
	lru     *list.List
	entries map[string]*list.Element

	queries    atomic.Uint64
	directHits atomic.Uint64
	tunnelHits atomic.Uint64
	rejectHits atomic.Uint64
}

// NewSplitDNSServer constructs a split-tunnel DNS responder bound to addr (e.g. "127.0.0.1:7853").
func NewSplitDNSServer(addr string, eng *client.Engine, directDNS []string, filterAAAA bool, modeFn func() GatewayMode) *SplitDNSServer {
	s := &SplitDNSServer{
		addr:      addr,
		engine:    eng,
		modeFn:    modeFn,
		directDNS: normalizeDNSServers(directDNS),
		closed:    make(chan struct{}),
		lru:       list.New(),
		entries:   make(map[string]*list.Element, 256),
	}
	s.filterAAAA.Store(filterAAAA)
	return s
}

func normalizeDNSServers(listIn []string) []string {
	seen := make(map[string]struct{})
	var out []string
	add := func(raw string) {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return
		}
		if _, _, err := net.SplitHostPort(raw); err != nil {
			raw = net.JoinHostPort(raw, "53")
		}
		if _, ok := seen[raw]; !ok {
			seen[raw] = struct{}{}
			out = append(out, raw)
		}
	}
	for _, item := range listIn {
		add(item)
	}
	add("223.5.5.5:53")
	add("119.29.29.29:53")
	return out
}

// UpdateConfig hot-updates direct upstream resolvers and AAAA filtering.
func (s *SplitDNSServer) UpdateConfig(directDNS []string, filterAAAA bool) {
	s.directMu.Lock()
	s.directDNS = normalizeDNSServers(directDNS)
	s.directMu.Unlock()
	s.filterAAAA.Store(filterAAAA)
}

// Start begins serving both UDP and TCP DNS queries on s.addr.
func (s *SplitDNSServer) Start() error {
	uAddr, err := net.ResolveUDPAddr("udp", s.addr)
	if err != nil {
		return err
	}
	uc, err := net.ListenUDP("udp", uAddr)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		_ = uc.Close()
		return err
	}
	s.udpConn = uc
	s.tcpLn = ln

	go s.serveUDP(uc)
	go s.serveTCP(ln)
	return nil
}

// Addr returns the listening UDP address.
func (s *SplitDNSServer) Addr() net.Addr {
	if s.udpConn != nil {
		return s.udpConn.LocalAddr()
	}
	return nil
}

// Close shuts down both UDP and TCP DNS listeners.
func (s *SplitDNSServer) Close() {
	s.closeMu.Lock()
	defer s.closeMu.Unlock()
	select {
	case <-s.closed:
		return
	default:
		close(s.closed)
	}
	if s.udpConn != nil {
		_ = s.udpConn.Close()
	}
	if s.tcpLn != nil {
		_ = s.tcpLn.Close()
	}
}

// Counters returns (queries, directHits, tunnelHits, rejectHits).
func (s *SplitDNSServer) Counters() (uint64, uint64, uint64, uint64) {
	return s.queries.Load(), s.directHits.Load(), s.tunnelHits.Load(), s.rejectHits.Load()
}

func (s *SplitDNSServer) serveUDP(uc *net.UDPConn) {
	buf := make([]byte, 4096)
	sem := make(chan struct{}, 128)
	for {
		n, raddr, err := uc.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-s.closed:
				return
			default:
				continue
			}
		}
		select {
		case sem <- struct{}{}:
		default:
			continue
		}
		req := make([]byte, n)
		copy(req, buf[:n])
		go func(pkt []byte, peer *net.UDPAddr) {
			defer func() { <-sem }()
			resp := s.HandlePacket(pkt)
			if len(resp) > 0 {
				_, _ = uc.WriteToUDP(resp, peer)
			}
		}(req, raddr)
	}
}

func (s *SplitDNSServer) serveTCP(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			select {
			case <-s.closed:
				return
			default:
				time.Sleep(20 * time.Millisecond)
				continue
			}
		}
		go s.handleTCPConn(c)
	}
}

func (s *SplitDNSServer) handleTCPConn(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	var lenBuf [2]byte
	if _, err := io.ReadFull(c, lenBuf[:]); err != nil {
		return
	}
	qLen := int(binary.BigEndian.Uint16(lenBuf[:]))
	if qLen < 12 || qLen > 4096 {
		return
	}
	req := make([]byte, qLen)
	if _, err := io.ReadFull(c, req); err != nil {
		return
	}
	resp := s.HandlePacket(req)
	if len(resp) == 0 {
		return
	}
	out := make([]byte, 2+len(resp))
	binary.BigEndian.PutUint16(out[:2], uint16(len(resp)))
	copy(out[2:], resp)
	_, _ = c.Write(out)
}

// HandlePacket routes a single wire DNS query packet according to RuleSet & GatewayMode.
func (s *SplitDNSServer) HandlePacket(req []byte) []byte {
	qname, qtype, qEnd, ok := parseDNSQuestion(req)
	if !ok {
		return buildRCodeResponse(req, len(req), 1) // FORMERR
	}
	s.queries.Add(1)

	if s.filterAAAA.Load() && qtype == 28 {
		return buildRCodeResponse(req, qEnd, 0) // NOERROR empty AAAA
	}

	gwMode := ModeRule
	if s.modeFn != nil {
		gwMode = s.modeFn()
	}

	var act client.RouteAction
	var smartWireResp []byte
	if gwMode == ModeGlobal {
		if isLocalDomain(qname) {
			act = client.ActionDirect
		} else {
			act = client.ActionProxy
		}
	} else {
		act, smartWireResp, _ = s.engine.ResolveSmartDNS(client.RouteRule, qname, req[:2])
	}

	switch act {
	case client.ActionReject:
		s.rejectHits.Add(1)
		return buildRCodeResponse(req, qEnd, 3) // NXDOMAIN

	case client.ActionDirect:
		s.directHits.Add(1)
		cacheKey := fmt.Sprintf("D:%d:%s", qtype, qname)
		if cached, hit := s.cacheGet(cacheKey, req[:2]); hit {
			return cached
		}
		if qtype == 1 && len(smartWireResp) >= 12 {
			s.cachePut(cacheKey, smartWireResp, dnsCacheMinTTL)
			return smartWireResp
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		resp, err := s.queryDirectConcurrent(ctx, req, isLocalDomain(qname))
		cancel()
		if err != nil || len(resp) < 12 {
			return buildRCodeResponse(req, qEnd, 2) // SERVFAIL
		}
		s.cachePut(cacheKey, resp, dnsCacheMinTTL)
		return resp

	default:
		s.tunnelHits.Add(1)
		cacheKey := fmt.Sprintf("P:%d:%s", qtype, qname)
		if cached, hit := s.cacheGet(cacheKey, req[:2]); hit {
			return cached
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		resp, err := s.engine.ForwardRawDNSThroughTunnel(ctx, req)
		cancel()
		if err != nil || len(resp) < 12 {
			return buildRCodeResponse(req, qEnd, 2) // SERVFAIL (never leak to local ISP DNS)
		}
		s.cachePut(cacheKey, resp, 120*time.Second)
		return resp
	}
}

func (s *SplitDNSServer) queryDirectConcurrent(ctx context.Context, req []byte, localOnly bool) ([]byte, error) {
	s.directMu.RLock()
	servers := append([]string(nil), s.directDNS...)
	s.directMu.RUnlock()
	if len(servers) == 0 {
		return nil, errors.New("no direct DNS server configured")
	}
	if localOnly && len(servers) > 1 {
		// Keep router/LAN resolvers ahead of public CN DNS for .lan/.local hostnames.
		var lan []string
		for _, srv := range servers {
			h, _, _ := net.SplitHostPort(srv)
			if ip := net.ParseIP(h); ip != nil && ip.IsPrivate() {
				lan = append(lan, srv)
			}
		}
		if len(lan) > 0 {
			servers = lan
		}
	}

	resCh := make(chan []byte, len(servers))
	errCh := make(chan error, len(servers))
	for _, srv := range servers {
		go func(target string) {
			d := net.Dialer{Timeout: 2500 * time.Millisecond, Control: netbind.Control}
			c, err := d.DialContext(ctx, "udp4", target)
			if err != nil {
				errCh <- err
				return
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(2500 * time.Millisecond))
			if _, err := c.Write(req); err != nil {
				errCh <- err
				return
			}
			buf := make([]byte, 4096)
			n, err := c.Read(buf)
			if err != nil || n < 12 {
				errCh <- errors.New("short dns reply")
				return
			}
			out := make([]byte, n)
			copy(out, buf[:n])
			resCh <- out
		}(srv)
	}

	var lastErr error
	pending := len(servers)
	for pending > 0 {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case resp := <-resCh:
			return resp, nil
		case err := <-errCh:
			lastErr = err
			pending--
		}
	}
	if lastErr == nil {
		lastErr = errors.New("all direct DNS queries failed")
	}
	return nil, lastErr
}

func (s *SplitDNSServer) cacheGet(key string, txID []byte) ([]byte, bool) {
	now := time.Now()
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()
	el, ok := s.entries[key]
	if !ok {
		return nil, false
	}
	item := el.Value.(*dnsCacheItem)
	if now.After(item.expires) {
		s.lru.Remove(el)
		delete(s.entries, key)
		return nil, false
	}
	s.lru.MoveToFront(el)
	cp := make([]byte, len(item.resp))
	copy(cp, item.resp)
	if len(cp) >= 2 && len(txID) >= 2 {
		cp[0], cp[1] = txID[0], txID[1]
	}
	return cp, true
}

func (s *SplitDNSServer) cachePut(key string, resp []byte, ttl time.Duration) {
	if len(resp) < 12 {
		return
	}
	// Only cache NOERROR responses with >=1 answer or clean empty authority.
	if resp[3]&0x0F != 0 {
		return
	}
	if ttl < dnsCacheMinTTL {
		ttl = dnsCacheMinTTL
	}
	if ttl > dnsCacheMaxTTL {
		ttl = dnsCacheMaxTTL
	}
	cp := make([]byte, len(resp))
	copy(cp, resp)
	exp := time.Now().Add(ttl)

	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()
	if el, ok := s.entries[key]; ok {
		it := el.Value.(*dnsCacheItem)
		it.resp = cp
		it.expires = exp
		s.lru.MoveToFront(el)
		return
	}
	for s.lru.Len() >= dnsCacheCap {
		back := s.lru.Back()
		if back == nil {
			break
		}
		old := back.Value.(*dnsCacheItem)
		delete(s.entries, old.key)
		s.lru.Remove(back)
	}
	el := s.lru.PushFront(&dnsCacheItem{key: key, resp: cp, expires: exp})
	s.entries[key] = el
}

func isLocalDomain(qname string) bool {
	return qname == "localhost" ||
		strings.HasSuffix(qname, ".local") ||
		strings.HasSuffix(qname, ".lan") ||
		strings.HasSuffix(qname, ".home.arpa") ||
		strings.HasSuffix(qname, ".internal")
}

func parseDNSQuestion(msg []byte) (qname string, qtype uint16, qEnd int, ok bool) {
	if len(msg) < 12 {
		return "", 0, 0, false
	}
	if binary.BigEndian.Uint16(msg[4:6]) == 0 {
		return "", 0, 0, false
	}
	var b strings.Builder
	pos := 12
	for pos < len(msg) {
		l := int(msg[pos])
		if l == 0 {
			pos++
			if pos+4 > len(msg) {
				return "", 0, 0, false
			}
			qt := binary.BigEndian.Uint16(msg[pos : pos+2])
			return strings.ToLower(b.String()), qt, pos + 4, true
		}
		if l&0xC0 != 0 || l > 63 || pos+1+l > len(msg) {
			return "", 0, 0, false
		}
		if b.Len() > 0 {
			b.WriteByte('.')
		}
		b.Write(msg[pos+1 : pos+1+l])
		pos += 1 + l
	}
	return "", 0, 0, false
}

func buildRCodeResponse(req []byte, qEnd int, rcode uint16) []byte {
	if len(req) < 12 {
		return nil
	}
	if qEnd > len(req) || qEnd < 12 {
		qEnd = 12
	}
	resp := make([]byte, qEnd)
	copy(resp, req[:qEnd])
	reqFlags := binary.BigEndian.Uint16(req[2:4])
	respFlags := uint16(0x8080) | (reqFlags & 0x7900) | (rcode & 0x000F)
	binary.BigEndian.PutUint16(resp[2:4], respFlags)
	if qEnd == 12 {
		binary.BigEndian.PutUint16(resp[4:6], 0)
	} else {
		binary.BigEndian.PutUint16(resp[4:6], 1)
	}
	binary.BigEndian.PutUint16(resp[6:8], 0)
	binary.BigEndian.PutUint16(resp[8:10], 0)
	binary.BigEndian.PutUint16(resp[10:12], 0)
	return resp
}
