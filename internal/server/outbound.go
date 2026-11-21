package server

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"ghostframe/internal/gft"
)

const (
	dnsCacheMax     = 4096
	dnsCacheTTL     = 300 * time.Second
	dnsRefreshAhead = 60 * time.Second
	happyDelay      = 150 * time.Millisecond
)

type dnsEntry struct {
	v4         []net.IP
	v6         []net.IP
	expires    time.Time
	refreshing atomic.Bool
}

var errIPv6Disabled = errors.New("outbound ipv6 disabled")

// FastOutbound provides an in-memory async DNS cache (4096 entries, 300s TTL),
// Happy Eyeballs (RFC 8305) IPv4/IPv6 racing dialer, and strict SSRF filtering.
type FastOutbound struct {
	mu           sync.RWMutex
	cache        map[string]*dnsEntry
	resolver     *net.Resolver
	listenPacket func(network, addr string) (net.PacketConn, error)
	disableIPv6  atomic.Bool
}

// SetDisableIPv6 toggles outbound IPv6 resolution/dialing and clears cached DNS answers.
func (f *FastOutbound) SetDisableIPv6(disabled bool) {
	prev := f.disableIPv6.Swap(disabled)
	if prev != disabled {
		f.mu.Lock()
		f.cache = make(map[string]*dnsEntry, 64)
		f.mu.Unlock()
	}
}

// IsIPv6Disabled reports whether server outbound IPv6 is disabled.
func (f *FastOutbound) IsIPv6Disabled() bool {
	return f.disableIPv6.Load()
}

// NewFastOutbound creates a FastOutbound engine.
func NewFastOutbound() *FastOutbound {
	return &FastOutbound{
		cache:        make(map[string]*dnsEntry, 256),
		resolver:     &net.Resolver{PreferGo: true},
		listenPacket: net.ListenPacket,
	}
}

func (f *FastOutbound) lookupAndFilter(ctx context.Context, host string) (*dnsEntry, error) {
	addrs, err := f.resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	ent := &dnsEntry{expires: time.Now().Add(dnsCacheTTL)}
	disableV6 := f.IsIPv6Disabled()
	sawV6 := false
	for _, a := range addrs {
		ip := a.IP
		if ip == nil {
			continue
		}
		if blockedIP(ip) && !AllowPrivateTargets {
			continue
		}
		if v4 := ip.To4(); v4 != nil {
			ent.v4 = append(ent.v4, v4)
		} else {
			sawV6 = true
			if !disableV6 {
				ent.v6 = append(ent.v6, ip)
			}
		}
	}
	if len(ent.v4) == 0 && len(ent.v6) == 0 {
		if disableV6 && sawV6 {
			return nil, errIPv6Disabled
		}
		return nil, errBlockedTarget
	}
	return ent, nil
}

// ResolveHost returns allowed IPv4 and IPv6 addresses from memory cache or DNS.
func (f *FastOutbound) ResolveHost(ctx context.Context, host string) (v4 []net.IP, v6 []net.IP, err error) {
	disableV6 := f.IsIPv6Disabled()
	if ip := net.ParseIP(host); ip != nil {
		if blockedIP(ip) && !AllowPrivateTargets {
			return nil, nil, errBlockedTarget
		}
		if ip4 := ip.To4(); ip4 != nil {
			return []net.IP{ip4}, nil, nil
		}
		if disableV6 {
			return nil, nil, errIPv6Disabled
		}
		return nil, []net.IP{ip}, nil
	}

	now := time.Now()
	f.mu.RLock()
	ent := f.cache[host]
	f.mu.RUnlock()

	if ent != nil && now.Before(ent.expires) {
		if time.Until(ent.expires) < dnsRefreshAhead && ent.refreshing.CompareAndSwap(false, true) {
			go f.asyncRefresh(host)
		}
		if disableV6 {
			if len(ent.v4) == 0 {
				return nil, nil, errIPv6Disabled
			}
			return ent.v4, nil, nil
		}
		return ent.v4, ent.v6, nil
	}

	fresh, err := f.lookupAndFilter(ctx, host)
	if err != nil {
		// Serve slightly stale entry if DNS temporarily blipped
		if ent != nil {
			if disableV6 {
				if len(ent.v4) > 0 {
					return ent.v4, nil, nil
				}
			} else if len(ent.v4) > 0 || len(ent.v6) > 0 {
				return ent.v4, ent.v6, nil
			}
		}
		return nil, nil, err
	}

	f.mu.Lock()
	if len(f.cache) >= dnsCacheMax {
		for k, v := range f.cache {
			if now.After(v.expires) || len(f.cache) >= dnsCacheMax {
				delete(f.cache, k)
				if len(f.cache) < dnsCacheMax-64 {
					break
				}
			}
		}
	}
	f.cache[host] = fresh
	f.mu.Unlock()
	return fresh.v4, fresh.v6, nil
}

func (f *FastOutbound) asyncRefresh(host string) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	fresh, err := f.lookupAndFilter(ctx, host)
	if err != nil {
		return
	}
	f.mu.Lock()
	f.cache[host] = fresh
	f.mu.Unlock()
}

func ssrfControl(_, address string, _ syscall.RawConn) error {
	h, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip := net.ParseIP(h)
	if ip == nil || (blockedIP(ip) && !AllowPrivateTargets) {
		return errBlockedTarget
	}
	return nil
}

func dialCheckedIP(ctx context.Context, ip net.IP, port string) (net.Conn, error) {
	d := net.Dialer{
		Timeout: 10 * time.Second,
		Control: ssrfControl,
	}
	c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), port))
	if err != nil {
		return nil, err
	}
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}
	return c, nil
}

// DialTCP dials target using cached DNS + Happy Eyeballs IPv4/IPv6 racing + SSRF protection.
func (f *FastOutbound) DialTCP(ctx context.Context, target string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return nil, err
	}
	v4, v6, err := f.ResolveHost(ctx, host)
	if err != nil {
		return nil, err
	}
	// Build interleaved candidates prioritizing IPv4 (reliable VPS egress) then IPv6.
	var primary, secondary []net.IP
	if len(v4) > 0 {
		primary = v4
		secondary = v6
	} else {
		primary = v6
	}
	if len(secondary) == 0 {
		return dialSequential(ctx, primary, port)
	}

	// Happy Eyeballs race between primary and secondary IP families (150ms stagger).
	raceCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	type dialRes struct {
		c   net.Conn
		err error
	}
	ch := make(chan dialRes, 2)
	go func() {
		c, e := dialSequential(raceCtx, primary, port)
		ch <- dialRes{c, e}
	}()
	go func() {
		select {
		case <-time.After(happyDelay):
		case <-raceCtx.Done():
			ch <- dialRes{nil, raceCtx.Err()}
			return
		}
		c, e := dialSequential(raceCtx, secondary, port)
		ch <- dialRes{c, e}
	}()

	var firstErr error
	for i := 0; i < 2; i++ {
		r := <-ch
		if r.err == nil && r.c != nil {
			cancel()
			// Drain loser if it also connected concurrently.
			if i == 0 {
				go func() {
					if r2 := <-ch; r2.c != nil {
						_ = r2.c.Close()
					}
				}()
			}
			return r.c, nil
		}
		if firstErr == nil {
			firstErr = r.err
		}
	}
	if firstErr == nil {
		firstErr = errors.New("all dial attempts failed")
	}
	return nil, firstErr
}

func dialSequential(ctx context.Context, ips []net.IP, port string) (net.Conn, error) {
	var lastErr error
	limit := len(ips)
	if limit > 3 {
		limit = 3
	}
	for i := 0; i < limit; i++ {
		c, err := dialCheckedIP(ctx, ips[i], port)
		if err == nil {
			return c, nil
		}
		lastErr = err
		if ctx.Err() != nil {
			break
		}
	}
	return nil, lastErr
}

// ResolveUDP resolves target against the cached SSRF-safe DNS resolver.
func (f *FastOutbound) ResolveUDP(ctx context.Context, target string) (*net.UDPAddr, error) {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		port, err = net.LookupPort("udp", portStr)
		if err != nil {
			return nil, err
		}
	}
	if port < 1 || port > 65535 {
		return nil, errors.New("bad udp port")
	}
	v4, v6, err := f.ResolveHost(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("dns lookup %s failed: %w", host, err)
	}
	if len(v4) > 0 {
		return &net.UDPAddr{IP: v4[0], Port: port}, nil
	}
	if len(v6) > 0 {
		return &net.UDPAddr{IP: v6[0], Port: port}, nil
	}
	return nil, errBlockedTarget
}

// ---- Unified Server UDP Association Manager (works over TCP Mux and QUIC Datagrams) ----

type udpReplyTarget struct {
	sink gft.UDPReplySink
	id   uint16
}

type udpAssoc struct {
	id       uint16
	pc       net.PacketConn
	reply    atomic.Pointer[udpReplyTarget]
	lastSeen atomic.Int64
	isDNS    atomic.Bool
	closed   chan struct{}
	once     sync.Once
}

func (u *udpAssoc) close() {
	u.once.Do(func() {
		close(u.closed)
		_ = u.pc.Close()
	})
}

type udpManager struct {
	defaultSink gft.UDPReplySink
	perConn     bool
	outbound    *FastOutbound
	logger      *log.Logger
	mu          sync.Mutex
	assocs      map[uint16]*udpAssoc
	lastUsed    atomic.Int64
	done        chan struct{}
}

func newUDPManager(defaultSink gft.UDPReplySink, perConn bool, outbound *FastOutbound, logger *log.Logger) *udpManager {
	m := &udpManager{
		defaultSink: defaultSink,
		perConn:     perConn,
		outbound:    outbound,
		logger:      logger,
		assocs:      make(map[uint16]*udpAssoc),
		done:        make(chan struct{}),
	}
	m.lastUsed.Store(time.Now().UnixNano())
	go m.reclaimLoop()
	return m
}

func (m *udpManager) handleDatagram(id uint16, target string, data []byte) {
	m.handleDatagramSink(m.defaultSink, id, target, data)
}

func (m *udpManager) handleDatagramSink(sink gft.UDPReplySink, id uint16, target string, data []byte) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	dstAddr, err := m.outbound.ResolveUDP(ctx, target)
	cancel()
	if err != nil {
		m.logger.Printf("udp blocked target=%s err=%v", target, err)
		return
	}

	now := time.Now().UnixNano()
	m.lastUsed.Store(now)

	m.mu.Lock()
	var evicted []*udpAssoc
	assoc, ok := m.assocs[id]
	if !ok {
		for len(m.assocs) >= maxUDPPerSession {
			var oldestID uint16
			var oldest *udpAssoc
			var oldestTS int64
			for k, v := range m.assocs {
				ts := v.lastSeen.Load()
				if oldest == nil || ts < oldestTS {
					oldestID = k
					oldest = v
					oldestTS = ts
				}
			}
			if oldest == nil {
				break
			}
			delete(m.assocs, oldestID)
			evicted = append(evicted, oldest)
		}
		listenNet := "udp"
		if m.outbound != nil && m.outbound.IsIPv6Disabled() {
			listenNet = "udp4"
		}
		listenFn := net.ListenPacket
		if m.outbound != nil && m.outbound.listenPacket != nil {
			listenFn = m.outbound.listenPacket
		}
		pc, err := listenFn(listenNet, ":0")
		if err != nil {
			m.mu.Unlock()
			for _, ev := range evicted {
				ev.close()
			}
			return
		}
		assoc = &udpAssoc{id: id, pc: pc, closed: make(chan struct{})}
		assoc.lastSeen.Store(now)
		assoc.isDNS.Store(dstAddr.Port == 53)
		assoc.reply.Store(&udpReplyTarget{sink: sink, id: id})
		m.assocs[id] = assoc
		go m.readLoop(assoc)
	} else {
		assoc.lastSeen.Store(now)
		if dstAddr.Port != 53 {
			assoc.isDNS.Store(false)
		}
		if sink != nil {
			assoc.reply.Store(&udpReplyTarget{sink: sink, id: id})
		}
	}
	m.mu.Unlock()

	for _, ev := range evicted {
		ev.close()
	}

	if _, werr := assoc.pc.WriteTo(data, dstAddr); werr != nil {
		m.logger.Printf("udp writeto %v err=%v", dstAddr, werr)
	}
}

func (m *udpManager) readLoop(a *udpAssoc) {
	buf := make([]byte, 64*1024)
	for {
		n, addr, err := a.pc.ReadFrom(buf)
		if err != nil {
			m.mu.Lock()
			if cur, exists := m.assocs[a.id]; exists && cur == a {
				delete(m.assocs, a.id)
			}
			m.mu.Unlock()
			a.close()
			return
		}
		now := time.Now().UnixNano()
		a.lastSeen.Store(now)
		m.lastUsed.Store(now)
		rt := a.reply.Load()
		if rt == nil || rt.sink == nil {
			continue
		}
		// Do not exit readLoop on transient SendUDPReply error (e.g., mid port-hop or failover):
		// keeping the outbound NAT socket alive preserves source IP:port across migrations.
		_ = rt.sink.SendUDPReply(rt.id, addr.String(), buf[:n])
	}
}

func (m *udpManager) handleClose(id uint16) {
	m.mu.Lock()
	assoc := m.assocs[id]
	delete(m.assocs, id)
	m.mu.Unlock()
	if assoc != nil {
		assoc.close()
	}
}

func (m *udpManager) reclaimLoop() {
	t := time.NewTicker(4 * time.Second)
	defer t.Stop()
	var sessDone <-chan struct{}
	if m.perConn && m.defaultSink != nil {
		sessDone = m.defaultSink.SessionDone()
	}
	for {
		select {
		case <-m.done:
			return
		case <-sessDone:
			return
		case now := <-t.C:
			cutoffDNS := now.Add(-udpDNSIdleTimeout).UnixNano()
			cutoffReg := now.Add(-udpIdleTimeout).UnixNano()
			var expired []*udpAssoc
			m.mu.Lock()
			for id, a := range m.assocs {
				cutoff := cutoffReg
				if a.isDNS.Load() {
					cutoff = cutoffDNS
				}
				if a.lastSeen.Load() < cutoff {
					expired = append(expired, a)
					delete(m.assocs, id)
				}
			}
			m.mu.Unlock()
			for _, a := range expired {
				a.close()
			}
		}
	}
}

func (m *udpManager) closeAll() {
	select {
	case <-m.done:
	default:
		close(m.done)
	}
	m.mu.Lock()
	for id, a := range m.assocs {
		delete(m.assocs, id)
		a.close()
	}
	m.mu.Unlock()
}
