package gft

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

const (
	quicHopMinAge       = 35 * time.Second
	quicHopMaxAge       = 65 * time.Second
	quicDrainUDPIdle    = 15 * time.Second
	quicDrainMaxTimeout = 60 * time.Second
)

// DialLimiter implements a 2-token, 2/sec token bucket with jitter to prevent
// reconnect storms that trigger DPI heuristics.
type DialLimiter struct {
	mu       sync.Mutex
	tokens   float64
	cap      float64
	rate     float64 // tokens per second
	last     time.Time
	minJitMs int
	maxJitMs int
}

// NewDialLimiter returns a token-bucket dial rate limiter (cap=2, rate=2/s, +50..200ms jitter).
func NewDialLimiter() *DialLimiter {
	return &DialLimiter{
		tokens:   2,
		cap:      2,
		rate:     2,
		last:     time.Now(),
		minJitMs: 50,
		maxJitMs: 200,
	}
}

// Wait blocks until a dial token is available and sleeps the anti-burst jitter.
func (d *DialLimiter) Wait(ctx context.Context) error {
	for {
		d.mu.Lock()
		now := time.Now()
		elapsed := now.Sub(d.last).Seconds()
		d.last = now
		d.tokens += elapsed * d.rate
		if d.tokens > d.cap {
			d.tokens = d.cap
		}
		if d.tokens >= 1 {
			d.tokens -= 1
			d.mu.Unlock()
			break
		}
		waitDur := time.Duration(((1 - d.tokens) / d.rate) * float64(time.Second))
		d.mu.Unlock()
		if waitDur < 10*time.Millisecond {
			waitDur = 10 * time.Millisecond
		}
		select {
		case <-time.After(waitDur):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if d.maxJitMs > 0 && d.maxJitMs >= d.minJitMs {
		jit := time.Duration(randRange(d.minJitMs, d.maxJitMs)) * time.Millisecond
		select {
		case <-time.After(jit):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

// ApexStats reports live status across both QUIC Dual-Track and TCP uTLS pool.
type ApexStats struct {
	Mode          string `json:"mode"` // "QUIC", "TCP-uTLS", "TCP-Fallback", "Starting"
	QUICConnected bool   `json:"quic_connected"`
	QUICPort      int    `json:"quic_port"`
	QUICRTTMs     int64  `json:"quic_rtt_ms"`
	TCPRTTMs      int64  `json:"tcp_rtt_ms"`
	RTTMs         int64  `json:"rtt_ms"`
	ActiveConns   int    `json:"active_conns"`
	ActiveStreams int    `json:"active_streams"`
	TotalUp       uint64 `json:"total_up"`
	TotalDown     uint64 `json:"total_down"`
	LastErr       string `json:"last_err"`
}

type drainingQUIC struct {
	sess      *QUICSession
	drainingAt time.Time
}

// ApexScheduler races and coordinates QUIC Dual-Track (with dynamic port hopping
// and fragmented RFC 9221 Datagrams) alongside the uTLS SessionPool, providing 0ms
// failover and cross-hop ClientID NAT port preservation.
type ApexScheduler struct {
	link       *Link
	ps         *ParamStore
	clientID   [8]byte
	limiter    *DialLimiter
	pool       *SessionPool
	onLog      func(string, ...any)
	quicDialFn func(ctx context.Context, l *Link, ps *ParamStore, port int, timeout time.Duration) (*QUICSession, time.Duration, error)

	hopMinAge    time.Duration
	hopMaxAge    time.Duration
	drainUDPIdle time.Duration
	maintainTick time.Duration

	mu            sync.Mutex
	quicActive    *QUICSession
	quicCreatedAt time.Time
	quicMaxAge    time.Duration
	quicDrain     []*drainingQUIC
	quicDegraded  time.Time
	retiredQUp    uint64
	retiredQDown  uint64
	lastErr       string

	nextAssocID atomic.Uint32
	udpMu       sync.Mutex
	udpAssocs   map[uint16]*SchedulerUDPAssoc

	quicRTTMs atomic.Int64

	ctx    context.Context
	cancel context.CancelFunc
	loopMu sync.Mutex
	closed bool
	wg     sync.WaitGroup
}

func (a *ApexScheduler) launchLoop(fn func()) {
	a.loopMu.Lock()
	defer a.loopMu.Unlock()
	if a.closed || a.ctx.Err() != nil {
		return
	}
	a.wg.Add(1)
	go fn()
}

// NewApexScheduler creates an Apex dual-track scheduler for link.
func NewApexScheduler(l *Link, ps *ParamStore, tcpPoolSize int, logf func(string, ...any)) *ApexScheduler {
	var cid [8]byte
	if _, err := io.ReadFull(rand.Reader, cid[:]); err != nil {
		cid = DefaultClientID
	}
	ctx, cancel := context.WithCancel(context.Background())
	lim := NewDialLimiter()
	a := &ApexScheduler{
		link:         l,
		ps:           ps,
		clientID:     cid,
		limiter:      lim,
		onLog:        logf,
		hopMinAge:    quicHopMinAge,
		hopMaxAge:    quicHopMaxAge,
		drainUDPIdle: quicDrainUDPIdle,
		maintainTick: 2 * time.Second,
		udpAssocs:    make(map[uint16]*SchedulerUDPAssoc),
		ctx:          ctx,
		cancel:       cancel,
	}
	pool := NewSessionPool(l, ps, tcpPoolSize, logf)
	pool.dialFn = func(dialCtx context.Context, dl *Link, dps *ParamStore, flags uint16, timeout time.Duration) (*Session, time.Duration, error) {
		if err := lim.Wait(dialCtx); err != nil {
			return nil, 0, err
		}
		return DialSessionWithID(dialCtx, dl, dps, flags, timeout, a.clientID)
	}
	a.pool = pool
	a.quicDialFn = func(dialCtx context.Context, dl *Link, dps *ParamStore, port int, timeout time.Duration) (*QUICSession, time.Duration, error) {
		return DialQUICSessionWithID(dialCtx, dl, dps, port, timeout, a.clientID)
	}
	return a
}

// ClientID returns the 8-byte session-group identifier used for server NAT preservation.
func (a *ApexScheduler) ClientID() [8]byte { return a.clientID }

// SetHopTimingsForTest overrides port-hop and drain intervals for unit tests.
func (a *ApexScheduler) SetHopTimingsForTest(minAge, maxAge, drainUDPIdle, tick time.Duration) {
	a.mu.Lock()
	a.hopMinAge = minAge
	a.hopMaxAge = maxAge
	a.drainUDPIdle = drainUDPIdle
	a.maintainTick = tick
	a.mu.Unlock()
}

// SetDialJitterForTest overrides dial rate-limiter jitter and rate for tests.
func (a *ApexScheduler) SetDialJitterForTest(minMs, maxMs int, rate float64) {
	a.limiter.mu.Lock()
	a.limiter.minJitMs = minMs
	a.limiter.maxJitMs = maxMs
	if rate > 0 {
		a.limiter.rate = rate
		if rate > a.limiter.cap {
			a.limiter.cap = rate
			a.limiter.tokens = rate
		}
	}
	a.limiter.mu.Unlock()
}

// SetQUICDialHookForTest overrides the QUIC dial function used by the scheduler.
func (a *ApexScheduler) SetQUICDialHookForTest(fn func(ctx context.Context, l *Link, ps *ParamStore, port int, timeout time.Duration, clientID [8]byte) (*QUICSession, time.Duration, error)) {
	a.mu.Lock()
	a.quicDialFn = func(dialCtx context.Context, dl *Link, dps *ParamStore, port int, timeout time.Duration) (*QUICSession, time.Duration, error) {
		return fn(dialCtx, dl, dps, port, timeout, a.clientID)
	}
	a.mu.Unlock()
}

// Start connects initial tracks based on Link.EffectiveTransport ("auto", "quic", "tcp").
func (a *ApexScheduler) Start(connectTimeout time.Duration) error {
	tr := a.link.EffectiveTransport()
	switch tr {
	case "tcp":
		return a.pool.Start(connectTimeout)
	case "quic":
		if err := a.dialQUICNow(connectTimeout); err != nil {
			return err
		}
		a.launchLoop(a.quicMaintainLoop)
		return nil
	default: // "auto": race QUIC + TCP simultaneously so 0ms failover is ready immediately
		type res struct {
			kind string
			err  error
		}
		ch := make(chan res, 2)
		go func() {
			ch <- res{"tcp", a.pool.Start(connectTimeout)}
		}()
		go func() {
			ch <- res{"quic", a.dialQUICNow(connectTimeout)}
		}()

		r1 := <-ch
		if r1.err == nil {
			a.launchLoop(func() {
				defer a.wg.Done()
				select {
				case <-a.ctx.Done():
					return
				case r2 := <-ch:
					if r2.err != nil {
						if r2.kind == "tcp" {
							if a.onLog != nil {
								a.onLog("TCP track initial dial deferred (%v); running on QUIC", r2.err)
							}
							a.launchLoop(func() { a.retryTCPStartLoop(connectTimeout) })
						} else if a.onLog != nil {
							a.onLog("QUIC track unavailable (%v); 0ms fallback active on TCP-uTLS", r2.err)
						}
					}
				}
			})
			a.launchLoop(a.quicMaintainLoop)
			return nil
		}

		r2 := <-ch
		if r2.err != nil {
			if r1.kind == "quic" {
				return r1.err
			}
			return r2.err
		}
		if r1.kind == "tcp" {
			if a.onLog != nil {
				a.onLog("TCP track initial dial deferred (%v); running on QUIC", r1.err)
			}
			a.launchLoop(func() { a.retryTCPStartLoop(connectTimeout) })
		} else if a.onLog != nil {
			a.onLog("QUIC track unavailable (%v); 0ms fallback active on TCP-uTLS", r1.err)
		}
		a.launchLoop(a.quicMaintainLoop)
		return nil
	}
}

func (a *ApexScheduler) retryTCPStartLoop(timeout time.Duration) {
	defer a.wg.Done()
	backoff := 4 * time.Second
	for {
		jit := time.Duration(randRange(200, 1200)) * time.Millisecond
		select {
		case <-a.ctx.Done():
			return
		case <-time.After(backoff + jit):
		}
		if a.ctx.Err() != nil {
			return
		}
		if err := a.pool.Start(timeout); err == nil {
			return
		}
		backoff *= 2
		if backoff > 60*time.Second {
			backoff = 60 * time.Second
		}
	}
}

func (a *ApexScheduler) randomHopAge() time.Duration {
	minMs := int(a.hopMinAge.Milliseconds())
	maxMs := int(a.hopMaxAge.Milliseconds())
	if minMs <= 0 {
		return 35 * time.Second
	}
	if maxMs <= minMs {
		return time.Duration(minMs) * time.Millisecond
	}
	return time.Duration(randRange(minMs, maxMs)) * time.Millisecond
}

func (a *ApexScheduler) dialQUICNow(timeout time.Duration) error {
	if err := a.limiter.Wait(a.ctx); err != nil {
		return err
	}
	port := PickHopPort(a.link)
	dialCtx, cancel := context.WithTimeout(a.ctx, timeout)
	defer cancel()
	qs, hs, err := a.quicDialFn(dialCtx, a.link, a.ps, port, timeout)
	if err != nil {
		a.mu.Lock()
		a.lastErr = err.Error()
		a.mu.Unlock()
		return err
	}
	ms := hs.Milliseconds()
	if ms <= 0 {
		ms = 1
	}
	a.quicRTTMs.Store(ms)

	hopAge := a.randomHopAge()
	now := time.Now()
	a.mu.Lock()
	if a.quicActive != nil {
		a.quicDrain = append(a.quicDrain, &drainingQUIC{sess: a.quicActive, drainingAt: now})
	}
	a.quicActive = qs
	a.quicCreatedAt = now
	a.quicMaxAge = hopAge
	a.quicDegraded = time.Time{}
	a.mu.Unlock()

	if a.onLog != nil {
		a.onLog("QUIC Dual-Track connected (UDP :%d, RTT=%dms)", port, ms)
	}
	return nil
}

func (a *ApexScheduler) quicMaintainLoop() {
	defer a.wg.Done()
	a.mu.Lock()
	tickDur := a.maintainTick
	a.mu.Unlock()
	if tickDur <= 0 {
		tickDur = 2 * time.Second
	}
	t := time.NewTicker(tickDur)
	pingTicker := time.NewTicker(20 * time.Second)
	defer t.Stop()
	defer pingTicker.Stop()

	backoff := 2 * time.Second
	for {
		select {
		case <-a.ctx.Done():
			return
		case <-pingTicker.C:
			a.mu.Lock()
			q := a.quicActive
			a.mu.Unlock()
			if q != nil {
				select {
				case <-q.Done():
				default:
					if rtt, err := q.ProbeRTT(4 * time.Second); err == nil {
						ms := rtt.Milliseconds()
						if ms <= 0 {
							ms = 1
						}
						a.quicRTTMs.Store(ms)
					}
				}
			}
		case <-t.C:
			now := time.Now()
			a.mu.Lock()
			q := a.quicActive
			created := a.quicCreatedAt
			maxAge := a.quicMaxAge
			drainUDPIdle := a.drainUDPIdle
			var alive []*drainingQUIC
			for _, dq := range a.quicDrain {
				select {
				case <-dq.sess.Done():
					a.retiredQUp += dq.sess.UpBytes.Load()
					a.retiredQDown += dq.sess.DownBytes.Load()
				default:
					lastUDP := dq.sess.LastUDPTime()
					udpIdleOK := lastUDP.IsZero() && now.Sub(dq.drainingAt) >= drainUDPIdle
					if !lastUDP.IsZero() && now.Sub(lastUDP) >= drainUDPIdle {
						udpIdleOK = true
					}
					hardExpired := now.Sub(dq.drainingAt) >= quicDrainMaxTimeout
					if (dq.sess.NumStreams() == 0 && udpIdleOK) || hardExpired {
						a.retiredQUp += dq.sess.UpBytes.Load()
						a.retiredQDown += dq.sess.DownBytes.Load()
						dq.sess.Close()
					} else {
						alive = append(alive, dq)
					}
				}
			}
			a.quicDrain = alive
			a.mu.Unlock()

			needDial := false
			isHop := false
			if q == nil {
				needDial = true
			} else {
				select {
				case <-q.Done():
					a.mu.Lock()
					a.retiredQUp += q.UpBytes.Load()
					a.retiredQDown += q.DownBytes.Load()
					if a.quicActive == q {
						a.quicActive = nil
					}
					a.mu.Unlock()
					needDial = true
				default:
					if _, _, hasHop := a.link.ParseHopRange(); hasHop && time.Since(created) >= maxAge {
						needDial = true
						isHop = true
					}
				}
			}
			if needDial {
				if err := a.dialQUICNow(6 * time.Second); err != nil {
					if !isHop {
						select {
						case <-a.ctx.Done():
							return
						case <-time.After(backoff):
						}
						backoff *= 2
						if backoff > 20*time.Second {
							backoff = 20 * time.Second
						}
					}
				} else {
					backoff = 2 * time.Second
				}
			}
		}
	}
}

func (a *ApexScheduler) activeQUICForSend() *QUICSession {
	if a.link.EffectiveTransport() == "tcp" {
		return nil
	}
	a.mu.Lock()
	q := a.quicActive
	degraded := a.quicDegraded
	a.mu.Unlock()
	if q == nil {
		return nil
	}
	select {
	case <-q.Done():
		return nil
	default:
	}
	if !degraded.IsZero() && time.Since(degraded) < 15*time.Second {
		return nil
	}
	if a.link.EffectiveTransport() == "auto" {
		qRTT := a.quicRTTMs.Load()
		tRTT := a.pool.rttMs.Load()
		if qRTT > 150 && tRTT > 0 && qRTT > (tRTT*18)/10 && a.pool.Stats().ActiveConns > 0 {
			return nil
		}
	}
	return q
}

func (a *ApexScheduler) markQUICDegraded(q *QUICSession, err error) {
	a.mu.Lock()
	if a.quicActive == q {
		a.quicDegraded = time.Now()
		if err != nil {
			a.lastErr = err.Error()
		}
	}
	a.mu.Unlock()
}

// OpenStream routes a TCP tunnel stream over QUIC Dual-Track when healthy, falling
// back in 0ms to the uTLS TCP SessionPool if UDP fails or is throttled.
func (a *ApexScheduler) OpenStream(target string, first []byte) (DataStream, error) {
	if q := a.activeQUICForSend(); q != nil {
		st, err := q.OpenStream(target, first)
		if err == nil {
			return st, nil
		}
		a.markQUICDegraded(q, err)
	}
	if a.link.EffectiveTransport() == "quic" {
		return nil, errors.New("gft: quic track unavailable")
	}
	st, err := a.pool.OpenStream(target, first)
	if err != nil {
		return nil, err
	}
	return st, nil
}

// SchedulerUDPAssoc is a persistent virtual UDP association across QUIC port hops
// and QUIC<->TCP 0ms failovers, preserving the exact server-side NAT socket.
type SchedulerUDPAssoc struct {
	sched *ApexScheduler
	id    uint16

	mu     sync.Mutex
	closed bool
	bySess map[any]UDPAssociation
	last   UDPAssociation

	recvCh    chan UDPPacket
	done      chan struct{}
	closeOnce sync.Once
}

// OpenUDP allocates a resilient SchedulerUDPAssoc surviving port hops & failovers.
func (a *ApexScheduler) OpenUDP() (UDPAssociation, error) {
	select {
	case <-a.ctx.Done():
		return nil, ErrSessionClosed
	default:
	}
	a.udpMu.Lock()
	var id uint16
	for tries := 0; tries < 65535; tries++ {
		cand := uint16((a.nextAssocID.Add(1)-1)%65534) + 1
		if _, exists := a.udpAssocs[cand]; !exists {
			id = cand
			break
		}
	}
	if id == 0 {
		a.udpMu.Unlock()
		return nil, errors.New("gft: no free scheduler udp assoc id")
	}
	su := &SchedulerUDPAssoc{
		sched:  a,
		id:     id,
		bySess: make(map[any]UDPAssociation),
		recvCh: make(chan UDPPacket, 256),
		done:   make(chan struct{}),
	}
	a.udpAssocs[id] = su
	a.udpMu.Unlock()
	return su, nil
}

func (u *SchedulerUDPAssoc) ID() uint16             { return u.id }
func (u *SchedulerUDPAssoc) Recv() <-chan UDPPacket { return u.recvCh }
func (u *SchedulerUDPAssoc) Done() <-chan struct{}  { return u.done }

func (u *SchedulerUDPAssoc) bindUnderlying(sessKey any, openFn func() (UDPAssociation, error)) (UDPAssociation, error) {
	u.mu.Lock()
	if u.closed {
		u.mu.Unlock()
		return nil, ErrStreamClosed
	}
	if existing, ok := u.bySess[sessKey]; ok {
		select {
		case <-existing.Done():
			delete(u.bySess, sessKey)
		default:
			u.last = existing
			u.mu.Unlock()
			return existing, nil
		}
	}
	u.mu.Unlock()

	sub, err := openFn()
	if err != nil {
		return nil, err
	}

	u.mu.Lock()
	if u.closed {
		u.mu.Unlock()
		_ = sub.Close()
		return nil, ErrStreamClosed
	}
	if existing, ok := u.bySess[sessKey]; ok {
		select {
		case <-existing.Done():
			delete(u.bySess, sessKey)
		default:
			u.last = existing
			u.mu.Unlock()
			_ = sub.Close()
			return existing, nil
		}
	}
	u.bySess[sessKey] = sub
	u.last = sub
	u.mu.Unlock()

	go u.pumpReplies(sessKey, sub)
	return sub, nil
}

func (u *SchedulerUDPAssoc) pumpReplies(sessKey any, sub UDPAssociation) {
	for {
		select {
		case <-u.done:
			return
		case <-sub.Done():
			u.mu.Lock()
			if u.bySess[sessKey] == sub {
				delete(u.bySess, sessKey)
			}
			u.mu.Unlock()
			return
		case pkt, ok := <-sub.Recv():
			if !ok {
				return
			}
			select {
			case u.recvCh <- pkt:
			case <-u.done:
				return
			default:
			}
		}
	}
}

func (u *SchedulerUDPAssoc) SendTo(target string, data []byte) error {
	select {
	case <-u.done:
		return ErrStreamClosed
	default:
	}

	if q := u.sched.activeQUICForSend(); q != nil {
		sub, err := u.bindUnderlying(q, func() (UDPAssociation, error) {
			return q.OpenUDPWithID(u.id)
		})
		if err == nil {
			if serr := sub.SendTo(target, data); serr == nil {
				return nil
			} else {
				u.sched.markQUICDegraded(q, serr)
			}
		} else {
			u.sched.markQUICDegraded(q, err)
		}
	}

	if u.sched.link.EffectiveTransport() == "quic" {
		return errors.New("gft: quic udp track unavailable")
	}

	s, err := u.sched.pool.Acquire()
	if err != nil {
		return err
	}
	sub, err := u.bindUnderlying(s, func() (UDPAssociation, error) {
		st, err := s.OpenUDPWithID(u.id)
		if err != nil {
			return nil, err
		}
		return st, nil
	})
	if err != nil {
		return err
	}
	return sub.SendTo(target, data)
}

func (u *SchedulerUDPAssoc) Close() error {
	u.closeOnce.Do(func() {
		u.mu.Lock()
		u.closed = true
		subs := make([]UDPAssociation, 0, len(u.bySess))
		for k, sub := range u.bySess {
			subs = append(subs, sub)
			delete(u.bySess, k)
		}
		last := u.last
		u.last = nil
		u.mu.Unlock()

		close(u.done)

		u.sched.udpMu.Lock()
		delete(u.sched.udpAssocs, u.id)
		u.sched.udpMu.Unlock()

		// Tell server to release the ClientID NAT socket once via active/last track.
		closedRemote := false
		if last != nil {
			_ = last.Close()
			closedRemote = true
		}
		for _, sub := range subs {
			if sub != last {
				if !closedRemote {
					_ = sub.Close()
					closedRemote = true
				} else if qs, ok := sub.(*QUICUDPAssoc); ok {
					qs.closeLocal()
				} else if ts, ok := sub.(*UDPStream); ok {
					ts.closeLocal()
				}
			}
		}
	})
	return nil
}

// Stats returns a live metrics snapshot across QUIC and TCP tracks.
func (a *ApexScheduler) Stats() ApexStats {
	ps := a.pool.Stats()
	a.mu.Lock()
	q := a.quicActive
	qUp, qDown := a.retiredQUp, a.retiredQDown
	var qPort, qStreams int
	qAlive := false
	if q != nil {
		select {
		case <-q.Done():
		default:
			qAlive = true
			qPort = q.RemotePort()
			qStreams = q.NumStreams()
		}
		qUp += q.UpBytes.Load()
		qDown += q.DownBytes.Load()
	}
	for _, dq := range a.quicDrain {
		qUp += dq.sess.UpBytes.Load()
		qDown += dq.sess.DownBytes.Load()
		qStreams += dq.sess.NumStreams()
	}
	lErr := a.lastErr
	a.mu.Unlock()

	if lErr == "" {
		lErr = ps.LastErr
	}
	qRTT := a.quicRTTMs.Load()
	tRTT := ps.RTTMs
	mode := "Starting"
	bestRTT := tRTT
	conns := ps.ActiveConns + ps.DrainingConns
	if qAlive {
		conns++
		if a.activeQUICForSend() != nil {
			mode = "QUIC"
			if qRTT > 0 {
				bestRTT = qRTT
			}
		} else if ps.ActiveConns > 0 {
			mode = "TCP-Fallback"
		}
	} else if ps.ActiveConns > 0 {
		if a.link.EffectiveTransport() == "tcp" {
			mode = "TCP-uTLS"
		} else {
			mode = "TCP-Fallback"
		}
	}

	return ApexStats{
		Mode:          mode,
		QUICConnected: qAlive,
		QUICPort:      qPort,
		QUICRTTMs:     qRTT,
		TCPRTTMs:      tRTT,
		RTTMs:         bestRTT,
		ActiveConns:   conns,
		ActiveStreams: ps.ActiveStreams + qStreams,
		TotalUp:       ps.TotalUp + qUp,
		TotalDown:     ps.TotalDown + qDown,
		LastErr:       lErr,
	}
}

// Close shuts down QUIC Dual-Track, UDP associations, and TCP SessionPool cleanly.
func (a *ApexScheduler) Close() {
	a.loopMu.Lock()
	a.closed = true
	a.cancel()
	a.loopMu.Unlock()

	a.udpMu.Lock()
	assocs := make([]*SchedulerUDPAssoc, 0, len(a.udpAssocs))
	for _, u := range a.udpAssocs {
		assocs = append(assocs, u)
	}
	a.udpMu.Unlock()
	for _, u := range assocs {
		_ = u.Close()
	}

	a.mu.Lock()
	if a.quicActive != nil {
		a.quicActive.Close()
		a.quicActive = nil
	}
	for _, dq := range a.quicDrain {
		dq.sess.Close()
	}
	a.quicDrain = nil
	a.mu.Unlock()
	a.pool.Close()
	a.wg.Wait()
}
