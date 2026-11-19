package gft

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"ghostframe/internal/gftrtc"
)

const (
	DefaultRTCPoolSize = 2
	rtcHopMinAge       = 25 * time.Second
	rtcHopMaxAge       = 50 * time.Second
	rtcDrainUDPIdle    = 15 * time.Second
)

// DialLimiter implements a token bucket with jitter to prevent reconnect storms.
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

// ApexStats reports live status across both GFT-RTC striped sessions and TCP uTLS pool.
type ApexStats struct {
	Mode          string  `json:"mode"` // "RTC-Smart", "TCP-uTLS", "TCP-Fallback", "Starting"
	RTCConnected  bool    `json:"rtc_connected"`
	RTCPort       int     `json:"rtc_port"`
	RTCRTTMs      int64   `json:"rtc_rtt_ms"`
	TCPRTTMs      int64   `json:"tcp_rtt_ms"`
	RTTMs         int64   `json:"rtt_ms"`
	FECRecovered  uint64  `json:"fec_recovered"`
	LossRate      float64 `json:"loss_rate"`
	PacingMbps    float64 `json:"pacing_mbps"`
	ActiveConns   int     `json:"active_conns"`
	ActiveStreams int     `json:"active_streams"`
	TotalUp       uint64  `json:"total_up"`
	TotalDown     uint64  `json:"total_down"`
	LastErr       string  `json:"last_err"`
}

type rtcSlot struct {
	sess       *gftrtc.RTCSession
	createdAt  time.Time
	lastHopAt  time.Time
	maxAge     time.Duration
	degradedAt time.Time
}

// ApexScheduler races and coordinates a Striped GFT-RTC Dual-Session pool (with 0ms WebRTC
// socket migration port hopping, XOR-FEC, and Smart-Brutal CC) alongside the TCP uTLS SessionPool.
type ApexScheduler struct {
	link       *Link
	ps         *ParamStore
	clientID   [8]byte
	limiter    *DialLimiter // alias of tcpLimiter
	tcpLimiter *DialLimiter
	rtcLimiter *DialLimiter
	pool       *SessionPool
	onLog      func(string, ...any)
	rtcDialFn  func(ctx context.Context, l *Link, ps *ParamStore, port int, timeout time.Duration) (*gftrtc.RTCSession, time.Duration, error)
	rtcHopFn   func(sess *gftrtc.RTCSession, nextPort int) error

	hopMinAge    time.Duration
	hopMaxAge    time.Duration
	drainUDPIdle time.Duration
	maintainTick time.Duration

	mu           sync.Mutex
	rtcSlots     []*rtcSlot
	retiredRUp   uint64
	retiredRDown uint64
	retiredFEC   uint64
	lastErr      string

	rtcRR       atomic.Uint64
	nextAssocID atomic.Uint32
	udpMu       sync.Mutex
	udpAssocs   map[uint16]*SchedulerUDPAssoc

	rtcRTTMs atomic.Int64

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

// NewApexScheduler creates an Apex dual-track scheduler (GFT-RTC + TCP-uTLS) for link.
func NewApexScheduler(l *Link, ps *ParamStore, tcpPoolSize int, logf func(string, ...any)) *ApexScheduler {
	var cid [8]byte
	if _, err := io.ReadFull(rand.Reader, cid[:]); err != nil {
		cid = DefaultClientID
	}
	ctx, cancel := context.WithCancel(context.Background())
	tcpLim := NewDialLimiter()
	rtcLim := &DialLimiter{
		tokens:   4,
		cap:      4,
		rate:     4,
		last:     time.Now(),
		minJitMs: 25,
		maxJitMs: 120,
	}
	a := &ApexScheduler{
		link:         l,
		ps:           ps,
		clientID:     cid,
		limiter:      tcpLim,
		tcpLimiter:   tcpLim,
		rtcLimiter:   rtcLim,
		onLog:        logf,
		hopMinAge:    rtcHopMinAge,
		hopMaxAge:    rtcHopMaxAge,
		drainUDPIdle: rtcDrainUDPIdle,
		maintainTick: 2 * time.Second,
		udpAssocs:    make(map[uint16]*SchedulerUDPAssoc),
		ctx:          ctx,
		cancel:       cancel,
	}
	pool := NewSessionPool(l, ps, tcpPoolSize, logf)
	pool.dialFn = func(dialCtx context.Context, dl *Link, dps *ParamStore, flags uint16, timeout time.Duration) (*Session, time.Duration, error) {
		if err := tcpLim.Wait(dialCtx); err != nil {
			return nil, 0, err
		}
		return DialSessionWithID(dialCtx, dl, dps, flags, timeout, a.clientID)
	}
	a.pool = pool
	a.rtcDialFn = func(dialCtx context.Context, dl *Link, dps *ParamStore, port int, timeout time.Duration) (*gftrtc.RTCSession, time.Duration, error) {
		return DialRTCSessionWithID(dialCtx, dl, dps, port, timeout, a.clientID)
	}
	a.rtcHopFn = func(sess *gftrtc.RTCSession, nextPort int) error {
		return sess.Hop(nextPort)
	}
	return a
}

func (a *ApexScheduler) rtcPoolTarget() int {
	return DefaultRTCPoolSize // 2 concurrent striped UDP 5-tuples
}

// ClientID returns the 8-byte session-group identifier used for server NAT preservation.
func (a *ApexScheduler) ClientID() [8]byte { return a.clientID }

// SetHopTimingsForTest overrides port-hop and maintain intervals for unit tests.
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
	for _, lim := range []*DialLimiter{a.tcpLimiter, a.rtcLimiter} {
		lim.mu.Lock()
		lim.minJitMs = minMs
		lim.maxJitMs = maxMs
		if rate > 0 {
			lim.rate = rate
			if rate > lim.cap {
				lim.cap = rate
				lim.tokens = rate
			}
		}
		lim.mu.Unlock()
	}
}

// SetRTCDialHookForTest overrides the GFT-RTC dial function used by the scheduler.
func (a *ApexScheduler) SetRTCDialHookForTest(fn func(ctx context.Context, l *Link, ps *ParamStore, port int, timeout time.Duration, clientID [8]byte) (*gftrtc.RTCSession, time.Duration, error)) {
	a.mu.Lock()
	a.rtcDialFn = func(dialCtx context.Context, dl *Link, dps *ParamStore, port int, timeout time.Duration) (*gftrtc.RTCSession, time.Duration, error) {
		return fn(dialCtx, dl, dps, port, timeout, a.clientID)
	}
	a.mu.Unlock()
}

// SetRTCHopHookForTest overrides how 0ms port hopping replaces UDP sockets in tests.
func (a *ApexScheduler) SetRTCHopHookForTest(fn func(sess *gftrtc.RTCSession, nextPort int) error) {
	a.mu.Lock()
	a.rtcHopFn = fn
	a.mu.Unlock()
}

// UpdateBandwidth updates pacing targets on active GFT-RTC sessions live.
func (a *ApexScheduler) UpdateBandwidth(upMbps, downMbps int) {
	a.mu.Lock()
	a.link.UpMbps = upMbps
	a.link.DownMbps = downMbps
	for _, sl := range a.rtcSlots {
		if sl != nil && sl.sess != nil {
			sl.sess.UpdateBandwidth(upMbps)
		}
	}
	a.mu.Unlock()
}

// Start connects initial tracks based on Link.EffectiveTransport ("auto", "rtc", "tcp").
func (a *ApexScheduler) Start(connectTimeout time.Duration) error {
	tr := a.link.EffectiveTransport()
	switch tr {
	case "tcp":
		return a.pool.Start(connectTimeout)
	case "rtc":
		if err := a.dialRTCNow(connectTimeout); err != nil {
			return err
		}
		a.launchLoop(a.rtcMaintainLoop)
		return nil
	default: // "auto": race GFT-RTC + TCP-uTLS simultaneously
		type res struct {
			kind string
			err  error
		}
		ch := make(chan res, 2)
		go func() {
			ch <- res{"tcp", a.pool.Start(connectTimeout)}
		}()
		go func() {
			ch <- res{"rtc", a.dialRTCNow(connectTimeout)}
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
								a.onLog("TCP track deferred (%v); running on GFT-RTC Smart-Brutal", r2.err)
							}
							a.launchLoop(func() { a.retryTCPStartLoop(connectTimeout) })
						} else if a.onLog != nil {
							a.onLog("GFT-RTC track unavailable (%v); 0ms fallback active on TCP-uTLS", r2.err)
						}
					}
				}
			})
			a.launchLoop(a.rtcMaintainLoop)
			return nil
		}

		r2 := <-ch
		if r2.err != nil {
			if r1.kind == "rtc" {
				return r1.err
			}
			return r2.err
		}
		if r1.kind == "tcp" {
			if a.onLog != nil {
				a.onLog("TCP track deferred (%v); running on GFT-RTC Smart-Brutal", r1.err)
			}
			a.launchLoop(func() { a.retryTCPStartLoop(connectTimeout) })
		} else if a.onLog != nil {
			a.onLog("GFT-RTC track unavailable (%v); 0ms fallback active on TCP-uTLS", r1.err)
		}
		a.launchLoop(a.rtcMaintainLoop)
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
		return 25 * time.Second
	}
	if maxMs <= minMs {
		return time.Duration(minMs) * time.Millisecond
	}
	return time.Duration(randRange(minMs, maxMs)) * time.Millisecond
}

func (a *ApexScheduler) dialOneRTCSlot(timeout time.Duration) (*rtcSlot, error) {
	if err := a.rtcLimiter.Wait(a.ctx); err != nil {
		return nil, err
	}
	port := PickHopPort(a.link)
	dialCtx, cancel := context.WithTimeout(a.ctx, timeout)
	defer cancel()
	sess, hs, err := a.rtcDialFn(dialCtx, a.link, a.ps, port, timeout)
	if err != nil {
		a.mu.Lock()
		a.lastErr = err.Error()
		a.mu.Unlock()
		return nil, err
	}
	if a.ctx.Err() != nil {
		sess.Close()
		return nil, a.ctx.Err()
	}
	ms := hs.Milliseconds()
	if ms <= 0 {
		ms = 1
	}
	a.rtcRTTMs.Store(ms)

	now := time.Now()
	slot := &rtcSlot{
		sess:      sess,
		createdAt: now,
		lastHopAt: now,
		maxAge:    a.randomHopAge(),
	}
	if a.onLog != nil {
		a.onLog("GFT-RTC connected (UDP :%d, Cipher=%s, RTT=%dms)", port, sess.Stats().Cipher, ms)
	}
	return slot, nil
}

func (a *ApexScheduler) dialRTCNow(timeout time.Duration) error {
	target := a.rtcPoolTarget()
	if target <= 1 {
		target = 1
	}

	var wg sync.WaitGroup
	var resMu sync.Mutex
	var slots []*rtcSlot
	var lastErr error
	for i := 0; i < target; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sl, err := a.dialOneRTCSlot(timeout)
			resMu.Lock()
			if err == nil && sl != nil {
				slots = append(slots, sl)
			} else if err != nil {
				lastErr = err
			}
			resMu.Unlock()
		}()
	}
	wg.Wait()

	if len(slots) == 0 {
		if lastErr == nil {
			lastErr = errors.New("gft: rtc pool dial failed")
		}
		return lastErr
	}

	a.mu.Lock()
	if a.closed || a.ctx.Err() != nil {
		a.mu.Unlock()
		for _, sl := range slots {
			sl.sess.Close()
		}
		return context.Canceled
	}
	a.rtcSlots = append(a.rtcSlots, slots...)
	a.mu.Unlock()
	return nil
}

func (a *ApexScheduler) rtcMaintainLoop() {
	defer a.wg.Done()
	a.mu.Lock()
	tickDur := a.maintainTick
	a.mu.Unlock()
	if tickDur <= 0 {
		tickDur = 2 * time.Second
	}
	t := time.NewTicker(tickDur)
	pingTicker := time.NewTicker(18 * time.Second)
	defer t.Stop()
	defer pingTicker.Stop()

	backoff := 2 * time.Second
	for {
		select {
		case <-a.ctx.Done():
			return
		case <-pingTicker.C:
			if rs := a.activeRTCForSend(); rs != nil {
				if rtt, err := rs.ProbeRTT(4 * time.Second); err == nil {
					ms := rtt.Milliseconds()
					if ms <= 0 {
						ms = 1
					}
					a.rtcRTTMs.Store(ms)
				}
			}
		case <-t.C:
			now := time.Now()
			target := a.rtcPoolTarget()
			_, _, hasHop := a.link.ParseHopRange()

			a.mu.Lock()
			var keepSlots []*rtcSlot
			var dueHop []*rtcSlot
			for _, sl := range a.rtcSlots {
				select {
				case <-sl.sess.Done():
					st := sl.sess.Stats()
					a.retiredRUp += st.UpBytes
					a.retiredRDown += st.DownBytes
					a.retiredFEC += st.FECRecovered
				default:
					if hasHop && now.Sub(sl.lastHopAt) >= sl.maxAge {
						dueHop = append(dueHop, sl)
					}
					keepSlots = append(keepSlots, sl)
				}
			}
			a.rtcSlots = keepSlots
			missing := target - len(keepSlots)
			hopFn := a.rtcHopFn
			a.mu.Unlock()

			// Execute 0ms in-place socket port-hop migration (zero stream interruption!)
			for _, sl := range dueHop {
				oldPort := sl.sess.RemotePort()
				nextPort := PickHopPort(a.link)
				if err := hopFn(sl.sess, nextPort); err == nil {
					a.mu.Lock()
					sl.lastHopAt = time.Now()
					sl.maxAge = a.randomHopAge()
					a.mu.Unlock()
					if a.onLog != nil {
						a.onLog("RTC 0ms Port-Hop migrated (UDP :%d -> :%d)", oldPort, nextPort)
					}
				} else if a.onLog != nil {
					a.onLog("RTC Port-Hop notice: %v", err)
				}
			}

			// Top up any closed/missing RTC slots
			if missing > 0 {
				var dialErr error
				var wg sync.WaitGroup
				var dMu sync.Mutex
				for i := 0; i < missing; i++ {
					wg.Add(1)
					go func() {
						defer wg.Done()
						sl, err := a.dialOneRTCSlot(6 * time.Second)
						if err != nil {
							dMu.Lock()
							dialErr = err
							dMu.Unlock()
							return
						}
						a.mu.Lock()
						if !a.closed && a.ctx.Err() == nil {
							a.rtcSlots = append(a.rtcSlots, sl)
						} else {
							sl.sess.Close()
						}
						a.mu.Unlock()
					}()
				}
				wg.Wait()
				if dialErr != nil {
					a.mu.Lock()
					curLen := len(a.rtcSlots)
					a.mu.Unlock()
					if curLen == 0 {
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

func (a *ApexScheduler) activeRTCForSend() *gftrtc.RTCSession {
	if a.link.EffectiveTransport() == "tcp" {
		return nil
	}
	now := time.Now()
	a.mu.Lock()
	var best *gftrtc.RTCSession
	bestStreams := int(^uint(0) >> 1)
	n := len(a.rtcSlots)
	start := 0
	if n > 1 {
		start = int(a.rtcRR.Add(1)-1) % n
	}
	for i := 0; i < n; i++ {
		sl := a.rtcSlots[(start+i)%n]
		if sl == nil || sl.sess == nil {
			continue
		}
		select {
		case <-sl.sess.Done():
			continue
		default:
		}
		if !sl.degradedAt.IsZero() && now.Sub(sl.degradedAt) < 15*time.Second {
			continue
		}
		sc := sl.sess.NumStreams()
		if best == nil || sc < bestStreams {
			best = sl.sess
			bestStreams = sc
		}
	}
	a.mu.Unlock()
	if best == nil {
		return nil
	}
	if a.link.EffectiveTransport() == "auto" {
		rRTT := a.rtcRTTMs.Load()
		tRTT := a.pool.rttMs.Load()
		if rRTT > 180 && tRTT > 0 && rRTT > tRTT*2 && a.pool.Stats().ActiveConns > 0 {
			return nil
		}
	}
	return best
}

func (a *ApexScheduler) markRTCDegraded(r *gftrtc.RTCSession, err error) {
	now := time.Now()
	a.mu.Lock()
	for _, sl := range a.rtcSlots {
		if sl != nil && sl.sess == r {
			sl.degradedAt = now
			if err != nil {
				a.lastErr = err.Error()
			}
			break
		}
	}
	a.mu.Unlock()
}

// OpenStream routes a TCP tunnel stream over GFT-RTC striped pool when healthy,
// falling back in 0ms to the uTLS TCP SessionPool if UDP fails or is throttled.
func (a *ApexScheduler) OpenStream(target string, first []byte) (DataStream, error) {
	if r := a.activeRTCForSend(); r != nil {
		st, err := r.OpenStream(target, first)
		if err == nil {
			return st, nil
		}
		a.markRTCDegraded(r, err)
	}
	if a.link.EffectiveTransport() == "rtc" {
		return nil, errors.New("gft: rtc track unavailable")
	}
	st, err := a.pool.OpenStream(target, first)
	if err != nil {
		return nil, err
	}
	return st, nil
}

// SchedulerUDPAssoc is a persistent virtual UDP association across RTC port hops
// and RTC<->TCP 0ms failovers, preserving the exact server-side NAT socket via ClientID.
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

	if r := u.sched.activeRTCForSend(); r != nil {
		sub, err := u.bindUnderlying(r, func() (UDPAssociation, error) {
			return r.OpenUDPWithID(u.id)
		})
		if err == nil {
			if serr := sub.SendTo(target, data); serr == nil {
				return nil
			} else {
				u.sched.markRTCDegraded(r, serr)
			}
		} else {
			u.sched.markRTCDegraded(r, err)
		}
	}

	if u.sched.link.EffectiveTransport() == "rtc" {
		return errors.New("gft: rtc udp track unavailable")
	}

	s, err := u.sched.pool.Acquire()
	if err != nil {
		return err
	}
	sub, err := u.bindUnderlying(s, func() (UDPAssociation, error) {
		return s.OpenUDPWithID(u.id)
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
				} else if rs, ok := sub.(*gftrtc.RTCUDPAssoc); ok {
					rs.CloseLocal()
				} else if ts, ok := sub.(*UDPStream); ok {
					ts.closeLocal()
				}
			}
		}
	})
	return nil
}

// Stats returns a live metrics snapshot across GFT-RTC and TCP-uTLS tracks.
func (a *ApexScheduler) Stats() ApexStats {
	ps := a.pool.Stats()
	a.mu.Lock()
	rUp, rDown, rFEC := a.retiredRUp, a.retiredRDown, a.retiredFEC
	var rPort, rStreams, rAliveCount int
	var sumPacing, maxLoss float64
	for _, sl := range a.rtcSlots {
		if sl == nil || sl.sess == nil {
			continue
		}
		st := sl.sess.Stats()
		rUp += st.UpBytes
		rDown += st.DownBytes
		rFEC += st.FECRecovered
		select {
		case <-sl.sess.Done():
		default:
			rAliveCount++
			if rPort == 0 {
				rPort = st.RemotePort
			}
			rStreams += st.ActiveStream
			sumPacing += st.PacingMbps
			if st.LossRate > maxLoss {
				maxLoss = st.LossRate
			}
		}
	}
	lErr := a.lastErr
	a.mu.Unlock()

	if lErr == "" {
		lErr = ps.LastErr
	}
	rRTT := a.rtcRTTMs.Load()
	tRTT := ps.RTTMs
	mode := "Starting"
	bestRTT := tRTT
	conns := ps.ActiveConns + ps.DrainingConns + rAliveCount
	rAlive := rAliveCount > 0
	if rAlive {
		if a.activeRTCForSend() != nil {
			mode = "RTC-Smart"
			if rRTT > 0 {
				bestRTT = rRTT
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
		RTCConnected:  rAlive,
		RTCPort:       rPort,
		RTCRTTMs:      rRTT,
		TCPRTTMs:      tRTT,
		RTTMs:         bestRTT,
		FECRecovered:  rFEC,
		LossRate:      maxLoss,
		PacingMbps:    sumPacing,
		ActiveConns:   conns,
		ActiveStreams: ps.ActiveStreams + rStreams,
		TotalUp:       ps.TotalUp + rUp,
		TotalDown:     ps.TotalDown + rDown,
		LastErr:       lErr,
	}
}

// Close shuts down GFT-RTC striped sessions, UDP associations, and TCP SessionPool cleanly.
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
	for _, sl := range a.rtcSlots {
		if sl != nil && sl.sess != nil {
			sl.sess.Close()
		}
	}
	a.rtcSlots = nil
	a.mu.Unlock()
	a.pool.Close()
	a.wg.Wait()
}
