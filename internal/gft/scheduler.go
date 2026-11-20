package gft

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"ghostframe/internal/gftrtc"
)

const (
	DefaultRTCPoolSize   = 2
	rtcHopMinAge         = 60 * time.Second
	rtcHopMaxAge         = 120 * time.Second
	rtcHopBytesQuota     = 64 * 1024 * 1024
	rtcIdleRateThreshold = 64 * 1024
	rtcHopStagger        = 25 * time.Second
	rtcDrainUDPIdle      = 15 * time.Second
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
	RTCPorts      [2]int  `json:"rtc_ports"`
	RTCRTTMs      int64   `json:"rtc_rtt_ms"`
	SRTTMs        int64   `json:"srtt_ms"`
	MinRTTMs      int64   `json:"min_rtt_ms"`
	TCPRTTMs      int64   `json:"tcp_rtt_ms"`
	RTTMs         int64   `json:"rtt_ms"`
	FECRecovered  uint64  `json:"fec_recovered"`
	HopCount      uint64  `json:"hop_count"`
	HopState      string  `json:"hop_state"`
	RekeyCount    uint64  `json:"rekey_count"`
	LossRate      float64 `json:"loss_rate"`
	PacingMbps    float64 `json:"pacing_mbps"`
	ActiveConns   int     `json:"active_conns"`
	ActiveStreams int     `json:"active_streams"`
	TotalUp       uint64  `json:"total_up"`
	TotalDown     uint64  `json:"total_down"`
	LastErr       string  `json:"last_err"`
}

type rtcSlot struct {
	channelIdx   int
	sess         *gftrtc.RTCSession
	createdAt    time.Time
	lastHopAt    time.Time
	lastHopBytes uint64
	maxAge       time.Duration
	degradedAt   time.Time
	pingFails    int
	streamFails  atomic.Int32
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

	hopMinAge        time.Duration
	hopMaxAge        time.Duration
	hopStagger       time.Duration
	hopBytesQuota    uint64
	idleRateThresh   uint64
	idlePauseEnabled bool
	drainUDPIdle     time.Duration
	maintainTick     time.Duration
	tcpRetryBase     time.Duration
	tcpCoolMin       time.Duration
	tcpCoolMax       time.Duration

	upMbps   atomic.Int64
	downMbps atomic.Int64

	mu           sync.Mutex
	rtcSlots     []*rtcSlot
	retiredRUp   uint64
	retiredRDown uint64
	retiredFEC   uint64
	retiredHops  uint64
	retiredRekey uint64
	lastErr      string

	rtcRR       atomic.Uint64
	nextAssocID atomic.Uint32
	udpMu       sync.Mutex
	udpAssocs   map[uint16]*SchedulerUDPAssoc

	rtcRTTMs  atomic.Int64
	tcpWakeCh chan struct{}
	wakeHopCh chan struct{}

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
	var schedLink *Link
	if l != nil {
		cp := *l
		schedLink = &cp
	}
	a := &ApexScheduler{
		link:             schedLink,
		ps:               ps,
		clientID:         cid,
		limiter:          tcpLim,
		tcpLimiter:       tcpLim,
		rtcLimiter:       rtcLim,
		onLog:            logf,
		hopMinAge:        rtcHopMinAge,
		hopMaxAge:        rtcHopMaxAge,
		hopStagger:       rtcHopStagger,
		hopBytesQuota:    rtcHopBytesQuota,
		idleRateThresh:   rtcIdleRateThreshold,
		idlePauseEnabled: true,
		drainUDPIdle:     rtcDrainUDPIdle,
		maintainTick:     2 * time.Second,
		tcpRetryBase:     4 * time.Second,
		tcpCoolMin:       5 * time.Minute,
		tcpCoolMax:       15 * time.Minute,
		udpAssocs:        make(map[uint16]*SchedulerUDPAssoc),
		tcpWakeCh:        make(chan struct{}, 1),
		wakeHopCh:        make(chan struct{}, 1),
		ctx:              ctx,
		cancel:           cancel,
	}
	if schedLink != nil {
		a.upMbps.Store(int64(schedLink.UpMbps))
		a.downMbps.Store(int64(schedLink.DownMbps))
	}
	pool := NewSessionPool(schedLink, ps, tcpPoolSize, logf)
	pool.SetCooldownGuard(a.hasHealthyRTC)
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
	a.rtcHopFn = func(sess *gftrtc.RTCSession, _ int) error {
		_, err := sess.HopValidated(func() int { return PickHopPort(a.link) }, 4, 600*time.Millisecond)
		return err
	}
	return a
}

func (a *ApexScheduler) rtcPoolTarget() int {
	if IsLowMemMode() {
		return 1
	}
	return DefaultRTCPoolSize // 2 concurrent striped UDP 5-tuples
}

// ClientID returns the 8-byte session-group identifier used for server NAT preservation.
func (a *ApexScheduler) ClientID() [8]byte { return a.clientID }

// SetHopTimingsForTest overrides port-hop and maintain intervals for unit tests.
func (a *ApexScheduler) SetHopTimingsForTest(minAge, maxAge, drainUDPIdle, tick time.Duration) {
	a.mu.Lock()
	a.hopMinAge = minAge
	a.hopMaxAge = maxAge
	if maxAge < 5*time.Second {
		a.hopStagger = 0
		a.idlePauseEnabled = false
	}
	a.drainUDPIdle = drainUDPIdle
	a.maintainTick = tick
	a.mu.Unlock()
}

// SetLazyHopPolicyForTest configures traffic-aware lazy hop parameters for unit tests.
func (a *ApexScheduler) SetLazyHopPolicyForTest(enabled bool, idleBps uint64, hopBytes uint64, stagger time.Duration) {
	a.mu.Lock()
	a.idlePauseEnabled = enabled
	a.idleRateThresh = idleBps
	a.hopBytesQuota = hopBytes
	a.hopStagger = stagger
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

// SetTCPBackoffForTest overrides initial retry and circuit-breaker cooldown durations for tests.
func (a *ApexScheduler) SetTCPBackoffForTest(base, coolMin, coolMax time.Duration) {
	a.mu.Lock()
	a.tcpRetryBase = base
	a.tcpCoolMin = coolMin
	a.tcpCoolMax = coolMax
	a.mu.Unlock()
}

// UpdateBandwidth updates pacing targets on active GFT-RTC sessions live, dividing manual targets evenly.
func (a *ApexScheduler) UpdateBandwidth(upMbps, downMbps int) {
	a.upMbps.Store(int64(upMbps))
	a.downMbps.Store(int64(downMbps))
	a.mu.Lock()
	n := len(a.rtcSlots)
	if n < 1 {
		n = 1
	}
	perUp := SplitBandwidthMbps(upMbps, n)
	for _, sl := range a.rtcSlots {
		if sl != nil && sl.sess != nil {
			sl.sess.UpdateBandwidth(perUp)
		}
	}
	a.mu.Unlock()
}

func (a *ApexScheduler) hasHealthyRTC() bool {
	now := time.Now()
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, sl := range a.rtcSlots {
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
		return true
	}
	return false
}

func (a *ApexScheduler) wakeTCPTrack() {
	if a.tcpWakeCh != nil {
		select {
		case a.tcpWakeCh <- struct{}{}:
		default:
		}
	}
	if a.pool != nil {
		a.pool.WakeReconnect()
	}
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
								a.onLog("[TCP] Track deferred (%v); running on GFT-RTC Smart-Brutal", r2.err)
							}
							a.launchLoop(func() { a.retryTCPStartLoop(connectTimeout) })
						} else if a.onLog != nil {
							a.onLog("[RTC] Track unavailable (%v); 0ms fallback active on [TCP] uTLS", r2.err)
						}
					}
				}
			})
			a.launchLoop(a.rtcMaintainLoop)
			return nil
		}

		r2 := <-ch
		if r2.err != nil {
			rtcErr, tcpErr := r1.err, r2.err
			if r1.kind == "tcp" {
				tcpErr, rtcErr = r1.err, r2.err
			}
			if a.onLog != nil {
				a.onLog("[Auto] Dual-track connect failed (rtc=%v | tcp=%v)", rtcErr, tcpErr)
			}
			return fmt.Errorf("rtc: %v; tcp: %v", rtcErr, tcpErr)
		}
		if r1.kind == "tcp" {
			if a.onLog != nil {
				a.onLog("[TCP] Track deferred (%v); running on GFT-RTC Smart-Brutal", r1.err)
			}
			a.launchLoop(func() { a.retryTCPStartLoop(connectTimeout) })
		} else if a.onLog != nil {
			a.onLog("[RTC] Track unavailable (%v); 0ms fallback active on [TCP] uTLS", r1.err)
		}
		a.launchLoop(a.rtcMaintainLoop)
		return nil
	}
}

func (a *ApexScheduler) retryTCPStartLoop(timeout time.Duration) {
	defer a.wg.Done()
	a.mu.Lock()
	base := a.tcpRetryBase
	coolMin := a.tcpCoolMin
	coolMax := a.tcpCoolMax
	a.mu.Unlock()
	if base <= 0 {
		base = 4 * time.Second
	}
	if coolMin <= 0 {
		coolMin = 5 * time.Minute
	}
	if coolMax <= 0 {
		coolMax = 15 * time.Minute
	}

	backoff := base
	fails := 1 // Initial synchronous Start() attempt already failed.
	trippedLogged := false

	for {
		var waitDur time.Duration
		if fails >= 3 && a.hasHealthyRTC() {
			waitDur = coolMin
			if fails >= 4 {
				waitDur = coolMax
			}
			if !trippedLogged {
				trippedLogged = true
				if a.onLog != nil {
					a.onLog("[TCP] :%d track circuit-breaker open after %d failures while RTC is healthy; cooling %v", a.link.Port, fails, waitDur)
				}
			}
		} else {
			jit := time.Duration(randRange(50, 400)) * time.Millisecond
			if base < 200*time.Millisecond {
				jit = 0
			}
			waitDur = backoff + jit
		}

		timer := time.NewTimer(waitDur)
		select {
		case <-a.ctx.Done():
			timer.Stop()
			return
		case <-a.tcpWakeCh:
			timer.Stop()
			fails = 0
			backoff = base
			trippedLogged = false
		case <-timer.C:
		}
		if a.ctx.Err() != nil {
			return
		}
		if err := a.pool.Start(timeout); err == nil {
			return
		}
		fails++
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
	return a.dialOneRTCSlotWithIndex(timeout, 1)
}

func (a *ApexScheduler) dialOneRTCSlotWithIndex(timeout time.Duration, channelIdx int) (*rtcSlot, error) {
	if channelIdx <= 0 {
		channelIdx = 1
	}
	if err := a.rtcLimiter.Wait(a.ctx); err != nil {
		return nil, err
	}
	port := PickHopPort(a.link)
	poolN := a.rtcPoolTarget()
	scaledLink := *a.link
	scaledLink.UpMbps = SplitBandwidthMbps(int(a.upMbps.Load()), poolN)
	scaledLink.DownMbps = SplitBandwidthMbps(int(a.downMbps.Load()), poolN)

	dialCtx, cancel := context.WithTimeout(a.ctx, timeout)
	defer cancel()
	sess, hs, err := a.rtcDialFn(dialCtx, &scaledLink, a.ps, port, timeout)
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
	chTag := channelIdx
	sess.SetOnRekey(func(epoch uint32) {
		if a.onLog != nil {
			a.onLog("[RTC#%d] Key rotated cleanly (epoch=%d)", chTag, epoch)
		}
	})

	ms := hs.Milliseconds()
	if ms <= 0 {
		ms = 1
	}
	a.rtcRTTMs.Store(ms)

	now := time.Now()
	maxAge := a.randomHopAge()
	if channelIdx == 2 && a.hopStagger > 0 {
		maxAge += a.hopStagger
	}
	slot := &rtcSlot{
		channelIdx: channelIdx,
		sess:       sess,
		createdAt:  now,
		lastHopAt:  now,
		maxAge:     maxAge,
	}
	if a.onLog != nil {
		a.onLog("[RTC#%d] GFT-RTC connected (UDP :%d, Cipher=%s, RTT=%dms)", channelIdx, port, sess.Stats().Cipher, ms)
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
		chIdx := i + 1
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			sl, err := a.dialOneRTCSlotWithIndex(timeout, idx)
			resMu.Lock()
			if err == nil && sl != nil {
				slots = append(slots, sl)
			} else if err != nil {
				lastErr = err
			}
			resMu.Unlock()
		}(chIdx)
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

// OnSystemWake resets stale RTT/CC state after OS sleep/wake or network changes and triggers wake probing.
func (a *ApexScheduler) OnSystemWake() {
	if a == nil {
		return
	}
	a.mu.Lock()
	slots := make([]*rtcSlot, len(a.rtcSlots))
	copy(slots, a.rtcSlots)
	a.mu.Unlock()

	for _, sl := range slots {
		if sl != nil && sl.sess != nil {
			sl.sess.ResetRTTOnWake()
		}
	}
	if a.onLog != nil {
		a.onLog("[SystemWake] Resetting RTT estimators & probing active tunnels")
	}
	if a.wakeHopCh != nil {
		select {
		case a.wakeHopCh <- struct{}{}:
		default:
		}
	}
	a.wakeTCPTrack()
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
	pingTicker := time.NewTicker(10 * time.Second)
	defer t.Stop()
	defer pingTicker.Stop()

	backoff := 2 * time.Second
	for {
		select {
		case <-a.ctx.Done():
			return
		case <-a.wakeHopCh:
			if a.handleEmergencyProbeAndHop(1500*time.Millisecond, true) {
				a.reapAndTopUpSlots(&backoff)
			}
		case <-pingTicker.C:
			if a.handleEmergencyProbeAndHop(3*time.Second, false) {
				a.reapAndTopUpSlots(&backoff)
			}
		case <-t.C:
			a.reapAndTopUpSlots(&backoff)
		}
	}
}

func (a *ApexScheduler) reapAndTopUpSlots(backoff *time.Duration) {
	now := time.Now()
	target := a.rtcPoolTarget()
	_, _, hasHop := a.link.ParseHopRange()

	a.mu.Lock()
	var keepSlots []*rtcSlot
	var dueHop []*rtcSlot
	hasCh := make(map[int]bool, target)
	idlePause := a.idlePauseEnabled
	idleThresh := a.idleRateThresh
	bytesQuota := a.hopBytesQuota
	for _, sl := range a.rtcSlots {
		select {
		case <-sl.sess.Done():
			st := sl.sess.Stats()
			a.retiredRUp += st.UpBytes
			a.retiredRDown += st.DownBytes
			a.retiredFEC += st.FECRecovered
			a.retiredHops += st.HopCount
			a.retiredRekey += st.RekeyCount
		default:
			if hasHop {
				st := sl.sess.Stats()
				totalTraffic := st.UpBytes + st.DownBytes
				var bytesDelta uint64
				if totalTraffic > sl.lastHopBytes {
					bytesDelta = totalTraffic - sl.lastHopBytes
				}
				if bytesQuota > 0 && bytesDelta >= bytesQuota {
					dueHop = append(dueHop, sl)
				} else if now.Sub(sl.lastHopAt) >= sl.maxAge {
					if !idlePause || sl.sess.Recent30sBytesPerSec() >= idleThresh {
						dueHop = append(dueHop, sl)
					}
				}
			}
			if sl.channelIdx > 0 {
				hasCh[sl.channelIdx] = true
			}
			keepSlots = append(keepSlots, sl)
		}
	}
	a.rtcSlots = keepSlots
	missing := target - len(keepSlots)
	hopFn := a.rtcHopFn
	allRTCDown := len(keepSlots) == 0
	a.mu.Unlock()

	if allRTCDown {
		a.wakeTCPTrack()
	}

	// Execute Make-Before-Break 0ms socket port-hop migration quietly (updates header badge, no log spam).
	for _, sl := range dueHop {
		nextPort := PickHopPort(a.link)
		if err := hopFn(sl.sess, nextPort); err == nil {
			st := sl.sess.Stats()
			a.mu.Lock()
			sl.lastHopAt = time.Now()
			sl.lastHopBytes = st.UpBytes + st.DownBytes
			sl.maxAge = a.randomHopAge()
			a.mu.Unlock()
		} else {
			a.mu.Lock()
			sl.lastHopAt = time.Now().Add(-sl.maxAge + 15*time.Second)
			a.mu.Unlock()
		}
	}

	// Top up any closed/missing RTC slots while preserving stable channel labels #1 / #2.
	if missing > 0 {
		var dialErr error
		var wg sync.WaitGroup
		var dMu sync.Mutex
		missingIdxs := make([]int, 0, missing)
		for idx := 1; idx <= target && len(missingIdxs) < missing; idx++ {
			if !hasCh[idx] {
				missingIdxs = append(missingIdxs, idx)
				hasCh[idx] = true
			}
		}
		for len(missingIdxs) < missing {
			missingIdxs = append(missingIdxs, len(missingIdxs)+1)
		}
		for _, chIdx := range missingIdxs {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				sl, err := a.dialOneRTCSlotWithIndex(6*time.Second, idx)
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
			}(chIdx)
		}
		wg.Wait()
		if up := int(a.upMbps.Load()); up > 0 {
			a.mu.Lock()
			n := len(a.rtcSlots)
			if n > 0 {
				perUp := SplitBandwidthMbps(up, n)
				for _, sl := range a.rtcSlots {
					if sl != nil && sl.sess != nil {
						sl.sess.UpdateBandwidth(perUp)
					}
				}
			}
			a.mu.Unlock()
		}
		if dialErr != nil {
			a.mu.Lock()
			curLen := len(a.rtcSlots)
			a.mu.Unlock()
			if curLen == 0 {
				select {
				case <-a.ctx.Done():
					return
				case <-time.After(*backoff):
				}
				*backoff *= 2
				if *backoff > 20*time.Second {
					*backoff = 20 * time.Second
				}
			}
		} else {
			*backoff = 2 * time.Second
		}
	}
}

func (a *ApexScheduler) handleEmergencyProbeAndHop(probeTimeout time.Duration, forceOnFail bool) bool {
	_, _, hasHop := a.link.ParseHopRange()
	a.mu.Lock()
	slots := make([]*rtcSlot, len(a.rtcSlots))
	copy(slots, a.rtcSlots)
	hopFn := a.rtcHopFn
	a.mu.Unlock()

	var closedAny atomic.Bool
	var wg sync.WaitGroup
	for _, sl := range slots {
		if sl == nil || sl.sess == nil {
			continue
		}
		select {
		case <-sl.sess.Done():
			closedAny.Store(true)
			continue
		default:
		}
		wg.Add(1)
		go func(slot *rtcSlot) {
			defer wg.Done()
			if rtt, err := slot.sess.ProbeRTT(probeTimeout); err == nil {
				ms := rtt.Milliseconds()
				if ms <= 0 {
					ms = 1
				}
				a.rtcRTTMs.Store(ms)
				a.mu.Lock()
				slot.pingFails = 0
				slot.degradedAt = time.Time{}
				a.mu.Unlock()
				slot.streamFails.Store(0)
				return
			}
			a.mu.Lock()
			slot.pingFails++
			fails := slot.pingFails
			chIdx := slot.channelIdx
			a.mu.Unlock()
			if !forceOnFail && fails < 2 {
				return
			}
			oldPort := slot.sess.RemotePort()
			if hasHop && hopFn != nil {
				if herr := hopFn(slot.sess, PickHopPort(a.link)); herr == nil {
					st := slot.sess.Stats()
					a.mu.Lock()
					slot.lastHopAt = time.Now()
					slot.lastHopBytes = st.UpBytes + st.DownBytes
					slot.maxAge = a.randomHopAge()
					slot.pingFails = 0
					slot.degradedAt = time.Time{}
					a.mu.Unlock()
					slot.streamFails.Store(0)
					if a.onLog != nil {
						a.onLog("[RTC#%d] Emergency MBB hop recovered path (UDP :%d -> :%d)", chIdx, oldPort, slot.sess.RemotePort())
					}
					return
				}
			}
			slot.sess.Close()
			closedAny.Store(true)
		}(sl)
	}
	wg.Wait()
	return closedAny.Load()
}

func (a *ApexScheduler) activeSlotForSend(exclude *gftrtc.RTCSession) *rtcSlot {
	if a.link.EffectiveTransport() == "tcp" {
		return nil
	}
	now := time.Now()
	a.mu.Lock()
	var best *rtcSlot
	bestStreams := int(^uint(0) >> 1)
	n := len(a.rtcSlots)
	start := 0
	if n > 1 {
		start = int(a.rtcRR.Add(1)-1) % n
	}
	for i := 0; i < n; i++ {
		sl := a.rtcSlots[(start+i)%n]
		if sl == nil || sl.sess == nil || sl.sess == exclude {
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
			best = sl
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

func (a *ApexScheduler) activeRTCForSend() *gftrtc.RTCSession {
	sl := a.activeSlotForSend(nil)
	if sl == nil {
		return nil
	}
	return sl.sess
}

func (a *ApexScheduler) markRTCDegraded(r *gftrtc.RTCSession, err error) {
	now := time.Now()
	a.mu.Lock()
	for _, sl := range a.rtcSlots {
		if sl != nil && sl.sess == r {
			sl.degradedAt = now
			sl.streamFails.Add(1)
			if err != nil {
				a.lastErr = err.Error()
			}
			break
		}
	}
	a.mu.Unlock()
	if a.wakeHopCh != nil {
		select {
		case a.wakeHopCh <- struct{}{}:
		default:
		}
	}
	if !a.hasHealthyRTC() {
		a.wakeTCPTrack()
	}
}

// OpenStream routes a TCP tunnel stream over GFT-RTC striped pool when healthy,
// falling back in 0ms to the uTLS TCP SessionPool if UDP fails or is throttled.
func (a *ApexScheduler) OpenStream(target string, first []byte) (DataStream, error) {
	if sl := a.activeSlotForSend(nil); sl != nil {
		st, err := sl.sess.OpenStream(target, first)
		if err == nil {
			sl.streamFails.Store(0)
			return st, nil
		}
		a.markRTCDegraded(sl.sess, err)
		if alt := a.activeSlotForSend(sl.sess); alt != nil {
			st2, err2 := alt.sess.OpenStream(target, first)
			if err2 == nil {
				alt.streamFails.Store(0)
				return st2, nil
			}
			a.markRTCDegraded(alt.sess, err2)
		}
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
	rHops, rRekey := a.retiredHops, a.retiredRekey
	var rPort, rStreams, rAliveCount int
	var rtcPorts [2]int
	var srttMs, minRTTMs int64
	var anyActiveRate bool
	var sumPacing, maxLoss float64
	idlePause := a.idlePauseEnabled
	idleThresh := a.idleRateThresh

	for _, sl := range a.rtcSlots {
		if sl == nil || sl.sess == nil {
			continue
		}
		st := sl.sess.Stats()
		rUp += st.UpBytes
		rDown += st.DownBytes
		rFEC += st.FECRecovered
		rHops += st.HopCount
		rRekey += st.RekeyCount
		select {
		case <-sl.sess.Done():
		default:
			rAliveCount++
			if rPort == 0 {
				rPort = st.RemotePort
			}
			if sl.channelIdx == 1 && rtcPorts[0] == 0 {
				rtcPorts[0] = st.RemotePort
			} else if sl.channelIdx == 2 && rtcPorts[1] == 0 {
				rtcPorts[1] = st.RemotePort
			} else if rtcPorts[0] == 0 {
				rtcPorts[0] = st.RemotePort
			} else if rtcPorts[1] == 0 {
				rtcPorts[1] = st.RemotePort
			}
			if srttMs == 0 || (st.SRTTMs > 0 && st.SRTTMs < srttMs) {
				srttMs = st.SRTTMs
			}
			if minRTTMs == 0 || (st.MinRTTMs > 0 && st.MinRTTMs < minRTTMs) {
				minRTTMs = st.MinRTTMs
			}
			if st.Rate30sBps >= idleThresh {
				anyActiveRate = true
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

	_, _, hasHop := a.link.ParseHopRange()
	hopState := "Offline"
	if rAliveCount > 0 {
		if !hasHop {
			hopState = "Fixed"
		} else if idlePause && !anyActiveRate {
			hopState = "Paused(Idle)"
		} else {
			hopState = "Active"
		}
	}

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
		RTCPorts:      rtcPorts,
		RTCRTTMs:      rRTT,
		SRTTMs:        srttMs,
		MinRTTMs:      minRTTMs,
		TCPRTTMs:      tRTT,
		RTTMs:         bestRTT,
		FECRecovered:  rFEC,
		HopCount:      rHops,
		HopState:      hopState,
		RekeyCount:    rRekey,
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
