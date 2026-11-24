package gft

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"math"
	"sync"
	"sync/atomic"
	"time"
)

const (
	DefaultPoolSize       = 4
	MinPoolSize           = 1
	MaxPoolSize           = 8
	rotateMinAge          = 15 * time.Minute
	rotateMaxAge          = 25 * time.Minute
	rotateMaxBytes        = uint64(512 * 1024 * 1024)
	defaultIdleShrinkDur  = 90 * time.Second
	scaleStreamsPerConn   = 4
	scaleRateBytesPerSec  = uint64(256 * 1024)
	shrinkRateBytesPerSec = uint64(64 * 1024)
	scaleUpCooldown       = 2 * time.Second
	idlePingMinMs         = 25000
	idlePingMaxMs         = 55000
)

type poolEntry struct {
	id           uint64
	sess         *Session
	createdAt    time.Time
	lastActiveAt time.Time
	lastBytes    uint64
	maxAge       time.Duration
	draining     bool
}

// PoolStats captures live metrics across the striped SessionPool.
type PoolStats struct {
	TargetSize    int    `json:"target_size"`
	ActiveConns   int    `json:"active_conns"`
	DrainingConns int    `json:"draining_conns"`
	ActiveStreams int    `json:"active_streams"`
	TotalUp       uint64 `json:"total_up"`
	TotalDown     uint64 `json:"total_down"`
	RTTMs         int64  `json:"rtt_ms"`
	HandshakeMs   int64  `json:"handshake_ms"`
	LastErr       string `json:"last_err"`
}

// SessionPool manages N concurrent GFT v2 sessions with least-loaded scheduling,
// smooth connection rotation, in-band RTT measurement, and exponential backoff healing.
type SessionPool struct {
	link           *Link
	ps             *ParamStore
	size           int
	dialFn         func(ctx context.Context, l *Link, ps *ParamStore, flags uint16, timeout time.Duration) (*Session, time.Duration, error)
	onLog          func(string, ...any)
	onStatus       func(PoolStats)
	shouldCoolDown func() bool
	wakeCh         chan struct{}

	mu             sync.Mutex
	entries        []*poolEntry
	nextEntryID    uint64
	retiredUp      uint64
	retiredDown    uint64
	lastErr        string
	minSize        int
	idleShrinkDur  time.Duration
	elastic        bool
	lastScaleAt    time.Time
	lastSampleAt   time.Time
	lastTotalBytes uint64
	recentBps      uint64
	lastTrafficAt  time.Time

	emergMu   sync.Mutex
	emergWait chan struct{}
	emergSess *Session
	emergErr  error

	rttMs atomic.Int64
	hsMs  atomic.Int64

	bond        *BondGroup
	poolEpoch   uint32
	nextBondSeq atomic.Uint32
	bondReady   atomic.Bool

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewSessionPool creates and starts a background-maintained SessionPool.
func NewSessionPool(l *Link, ps *ParamStore, size int, logf func(string, ...any)) *SessionPool {
	if size < MinPoolSize {
		size = EffectivePoolSize()
	}
	if size > MaxPoolSize {
		size = MaxPoolSize
	}
	var ep [4]byte
	_, _ = rand.Read(ep[:])
	epoch := binary.BigEndian.Uint32(ep[:]) | 1
	ctx, cancel := context.WithCancel(context.Background())
	p := &SessionPool{
		link:          l,
		ps:            ps,
		size:          size,
		minSize:       size,
		idleShrinkDur: defaultIdleShrinkDur,
		dialFn:        DialSession,
		onLog:         logf,
		wakeCh:        make(chan struct{}, 1),
		bond:          NewBondGroup(nil),
		poolEpoch:     epoch,
		ctx:           ctx,
		cancel:        cancel,
	}
	return p
}

// SetElasticPolicy enables on-demand scaling between minSize (idle floor) and pool.size (ceiling),
// shrinking excess idle connections back to minSize after idleShrink with low traffic.
func (p *SessionPool) SetElasticPolicy(minSize int, idleShrink time.Duration) {
	if p == nil {
		return
	}
	if minSize < MinPoolSize {
		minSize = MinPoolSize
	}
	if minSize > p.size {
		minSize = p.size
	}
	if idleShrink <= 0 {
		idleShrink = defaultIdleShrinkDur
	}
	p.mu.Lock()
	p.elastic = true
	p.minSize = minSize
	p.idleShrinkDur = idleShrink
	p.mu.Unlock()
}

// NoteDemand notifies the elastic pool of fresh traffic/stream demand so it can scale up smoothly.
func (p *SessionPool) NoteDemand() {
	if p == nil {
		return
	}
	now := time.Now()
	shouldWake := false
	p.mu.Lock()
	p.lastTrafficAt = now
	if p.elastic {
		activeCount := 0
		totalStreams := 0
		hasBacklog := false
		for _, e := range p.entries {
			if e.draining {
				continue
			}
			select {
			case <-e.sess.Done():
				continue
			default:
			}
			activeCount++
			totalStreams += e.sess.NumStreams()
			if e.sess.PendingWriteBytes() >= 64*1024 {
				hasBacklog = true
			}
		}
		bondStreams := 0
		if p.bond != nil {
			bondStreams = p.bond.NumStreams()
			totalStreams += bondStreams
		}
		if activeCount < p.size && now.Sub(p.lastScaleAt) >= scaleUpCooldown {
			if totalStreams >= activeCount*scaleStreamsPerConn ||
				p.recentBps >= scaleRateBytesPerSec ||
				hasBacklog ||
				(bondStreams > 0 && activeCount < 2) {
				shouldWake = true
			}
		}
	}
	p.mu.Unlock()
	if shouldWake {
		p.WakeReconnect()
	}
}

// SetCooldownGuard registers a predicate indicating whether long circuit-breaker cooldowns
// should be used when repeated TCP reconnect attempts fail (e.g., while Kestrel-RTC is healthy).
func (p *SessionPool) SetCooldownGuard(fn func() bool) {
	p.mu.Lock()
	p.shouldCoolDown = fn
	p.mu.Unlock()
}

// WakeReconnect interrupts any cooldown sleep so maintainLoop retries TCP immediately.
func (p *SessionPool) WakeReconnect() {
	if p == nil || p.wakeCh == nil {
		return
	}
	select {
	case p.wakeCh <- struct{}{}:
	default:
	}
}

// Start connects the initial pool (waiting until at least 1 session is ready or ctx expires)
// and starts background keeper and in-band RTT prober goroutines.
func (p *SessionPool) Start(connectTimeout time.Duration) error {
	// Dial first session synchronously so caller knows credentials & network work immediately.
	e, hs, err := p.dialOne(connectTimeout)
	if err != nil {
		return err
	}
	p.hsMs.Store(hs.Milliseconds())
	p.mu.Lock()
	p.entries = append(p.entries, e)
	p.mu.Unlock()

	if p.onLog != nil {
		p.onLog("[TCP] Pool slot #%d connected via uTLS (%s), handshake=%v", e.id, p.link.EffectiveFP(), hs.Round(time.Millisecond))
	}

	p.wg.Add(2)
	go p.maintainLoop()
	go p.inBandPingLoop()
	return nil
}

func (p *SessionPool) dialOne(timeout time.Duration) (*poolEntry, time.Duration, error) {
	id := atomic.AddUint64(&p.nextEntryID, 1)
	dialCtx, cancel := context.WithTimeout(p.ctx, timeout)
	defer cancel()

	sess, hs, err := p.dialFn(dialCtx, p.link, p.ps, uint16(p.size), timeout)
	if err != nil {
		return nil, 0, err
	}
	sess.SetOnPing(func(rtt time.Duration) {
		ms := rtt.Milliseconds()
		if ms <= 0 {
			ms = 1
		}
		p.rttMs.Store(ms)
	})
	if p.bond != nil {
		p.bond.AddSession(sess)
		sess.SetOnBondCap(func() {
			p.bondReady.Store(true)
		})
	}
	now := time.Now()
	maxAge := time.Duration(randRange(int(rotateMinAge.Seconds()), int(rotateMaxAge.Seconds()))) * time.Second
	entry := &poolEntry{
		id:           id,
		sess:         sess,
		createdAt:    now,
		lastActiveAt: now,
		maxAge:       maxAge,
	}
	return entry, hs, nil
}

func (p *SessionPool) maintainLoop() {
	defer p.wg.Done()
	backoff := 250 * time.Millisecond
	consecFails := 0
	t := time.NewTicker(1 * time.Second)
	defer t.Stop()

	for {
		active, need := p.reapAndCheck()
		if need > 0 {
			// Dial missing connections concurrently up to need, with exponential backoff on failure.
			var dialWG sync.WaitGroup
			var anyOK atomic.Bool
			var lastDialErr atomic.Value
			for i := 0; i < need; i++ {
				dialWG.Add(1)
				go func() {
					defer dialWG.Done()
					e, hs, err := p.dialOne(8 * time.Second)
					if err != nil {
						lastDialErr.Store(err.Error())
						return
					}
					anyOK.Store(true)
					p.hsMs.Store(hs.Milliseconds())
					p.mu.Lock()
					p.entries = append(p.entries, e)
					p.lastErr = ""
					p.mu.Unlock()
					if p.onLog != nil {
						p.onLog("[TCP] Pool slot #%d online (active=%d/%d, hs=%v)", e.id, active+1, p.size, hs.Round(time.Millisecond))
					}
				}()
			}
			dialWG.Wait()
			if anyOK.Load() {
				backoff = 250 * time.Millisecond
				consecFails = 0
			} else if p.ctx.Err() == nil {
				consecFails++
				waitDur := backoff
				p.mu.Lock()
				guard := p.shouldCoolDown
				p.mu.Unlock()
				if consecFails >= 3 && guard != nil && guard() {
					waitDur = 5 * time.Minute
					if consecFails >= 4 {
						waitDur = 15 * time.Minute
					}
				}
				if msg, ok := lastDialErr.Load().(string); ok {
					p.mu.Lock()
					p.lastErr = msg
					p.mu.Unlock()
					if p.onLog != nil {
						p.onLog("[TCP] Pool reconnect failed (%s), retrying in %v", msg, waitDur)
					}
				}
				timer := time.NewTimer(waitDur)
				select {
				case <-p.ctx.Done():
					timer.Stop()
					return
				case <-p.wakeCh:
					timer.Stop()
					consecFails = 0
					backoff = 250 * time.Millisecond
				case <-timer.C:
				}
				backoff *= 2
				if backoff > 5*time.Second {
					backoff = 5 * time.Second
				}
				continue
			}
		}

		select {
		case <-p.ctx.Done():
			return
		case <-p.wakeCh:
			consecFails = 0
			backoff = 250 * time.Millisecond
		case <-t.C:
		}
	}
}

func (p *SessionPool) reapAndCheck() (activeCount int, needed int) {
	now := time.Now()
	p.mu.Lock()
	defer p.mu.Unlock()

	bondStreams := 0
	if p.bond != nil {
		bondStreams = p.bond.NumStreams()
	}

	var totalBytes uint64 = p.retiredUp + p.retiredDown
	totalStreams := bondStreams
	hasBacklog := false

	kept := make([]*poolEntry, 0, len(p.entries))
	for _, e := range p.entries {
		select {
		case <-e.sess.Done():
			// Dead session: retire counters and discard.
			p.retiredUp += e.sess.UpBytes.Load()
			p.retiredDown += e.sess.DownBytes.Load()
			p.bond.RemoveSession(e.sess, false)
			continue
		default:
		}

		curBytes := e.sess.TotalBytes()
		totalBytes += curBytes
		curStreams := e.sess.NumStreams()
		if curStreams > 0 || curBytes != e.lastBytes {
			e.lastActiveAt = now
			e.lastBytes = curBytes
		}

		if !e.draining && (now.Sub(e.createdAt) >= e.maxAge || curBytes >= rotateMaxBytes) {
			e.draining = true
			e.sess.draining.Store(true)
			if p.onLog != nil {
				p.onLog("[TCP] Pool slot #%d entering graceful drain (age=%v, bytes=%dMB)", e.id, now.Sub(e.createdAt).Round(time.Second), curBytes>>20)
			}
		}

		if e.draining {
			if curStreams == 0 && (bondStreams == 0 || now.Sub(e.createdAt) >= e.maxAge+45*time.Second) {
				p.retiredUp += e.sess.UpBytes.Load()
				p.retiredDown += e.sess.DownBytes.Load()
				p.bond.RemoveSession(e.sess, false)
				e.sess.Close()
				continue
			}
			kept = append(kept, e)
			continue
		}

		activeCount++
		totalStreams += curStreams
		if e.sess.PendingWriteBytes() >= 64*1024 {
			hasBacklog = true
		}
		kept = append(kept, e)
	}
	p.entries = kept

	// Update aggregate throughput estimate for elastic scale-up / idle shrink decisions.
	if p.lastSampleAt.IsZero() {
		p.lastSampleAt = now
		p.lastTotalBytes = totalBytes
		if totalStreams > 0 {
			p.lastTrafficAt = now
		}
	} else if dt := now.Sub(p.lastSampleAt); dt >= time.Second {
		var delta uint64
		if totalBytes > p.lastTotalBytes {
			delta = totalBytes - p.lastTotalBytes
		}
		instBps := uint64(float64(delta) / dt.Seconds())
		if p.recentBps == 0 {
			p.recentBps = instBps
		} else {
			p.recentBps = (p.recentBps*3 + instBps*7) / 10
		}
		p.lastSampleAt = now
		p.lastTotalBytes = totalBytes
		if delta > 0 || totalStreams > 0 {
			p.lastTrafficAt = now
		}
	}

	if !p.elastic {
		if activeCount < p.size {
			needed = p.size - activeCount
		}
		return activeCount, needed
	}

	// Elastic mode: maintain minSize floor when idle, scale up smoothly +1 under demand,
	// and gracefully drain excess idle connections back to minSize.
	minSz := p.minSize
	if minSz < MinPoolSize {
		minSz = MinPoolSize
	}
	if minSz > p.size {
		minSz = p.size
	}
	if activeCount < minSz {
		return activeCount, minSz - activeCount
	}

	// Scale up by at most +1 per cooldown interval when demand justifies more TCP stripes.
	if activeCount < p.size && now.Sub(p.lastScaleAt) >= scaleUpCooldown {
		if totalStreams >= activeCount*scaleStreamsPerConn ||
			p.recentBps >= scaleRateBytesPerSec ||
			hasBacklog ||
			(bondStreams > 0 && activeCount < 2) {
			p.lastScaleAt = now
			return activeCount, 1
		}
	}

	// Shrink at most 1 excess idle slot per tick when traffic is quiet.
	if activeCount > minSz && bondStreams == 0 && p.recentBps < shrinkRateBytesPerSec {
		for i := len(p.entries) - 1; i >= 0; i-- {
			e := p.entries[i]
			if e.draining || e.sess.NumStreams() > 0 {
				continue
			}
			if now.Sub(e.lastActiveAt) >= p.idleShrinkDur {
				e.draining = true
				e.sess.draining.Store(true)
				activeCount--
				if p.onLog != nil {
					p.onLog("[TCP] Pool slot #%d idle shrink (active=%d, floor=%d)", e.id, activeCount, minSz)
				}
				break
			}
		}
	}

	return activeCount, 0
}

func (p *SessionPool) isIdle(now time.Time) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.elastic {
		return false
	}
	if p.bond != nil && p.bond.NumStreams() > 0 {
		return false
	}
	for _, e := range p.entries {
		if !e.draining && e.sess.NumStreams() > 0 {
			return false
		}
	}
	return p.lastTrafficAt.IsZero() || now.Sub(p.lastTrafficAt) >= 20*time.Second
}

func (p *SessionPool) inBandPingLoop() {
	defer p.wg.Done()
	// Fire an initial health probe shortly after startup, then probe active slots every 5..7s
	// under load or 25..55s randomized when completely idle to avoid rhythmic heartbeat fingerprints.
	select {
	case <-p.ctx.Done():
		return
	case <-time.After(1200 * time.Millisecond):
		p.probeAllHealth()
	}

	t := time.NewTimer(time.Hour)
	defer t.Stop()
	for {
		var wait time.Duration
		if p.isIdle(time.Now()) {
			wait = time.Duration(randRange(idlePingMinMs, idlePingMaxMs)) * time.Millisecond
		} else {
			wait = time.Duration(randRange(5000, 7000)) * time.Millisecond
		}
		if !t.Stop() {
			select {
			case <-t.C:
			default:
			}
		}
		t.Reset(wait)
		select {
		case <-p.ctx.Done():
			return
		case <-t.C:
			p.probeAllHealth()
		}
	}
}

func (p *SessionPool) probeAllHealth() {
	p.mu.Lock()
	var targets []*poolEntry
	for _, e := range p.entries {
		if e.draining {
			continue
		}
		select {
		case <-e.sess.Done():
			continue
		default:
		}
		targets = append(targets, e)
	}
	p.mu.Unlock()

	if len(targets) == 0 {
		return
	}

	pCtx, cancel := context.WithTimeout(p.ctx, 3*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	var bestMs atomic.Int64
	for _, e := range targets {
		wg.Add(1)
		go func(ent *poolEntry) {
			defer wg.Done()
			rtt, err := ent.sess.SendPingReqAndWait(pCtx)
			if err != nil {
				if p.ctx.Err() != nil {
					return
				}
				if fails := ent.sess.RecordPingFail(); fails >= 2 {
					if p.onLog != nil {
						p.onLog("[TCP] Pool slot #%d blackholed (%d ping timeouts), closing to reconnect", ent.id, fails)
					}
					ent.sess.Close()
				}
				return
			}
			ent.sess.ResetPingFail()
			ms := rtt.Milliseconds()
			if ms <= 0 {
				ms = 1
			}
			ent.sess.SetLastRTTMs(ms)
			for {
				cur := bestMs.Load()
				if cur != 0 && ms >= cur {
					break
				}
				if bestMs.CompareAndSwap(cur, ms) {
					break
				}
			}
		}(e)
	}
	wg.Wait()
	if b := bestMs.Load(); b > 0 {
		p.rttMs.Store(b)
	}
}

// acquireForPingTop picks up to 2 healthy sessions with lowest pending write backlog
// and fewest streams so interactive RTT probing isn't skewed by a single slow TCP socket.
func (p *SessionPool) acquireForPingTop() ([]*Session, error) {
	if p.ctx.Err() != nil {
		return nil, ErrSessionClosed
	}
	p.mu.Lock()
	type cand struct {
		s    *Session
		pend int64
		load int
		rtt  int64
	}
	var cands []cand
	for _, e := range p.entries {
		if e.draining {
			continue
		}
		select {
		case <-e.sess.Done():
			continue
		default:
		}
		cands = append(cands, cand{
			s:    e.sess,
			pend: e.sess.PendingWriteBytes(),
			load: e.sess.NumStreams(),
			rtt:  e.sess.LastRTTMs(),
		})
	}
	p.mu.Unlock()
	if len(cands) == 0 {
		s, err := p.Acquire()
		if err != nil {
			return nil, err
		}
		return []*Session{s}, nil
	}
	// Simple partial selection for best 2 candidates without sorting allocation overhead.
	for i := 0; i < len(cands) && i < 2; i++ {
		best := i
		for j := i + 1; j < len(cands); j++ {
			better := false
			if (cands[j].pend == 0) != (cands[best].pend == 0) {
				better = cands[j].pend == 0
			} else if cands[j].pend != cands[best].pend {
				better = cands[j].pend < cands[best].pend
			} else if cands[j].load != cands[best].load {
				better = cands[j].load < cands[best].load
			} else if cands[j].rtt > 0 && (cands[best].rtt == 0 || cands[j].rtt < cands[best].rtt) {
				better = true
			}
			if better {
				best = j
			}
		}
		cands[i], cands[best] = cands[best], cands[i]
	}
	if len(cands) > 2 {
		cands = cands[:2]
	}
	out := make([]*Session, len(cands))
	for i := range cands {
		out[i] = cands[i].s
	}
	return out, nil
}

// PingNow actively measures live in-band RTT by racing up to 2 least-congested sessions.
func (p *SessionPool) PingNow(ctx context.Context) (int64, error) {
	sessions, err := p.acquireForPingTop()
	if err != nil {
		return 0, err
	}
	pCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	if len(sessions) == 1 {
		rtt, err := sessions[0].SendPingReqAndWait(pCtx)
		if err != nil {
			return 0, err
		}
		ms := rtt.Milliseconds()
		if ms <= 0 {
			ms = 1
		}
		p.rttMs.Store(ms)
		return ms, nil
	}

	type res struct {
		rtt time.Duration
		err error
	}
	ch := make(chan res, len(sessions))
	for _, s := range sessions {
		go func(sess *Session) {
			r, e := sess.SendPingReqAndWait(pCtx)
			ch <- res{r, e}
		}(s)
	}
	var lastErr error
	for i := 0; i < len(sessions); i++ {
		r := <-ch
		if r.err == nil {
			ms := r.rtt.Milliseconds()
			if ms <= 0 {
				ms = 1
			}
			p.rttMs.Store(ms)
			return ms, nil
		}
		lastErr = r.err
	}
	return 0, lastErr
}

// PingInBand measures RTT strictly inside an existing active pooled session (no new TCP+TLS dials).
func (p *SessionPool) PingInBand() (int64, error) {
	return p.PingNow(p.ctx)
}

// Acquire returns the healthy non-draining session with the fewest active streams.
func (p *SessionPool) Acquire() (*Session, error) {
	if p.ctx.Err() != nil {
		return nil, ErrSessionClosed
	}
	p.mu.Lock()
	var best *Session
	bestLoad := math.MaxInt
	for _, e := range p.entries {
		if e.draining {
			continue
		}
		select {
		case <-e.sess.Done():
			continue
		default:
		}
		load := e.sess.NumStreams()
		if load < bestLoad {
			bestLoad = load
			best = e.sess
		}
	}
	p.mu.Unlock()

	if best != nil {
		return best, nil
	}

	// Coalesce concurrent emergency dials into a single-flight reconnect to avoid stampedes.
	p.emergMu.Lock()
	if ch := p.emergWait; ch != nil {
		p.emergMu.Unlock()
		select {
		case <-ch:
		case <-p.ctx.Done():
			return nil, ErrSessionClosed
		}
		p.emergMu.Lock()
		sess, err := p.emergSess, p.emergErr
		p.emergMu.Unlock()
		if err != nil {
			return nil, err
		}
		if sess != nil {
			select {
			case <-sess.Done():
			default:
				return sess, nil
			}
		}
		return nil, ErrSessionClosed
	}

	ch := make(chan struct{})
	p.emergWait = ch
	p.emergSess = nil
	p.emergErr = nil
	p.emergMu.Unlock()

	if p.ctx.Err() != nil {
		p.emergMu.Lock()
		p.emergErr = ErrSessionClosed
		p.emergWait = nil
		close(ch)
		p.emergMu.Unlock()
		return nil, ErrSessionClosed
	}

	e, hs, err := p.dialOne(5 * time.Second)
	if err != nil && p.ctx.Err() == nil {
		select {
		case <-time.After(350 * time.Millisecond):
			e, hs, err = p.dialOne(5 * time.Second)
		case <-p.ctx.Done():
			err = ErrSessionClosed
		}
	}

	var outSess *Session
	if err == nil && e != nil {
		outSess = e.sess
		p.hsMs.Store(hs.Milliseconds())
		p.mu.Lock()
		p.entries = append(p.entries, e)
		p.lastErr = ""
		p.mu.Unlock()
	} else if err != nil {
		p.mu.Lock()
		p.lastErr = err.Error()
		p.mu.Unlock()
	}

	p.emergMu.Lock()
	p.emergSess = outSess
	p.emergErr = err
	p.emergWait = nil
	close(ch)
	p.emergMu.Unlock()

	if err != nil {
		return nil, err
	}
	return outSess, nil
}

// OpenStream opens a multiplexed TCP stream on the least-loaded healthy session.
func (p *SessionPool) OpenStream(target string, first []byte) (*Stream, error) {
	s, err := p.Acquire()
	if err != nil {
		return nil, err
	}
	st, err := s.OpenStream(target, first)
	if err == nil {
		p.NoteDemand()
	}
	return st, err
}

// OpenDataStream opens a Multi-TCP BondedStream when the server advertises CmdBondCap
// (and low-memory mode is off), falling back transparently to a single-session Stream.
func (p *SessionPool) OpenDataStream(target string, first []byte) (DataStream, error) {
	if !IsLowMemMode() && p.bondReady.Load() && p.bond != nil {
		bondID := (uint64(p.poolEpoch) << 32) | uint64(p.nextBondSeq.Add(1))
		if bs, err := p.bond.OpenStream(bondID, target, first); err == nil {
			p.NoteDemand()
			return bs, nil
		}
	}
	return p.OpenStream(target, first)
}

// OpenUDP opens a multiplexed UDP association on the least-loaded healthy session.
func (p *SessionPool) OpenUDP() (*UDPStream, error) {
	s, err := p.Acquire()
	if err != nil {
		return nil, err
	}
	u, err := s.OpenUDP()
	if err == nil {
		p.NoteDemand()
	}
	return u, err
}

// Stats returns aggregated metrics across all pooled sessions.
func (p *SessionPool) Stats() PoolStats {
	p.mu.Lock()
	defer p.mu.Unlock()

	st := PoolStats{
		TargetSize:  p.size,
		TotalUp:     p.retiredUp,
		TotalDown:   p.retiredDown,
		RTTMs:       p.rttMs.Load(),
		HandshakeMs: p.hsMs.Load(),
		LastErr:     p.lastErr,
	}
	for _, e := range p.entries {
		select {
		case <-e.sess.Done():
			continue
		default:
		}
		if e.draining {
			st.DrainingConns++
		} else {
			st.ActiveConns++
		}
		st.ActiveStreams += e.sess.NumStreams()
		st.TotalUp += e.sess.UpBytes.Load()
		st.TotalDown += e.sess.DownBytes.Load()
	}
	if p.bond != nil {
		st.ActiveStreams += p.bond.NumStreams()
	}
	return st
}

// Close closes the entire pool and all active/draining sessions.
func (p *SessionPool) Close() {
	p.cancel()
	if p.bond != nil {
		p.bond.CloseAll(ErrSessionClosed)
	}
	p.mu.Lock()
	entries := p.entries
	p.entries = nil
	p.mu.Unlock()
	for _, e := range entries {
		e.sess.Close()
	}
	p.wg.Wait()
}

var _ = errors.New
