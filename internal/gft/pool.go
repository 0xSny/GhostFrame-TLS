package gft

import (
	"context"
	"errors"
	"math"
	"sync"
	"sync/atomic"
	"time"
)

const (
	DefaultPoolSize = 4
	MinPoolSize     = 1
	MaxPoolSize     = 8
	rotateMinAge    = 15 * time.Minute
	rotateMaxAge    = 25 * time.Minute
	rotateMaxBytes  = uint64(512 * 1024 * 1024)
)

type poolEntry struct {
	id        uint64
	sess      *Session
	createdAt time.Time
	maxAge    time.Duration
	draining  bool
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
	link     *Link
	ps       *ParamStore
	size     int
	dialFn   func(ctx context.Context, l *Link, ps *ParamStore, flags uint16, timeout time.Duration) (*Session, time.Duration, error)
	onLog    func(string, ...any)
	onStatus func(PoolStats)

	mu          sync.Mutex
	entries     []*poolEntry
	nextEntryID uint64
	retiredUp   uint64
	retiredDown uint64
	lastErr     string

	rttMs atomic.Int64
	hsMs  atomic.Int64

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewSessionPool creates and starts a background-maintained SessionPool.
func NewSessionPool(l *Link, ps *ParamStore, size int, logf func(string, ...any)) *SessionPool {
	if size < MinPoolSize {
		size = DefaultPoolSize
	}
	if size > MaxPoolSize {
		size = MaxPoolSize
	}
	ctx, cancel := context.WithCancel(context.Background())
	p := &SessionPool{
		link:   l,
		ps:     ps,
		size:   size,
		dialFn: DialSession,
		onLog:  logf,
		ctx:    ctx,
		cancel: cancel,
	}
	return p
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
		p.onLog("Pool slot #%d connected via uTLS (%s), handshake=%v", e.id, p.link.EffectiveFP(), hs.Round(time.Millisecond))
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
	maxAge := time.Duration(randRange(int(rotateMinAge.Seconds()), int(rotateMaxAge.Seconds()))) * time.Second
	entry := &poolEntry{
		id:        id,
		sess:      sess,
		createdAt: time.Now(),
		maxAge:    maxAge,
	}
	return entry, hs, nil
}

func (p *SessionPool) maintainLoop() {
	defer p.wg.Done()
	backoff := 250 * time.Millisecond
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
						p.onLog("Pool slot #%d online (active=%d/%d, hs=%v)", e.id, active+1, p.size, hs.Round(time.Millisecond))
					}
				}()
			}
			dialWG.Wait()
			if anyOK.Load() {
				backoff = 250 * time.Millisecond
			} else if p.ctx.Err() == nil {
				if msg, ok := lastDialErr.Load().(string); ok {
					p.mu.Lock()
					p.lastErr = msg
					p.mu.Unlock()
					if p.onLog != nil {
						p.onLog("Pool reconnect failed (%s), retrying in %v", msg, backoff)
					}
				}
				select {
				case <-p.ctx.Done():
					return
				case <-time.After(backoff):
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
		case <-t.C:
		}
	}
}

func (p *SessionPool) reapAndCheck() (activeCount int, needed int) {
	now := time.Now()
	p.mu.Lock()
	defer p.mu.Unlock()

	kept := make([]*poolEntry, 0, len(p.entries))
	for _, e := range p.entries {
		select {
		case <-e.sess.Done():
			// Dead session: retire counters and discard.
			p.retiredUp += e.sess.UpBytes.Load()
			p.retiredDown += e.sess.DownBytes.Load()
			continue
		default:
		}

		if !e.draining && (now.Sub(e.createdAt) >= e.maxAge || e.sess.TotalBytes() >= rotateMaxBytes) {
			e.draining = true
			if p.onLog != nil {
				p.onLog("Pool slot #%d entering graceful drain (age=%v, bytes=%dMB)", e.id, now.Sub(e.createdAt).Round(time.Second), e.sess.TotalBytes()>>20)
			}
		}

		if e.draining {
			if e.sess.NumStreams() == 0 {
				p.retiredUp += e.sess.UpBytes.Load()
				p.retiredDown += e.sess.DownBytes.Load()
				e.sess.Close()
				continue
			}
			kept = append(kept, e)
			continue
		}

		activeCount++
		kept = append(kept, e)
	}
	p.entries = kept

	if activeCount < p.size {
		needed = p.size - activeCount
	}
	return activeCount, needed
}

func (p *SessionPool) inBandPingLoop() {
	defer p.wg.Done()
	// Fire an initial in-band ping shortly after startup, then every 20..35s.
	select {
	case <-p.ctx.Done():
		return
	case <-time.After(1500 * time.Millisecond):
		_, _ = p.PingInBand()
	}

	t := time.NewTimer(time.Hour)
	defer t.Stop()
	for {
		wait := time.Duration(randRange(20000, 35000)) * time.Millisecond
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
			_, _ = p.PingInBand()
		}
	}
}

// PingInBand measures RTT strictly inside an existing active pooled session (no new TCP+TLS dials).
func (p *SessionPool) PingInBand() (int64, error) {
	s, err := p.Acquire()
	if err != nil {
		return 0, err
	}
	if err := s.SendPingReq(); err != nil {
		return 0, err
	}
	return p.rttMs.Load(), nil
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

	// Emergency fast dial if all slots temporarily dropped
	e, hs, err := p.dialOne(6 * time.Second)
	if err != nil {
		return nil, err
	}
	p.hsMs.Store(hs.Milliseconds())
	p.mu.Lock()
	p.entries = append(p.entries, e)
	p.lastErr = ""
	p.mu.Unlock()
	return e.sess, nil
}

// OpenStream opens a multiplexed TCP stream on the least-loaded healthy session.
func (p *SessionPool) OpenStream(target string, first []byte) (*Stream, error) {
	s, err := p.Acquire()
	if err != nil {
		return nil, err
	}
	return s.OpenStream(target, first)
}

// OpenUDP opens a multiplexed UDP association on the least-loaded healthy session.
func (p *SessionPool) OpenUDP() (*UDPStream, error) {
	s, err := p.Acquire()
	if err != nil {
		return nil, err
	}
	return s.OpenUDP()
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
	return st
}

// Close closes the entire pool and all active/draining sessions.
func (p *SessionPool) Close() {
	p.cancel()
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
