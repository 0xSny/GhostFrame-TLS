package gft

import (
	"encoding/binary"
	"fmt"
	"io"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

const (
	bondChunkSize          = 32 * 1024        // 32 KB striping chunk across pooled TCP sessions
	bondInitWindow         = 8 * 1024 * 1024  // 8 MB initial bonded stream window
	bondMaxWindow          = 16 * 1024 * 1024 // 16 MB max dynamic bonded window
	bondMaxNackCount       = 32               // max contiguous missing chunks requested per CmdBondNack
	bondRetransmitMaxCap   = 512              // hard per-stream unacked chunk cache cap (16 MB max)
	bondGapTimerInit       = 140 * time.Millisecond
	bondGapTimerBackoff    = 220 * time.Millisecond
	bondNackMinCooldownNs  = int64(160 * time.Millisecond)
	bondPenaltyDur         = 1500 * time.Millisecond
)

var bondChunkPool = sync.Pool{
	New: func() any {
		b := make([]byte, bondChunkSize)
		return &b
	},
}

func getBondChunk(n int) (*[]byte, []byte) {
	if n <= bondChunkSize {
		bp := bondChunkPool.Get().(*[]byte)
		return bp, (*bp)[:n]
	}
	b := make([]byte, n)
	return nil, b
}

func putBondChunk(bp *[]byte) {
	if bp != nil {
		bondChunkPool.Put(bp)
	}
}

type bondBufEntry struct {
	bp *[]byte
	b  []byte
}

type sentBondChunk struct {
	bp         *[]byte
	b          []byte
	sess       *Session
	lastNackNs int64
}

func effectiveBondInitWindow() int {
	if IsLowMemMode() {
		return 2 * 1024 * 1024
	}
	return bondInitWindow
}

func effectiveBondMaxWindow() int {
	if IsLowMemMode() {
		return 4 * 1024 * 1024
	}
	return bondMaxWindow
}

// BondOpenHandler is invoked when a remote client opens a Multi-TCP BondedStream.
type BondOpenHandler func(s DataStream, target string, first []byte)

// BondGroup coordinates multi-TCP stream striping across all active gft.Session
// sockets belonging to a single ClientID / SessionPool. Each stream stripes ordered
// 32KB chunks across non-stalled TCP sockets to bypass single-flow CWND limits.
type BondGroup struct {
	mu             sync.Mutex
	sessions       []*Session
	streams        map[uint64]*BondedStream
	linger         map[uint64]*BondedStream
	recentlyClosed map[uint64]struct{}
	closedRing     []uint64
	onOpen         BondOpenHandler
	rr             atomic.Uint64
}

// NewBondGroup creates a BondGroup (server passes onOpen handler; client passes nil).
func NewBondGroup(onOpen BondOpenHandler) *BondGroup {
	return &BondGroup{
		streams:        make(map[uint64]*BondedStream),
		linger:         make(map[uint64]*BondedStream),
		recentlyClosed: make(map[uint64]struct{}),
		onOpen:         onOpen,
	}
}

// AddSession registers s as an available carrier socket for this BondGroup.
func (g *BondGroup) AddSession(s *Session) {
	if g == nil || s == nil {
		return
	}
	s.SetBondHandler(g.HandleFrame)
	g.mu.Lock()
	for _, cur := range g.sessions {
		if cur == s {
			g.mu.Unlock()
			return
		}
	}
	g.sessions = append(g.sessions, s)
	g.mu.Unlock()
}

// RemoveSession removes s from active carriers and returns the remaining count.
// When closeOnEmpty is true and no carriers remain, all open bonded streams abort cleanly.
func (g *BondGroup) RemoveSession(s *Session, closeOnEmpty bool) int {
	if g == nil || s == nil {
		return 0
	}
	g.mu.Lock()
	kept := g.sessions[:0]
	for _, cur := range g.sessions {
		if cur != s {
			kept = append(kept, cur)
		}
	}
	g.sessions = kept
	rem := len(kept)
	var toAbort []*BondedStream
	if rem == 0 && closeOnEmpty && len(g.streams) > 0 {
		toAbort = make([]*BondedStream, 0, len(g.streams))
		for id, bs := range g.streams {
			delete(g.streams, id)
			toAbort = append(toAbort, bs)
		}
	}
	g.mu.Unlock()
	for _, bs := range toAbort {
		bs.abort(ErrSessionClosed)
	}
	return rem
}

// CloseAll aborts all open bonded streams in this group.
func (g *BondGroup) CloseAll(err error) {
	if g == nil {
		return
	}
	if err == nil {
		err = ErrSessionClosed
	}
	g.mu.Lock()
	toAbort := make([]*BondedStream, 0, len(g.streams)+len(g.linger))
	for id, bs := range g.streams {
		delete(g.streams, id)
		toAbort = append(toAbort, bs)
	}
	for id, bs := range g.linger {
		delete(g.linger, id)
		toAbort = append(toAbort, bs)
	}
	g.sessions = nil
	g.mu.Unlock()
	for _, bs := range toAbort {
		bs.abort(err)
	}
}

// NumStreams returns the number of active bonded streams.
func (g *BondGroup) NumStreams() int {
	if g == nil {
		return 0
	}
	g.mu.Lock()
	n := len(g.streams)
	g.mu.Unlock()
	return n
}

// pickSendSession picks a live, non-draining carrier session scored by:
// - active write stall duration & queued PendingWriteBytes (detects TCP_NOTSENT_LOWAT backpressure)
// - recent CmdBondNack blame penalty (avoids slow/blackholed TCP streams)
// - live per-session RTT
// Healthy, unblocked fast sessions share traffic round-robin.
func (g *BondGroup) pickSendSession(exclude *Session) *Session {
	g.mu.Lock()
	n := len(g.sessions)
	if n == 0 {
		g.mu.Unlock()
		return nil
	}
	snap := make([]*Session, n)
	copy(snap, g.sessions)
	g.mu.Unlock()

	nowNs := time.Now().UnixNano()
	start := int(g.rr.Add(1)-1) % len(snap)

	var minHealthyRTT int64
	for _, s := range snap {
		if s == nil || s == exclude || s.draining.Load() || s.BondPenaltyActive(nowNs) {
			continue
		}
		select {
		case <-s.Done():
			continue
		default:
		}
		if r := s.LastRTTMs(); r > 0 && (minHealthyRTT == 0 || r < minHealthyRTT) {
			minHealthyRTT = r
		}
	}

	var best *Session
	var bestScore int64 = 1<<62 - 1

	for i := 0; i < len(snap); i++ {
		s := snap[(start+i)%len(snap)]
		if s == nil || s == exclude || s.draining.Load() {
			continue
		}
		select {
		case <-s.Done():
			continue
		default:
		}

		pend := s.PendingWriteBytes()
		stallMs := s.WriteStallMs()
		rtt := s.LastRTTMs()
		penalized := s.BondPenaltyActive(nowNs)

		// Fast path: healthy, zero-backlog, unpenalized session whose RTT is near pool best.
		if pend == 0 && stallMs == 0 && !penalized {
			if minHealthyRTT == 0 || rtt == 0 || rtt <= minHealthyRTT*2+40 {
				return s
			}
		}

		score := (pend / 1024) + stallMs*16
		if rtt > 0 {
			score += rtt
		}
		if penalized {
			score += 50_000
		}
		if score < bestScore {
			bestScore = score
			best = s
		}
	}
	return best
}

func (g *BondGroup) getStream(bondID uint64) *BondedStream {
	g.mu.Lock()
	bs := g.streams[bondID]
	if bs == nil {
		bs = g.linger[bondID]
	}
	g.mu.Unlock()
	return bs
}

func (g *BondGroup) retireOrLingerStream(bs *BondedStream) {
	if bs == nil {
		return
	}
	bs.mu.Lock()
	keep := bs.aborted == nil && len(bs.sentChunks) > 0 && bs.ackedSeq < bs.sendSeq
	if keep {
		bs.lingering = true
		if bs.lingerTimer == nil {
			bs.lingerTimer = time.AfterFunc(4*time.Second, func() {
				g.finishLinger(bs.id, bs)
			})
		}
	}
	bs.mu.Unlock()

	if !keep {
		bs.mu.Lock()
		bs.freeSentLocked()
		bs.mu.Unlock()
		g.removeStream(bs.id)
		return
	}

	g.mu.Lock()
	if cur := g.streams[bs.id]; cur == bs {
		delete(g.streams, bs.id)
		if cur.orphanTimer != nil {
			cur.orphanTimer.Stop()
			cur.orphanTimer = nil
		}
		g.linger[bs.id] = bs
	}
	g.mu.Unlock()
}

func (g *BondGroup) finishLinger(bondID uint64, expect *BondedStream) {
	g.mu.Lock()
	cur := g.linger[bondID]
	if cur != expect {
		g.mu.Unlock()
		return
	}
	delete(g.linger, bondID)
	g.mu.Unlock()

	expect.mu.Lock()
	if expect.lingerTimer != nil {
		expect.lingerTimer.Stop()
		expect.lingerTimer = nil
	}
	expect.freeSentLocked()
	expect.mu.Unlock()
	g.removeStream(bondID)
}

func (g *BondGroup) removeStream(bondID uint64) {
	g.mu.Lock()
	bs := g.streams[bondID]
	delete(g.streams, bondID)
	if lbs, ok := g.linger[bondID]; ok {
		delete(g.linger, bondID)
		if bs == nil {
			bs = lbs
		}
	}
	if bs != nil && bs.orphanTimer != nil {
		bs.orphanTimer.Stop()
		bs.orphanTimer = nil
	}
	if _, exists := g.recentlyClosed[bondID]; !exists {
		if len(g.closedRing) >= 512 {
			evict := g.closedRing[0]
			g.closedRing = g.closedRing[1:]
			delete(g.recentlyClosed, evict)
		}
		g.closedRing = append(g.closedRing, bondID)
		g.recentlyClosed[bondID] = struct{}{}
	}
	g.mu.Unlock()
}

// getOrPrecreateForEarlyFrame returns an existing stream or pre-allocates an unopened
// placeholder stream on the server when CmdBondData/Close/Window beats CmdBondOpen
// across distinct pooled TCP connections.
func (g *BondGroup) getOrPrecreateForEarlyFrame(bondID uint64) *BondedStream {
	g.mu.Lock()
	bs := g.streams[bondID]
	if bs != nil || g.onOpen == nil {
		g.mu.Unlock()
		return bs
	}
	if _, closed := g.recentlyClosed[bondID]; closed || len(g.streams) >= 4096 {
		g.mu.Unlock()
		return nil
	}
	bs = newBondedStream(g, bondID, "")
	bs.opened = false
	bs.orphanTimer = time.AfterFunc(15*time.Second, func() {
		g.mu.Lock()
		cur := g.streams[bondID]
		unopened := cur == bs && !bs.opened
		if unopened {
			delete(g.streams, bondID)
		}
		g.mu.Unlock()
		if unopened {
			bs.abort(ErrSessionClosed)
		}
	})
	g.streams[bondID] = bs
	g.mu.Unlock()
	return bs
}

// OpenStream opens a client-side bonded stream and announces it via CmdBondOpen.
func (g *BondGroup) OpenStream(bondID uint64, target string, first []byte) (*BondedStream, error) {
	addr, err := EncodeAddr(target)
	if err != nil {
		return nil, err
	}
	if 8+len(addr)+len(first) > MaxPayload {
		return nil, ErrProtocol
	}

	s := g.pickSendSession(nil)
	if s == nil {
		return nil, ErrSessionClosed
	}

	bs := newBondedStream(g, bondID, target)
	bs.opened = true
	bs.openSess = s
	g.mu.Lock()
	g.streams[bondID] = bs
	g.mu.Unlock()

	pl := make([]byte, 8+len(addr)+len(first))
	binary.BigEndian.PutUint64(pl[:8], bondID)
	copy(pl[8:], addr)
	copy(pl[8+len(addr):], first)

	if err := s.writeFrame(CmdBondOpen, 0, 0, pl, 0); err != nil {
		alt := g.pickSendSession(s)
		if alt == nil || alt.writeFrame(CmdBondOpen, 0, 0, pl, 0) != nil {
			g.removeStream(bondID)
			return nil, err
		}
		s = alt
		bs.openSess = alt
	}
	bs.Up.Add(uint64(len(first)))
	s.UpBytes.Add(uint64(len(first)))
	if s.OnBytes != nil && len(first) > 0 {
		s.OnBytes(len(first), 0)
	}
	return bs, nil
}

// HandleFrame dispatches incoming CmdBondOpen / CmdBondData / CmdBondClose / CmdBondWindow frames.
func (g *BondGroup) HandleFrame(s *Session, cmd, flags byte, pl []byte) error {
	switch cmd {
	case CmdBondOpen:
		if len(pl) < 8 || g.onOpen == nil {
			return nil
		}
		bondID := binary.BigEndian.Uint64(pl[:8])
		target, rest, err := DecodeAddr(pl[8:])
		if err != nil {
			g.sendControl(nil, CmdBondClose, CloseRST, bondID, 0)
			return nil
		}
		g.mu.Lock()
		bs := g.streams[bondID]
		if bs != nil && bs.opened {
			g.mu.Unlock()
			return nil
		}
		if bs == nil {
			bs = newBondedStream(g, bondID, target)
			g.streams[bondID] = bs
		} else {
			bs.Target = target
			if bs.orphanTimer != nil {
				bs.orphanTimer.Stop()
				bs.orphanTimer = nil
			}
		}
		bs.opened = true
		g.mu.Unlock()

		var first []byte
		if len(rest) > 0 {
			first = append([]byte(nil), rest...)
		}
		s.DownBytes.Add(uint64(len(rest)))
		if s.OnBytes != nil && len(rest) > 0 {
			s.OnBytes(0, len(rest))
		}
		go g.onOpen(bs, target, first)

	case CmdBondData:
		if len(pl) < 12 {
			return nil
		}
		bondID := binary.BigEndian.Uint64(pl[:8])
		seq := binary.BigEndian.Uint32(pl[8:12])
		data := pl[12:]
		s.DownBytes.Add(uint64(len(data)))
		if s.OnBytes != nil && len(data) > 0 {
			s.OnBytes(0, len(data))
		}
		if bs := g.getOrPrecreateForEarlyFrame(bondID); bs != nil {
			if err := bs.pushChunk(seq, data); err != nil {
				bs.abort(err)
				g.removeStream(bondID)
			}
		}

	case CmdBondWindow:
		if len(pl) < 12 {
			return nil
		}
		bondID := binary.BigEndian.Uint64(pl[:8])
		add := binary.BigEndian.Uint32(pl[8:12])
		hasAck := len(pl) >= 16
		var ackSeq uint32
		if hasAck {
			ackSeq = binary.BigEndian.Uint32(pl[12:16])
		}
		if bs := g.getOrPrecreateForEarlyFrame(bondID); bs != nil {
			bs.onRemoteWindow(int64(add), hasAck, ackSeq)
		}

	case CmdBondNack:
		if len(pl) < 16 {
			return nil
		}
		bondID := binary.BigEndian.Uint64(pl[:8])
		seqStart := binary.BigEndian.Uint32(pl[8:12])
		count := binary.BigEndian.Uint32(pl[12:16])
		if bs := g.getStream(bondID); bs != nil {
			bs.handleNack(seqStart, count)
		}

	case CmdBondClose:
		if len(pl) < 12 {
			return nil
		}
		bondID := binary.BigEndian.Uint64(pl[:8])
		finalSeq := binary.BigEndian.Uint32(pl[8:12])
		if bs := g.getOrPrecreateForEarlyFrame(bondID); bs != nil {
			if flags == CloseRST {
				bs.abort(ErrStreamReset)
				g.removeStream(bondID)
			} else {
				bs.remoteClose(finalSeq)
			}
		}
	}
	return nil
}

func (g *BondGroup) sendControl(prefer *Session, cmd, flags byte, bondID uint64, val uint32) error {
	var pl [12]byte
	binary.BigEndian.PutUint64(pl[:8], bondID)
	binary.BigEndian.PutUint32(pl[8:12], val)
	return g.sendControlPayload(prefer, cmd, flags, pl[:])
}

func (g *BondGroup) sendBondWindow(bondID uint64, add uint32, ackSeq uint32) error {
	var pl [16]byte
	binary.BigEndian.PutUint64(pl[:8], bondID)
	binary.BigEndian.PutUint32(pl[8:12], add)
	binary.BigEndian.PutUint32(pl[12:16], ackSeq)
	return g.sendControlPayload(nil, CmdBondWindow, 0, pl[:])
}

func (g *BondGroup) sendBondNack(bondID uint64, seqStart, count uint32) error {
	var pl [16]byte
	binary.BigEndian.PutUint64(pl[:8], bondID)
	binary.BigEndian.PutUint32(pl[8:12], seqStart)
	binary.BigEndian.PutUint32(pl[12:16], count)
	return g.sendControlPayload(nil, CmdBondNack, 0, pl[:])
}

func (g *BondGroup) sendControlPayload(prefer *Session, cmd, flags byte, pl []byte) error {
	s := prefer
	if s == nil {
		s = g.pickSendSession(nil)
	}
	if s == nil {
		return ErrSessionClosed
	}
	if err := s.writeFrame(cmd, flags, 0, pl, 0); err != nil {
		alt := g.pickSendSession(s)
		if alt == nil {
			return err
		}
		return alt.writeFrame(cmd, flags, 0, pl, 0)
	}
	return nil
}

// BondedStream implements DataStream striped across multiple TCP sessions in a BondGroup.
type BondedStream struct {
	g           *BondGroup
	id          uint64
	Target      string
	openSess    *Session
	opened      bool
	orphanTimer *time.Timer
	Up          atomic.Uint64
	Down        atomic.Uint64

	mu             sync.Mutex
	rcond          *sync.Cond
	wcond          *sync.Cond
	reorder        map[uint32]bondBufEntry
	head           []byte
	headBP         *[]byte
	headOff        int
	buffered       int
	recvNextSeq    uint32
	lastAckSent    uint32
	gapSinceNs     int64
	lastNackSeq    uint32
	lastNackSentNs int64
	nackTimer      *time.Timer
	finKnown       bool
	finSeq         uint32
	consumed       int
	curWindow      int
	winConsumed    int
	lastWinCheck   int64
	rEOF           bool
	sendSeq        uint32
	sendWin        int64
	sentChunks     map[uint32]sentBondChunk
	ackedSeq       uint32
	lingering      bool
	lingerTimer    *time.Timer
	wClosed        bool
	aborted        error
}

func newBondedStream(g *BondGroup, id uint64, target string) *BondedStream {
	initWin := effectiveBondInitWindow()
	bs := &BondedStream{
		g:            g,
		id:           id,
		Target:       target,
		reorder:      make(map[uint32]bondBufEntry),
		sentChunks:   make(map[uint32]sentBondChunk),
		curWindow:    initWin,
		sendWin:      int64(initWin),
		lastWinCheck: time.Now().UnixNano(),
	}
	bs.rcond = sync.NewCond(&bs.mu)
	bs.wcond = sync.NewCond(&bs.mu)
	return bs
}

func (bs *BondedStream) RemoteTarget() string { return bs.Target }

// DebugState returns a concise diagnostic snapshot for tests/troubleshooting.
func (bs *BondedStream) DebugState() string {
	bs.mu.Lock()
	defer bs.mu.Unlock()
	seqs := make([]int, 0, len(bs.reorder))
	for k := range bs.reorder {
		seqs = append(seqs, int(k))
	}
	sort.Ints(seqs)
	if len(seqs) > 10 {
		seqs = seqs[:10]
	}
	return fmt.Sprintf("recvNext=%d reorderLen=%d firstKeys=%v finKnown=%v finSeq=%d rEOF=%v sendSeq=%d sendWin=%d sentCache=%d wClosed=%v aborted=%v srvStreams=%d",
		bs.recvNextSeq, len(bs.reorder), seqs, bs.finKnown, bs.finSeq, bs.rEOF, bs.sendSeq, bs.sendWin, len(bs.sentChunks), bs.wClosed, bs.aborted, bs.g.NumStreams())
}

func (bs *BondedStream) freeReorderLocked() {
	for k, ent := range bs.reorder {
		putBondChunk(ent.bp)
		delete(bs.reorder, k)
	}
	if bs.headBP != nil {
		putBondChunk(bs.headBP)
		bs.headBP = nil
	}
	bs.head = nil
	bs.headOff = 0
	bs.buffered = 0
}

func (bs *BondedStream) freeSentLocked() {
	for k, sc := range bs.sentChunks {
		putBondChunk(sc.bp)
		delete(bs.sentChunks, k)
	}
}

func (bs *BondedStream) stopNackTimerLocked() {
	if bs.nackTimer != nil {
		bs.nackTimer.Stop()
		bs.nackTimer = nil
	}
}

func (bs *BondedStream) armNackTimerLocked(d time.Duration) {
	if bs.nackTimer != nil {
		bs.nackTimer.Reset(d)
		return
	}
	bs.nackTimer = time.AfterFunc(d, bs.onNackTimer)
}

func (bs *BondedStream) missingRunLocked() uint32 {
	var count uint32 = 1
	maxProbe := uint32(bondMaxNackCount)
	for off := uint32(1); off < maxProbe; off++ {
		next := bs.recvNextSeq + off
		if bs.finKnown && next >= bs.finSeq {
			break
		}
		if _, ok := bs.reorder[next]; ok {
			break
		}
		count++
	}
	return count
}

func (bs *BondedStream) onNackTimer() {
	bs.mu.Lock()
	if bs.aborted != nil || bs.rEOF {
		bs.stopNackTimerLocked()
		bs.mu.Unlock()
		return
	}
	hasGap := len(bs.reorder) > 0 || (bs.finKnown && bs.recvNextSeq < bs.finSeq)
	if !hasGap {
		bs.gapSinceNs = 0
		bs.stopNackTimerLocked()
		bs.mu.Unlock()
		return
	}
	nowNs := time.Now().UnixNano()
	if bs.lastNackSeq == bs.recvNextSeq && nowNs-bs.lastNackSentNs < bondNackMinCooldownNs {
		bs.armNackTimerLocked(bondGapTimerBackoff)
		bs.mu.Unlock()
		return
	}
	seqStart := bs.recvNextSeq
	count := bs.missingRunLocked()
	bs.lastNackSeq = seqStart
	bs.lastNackSentNs = nowNs
	bs.armNackTimerLocked(bondGapTimerBackoff)
	bs.mu.Unlock()

	_ = bs.g.sendBondNack(bs.id, seqStart, count)
}

func (bs *BondedStream) pushChunk(seq uint32, data []byte) error {
	var nackSeq, nackCount uint32
	var sendNack bool

	bs.mu.Lock()
	if bs.aborted != nil || bs.rEOF {
		bs.mu.Unlock()
		return nil
	}
	if seq < bs.recvNextSeq {
		bs.mu.Unlock()
		return nil
	}
	if bs.finKnown && seq >= bs.finSeq {
		bs.mu.Unlock()
		return nil
	}
	if _, dup := bs.reorder[seq]; dup {
		bs.mu.Unlock()
		return nil
	}
	maxWin := effectiveBondMaxWindow()
	limit := 2*bs.curWindow + 2*1024*1024
	if limit > 2*maxWin+2*1024*1024 {
		limit = 2*maxWin + 2*1024*1024
	}
	if bs.buffered+len(data) > limit {
		bs.mu.Unlock()
		return ErrProtocol
	}
	bp, cp := getBondChunk(len(data))
	copy(cp, data)
	bs.reorder[seq] = bondBufEntry{bp: bp, b: cp}
	bs.buffered += len(cp)
	bs.Down.Add(uint64(len(cp)))

	if _, headReady := bs.reorder[bs.recvNextSeq]; !headReady && len(bs.reorder) > 0 {
		nowNs := time.Now().UnixNano()
		if bs.gapSinceNs == 0 {
			bs.gapSinceNs = nowNs
			bs.armNackTimerLocked(bondGapTimerInit)
		} else if len(bs.reorder) >= 4 && nowNs-bs.gapSinceNs >= int64(70*time.Millisecond) {
			if bs.lastNackSeq != bs.recvNextSeq || nowNs-bs.lastNackSentNs >= bondNackMinCooldownNs {
				nackSeq = bs.recvNextSeq
				nackCount = bs.missingRunLocked()
				bs.lastNackSeq = nackSeq
				bs.lastNackSentNs = nowNs
				sendNack = true
				bs.armNackTimerLocked(bondGapTimerBackoff)
			}
		}
	} else if headReady && len(bs.reorder) == 1 {
		bs.gapSinceNs = 0
		bs.stopNackTimerLocked()
	}

	bs.rcond.Broadcast()
	bs.mu.Unlock()

	if sendNack {
		_ = bs.g.sendBondNack(bs.id, nackSeq, nackCount)
	}
	return nil
}

func (bs *BondedStream) remoteClose(finalSeq uint32) {
	bs.mu.Lock()
	bs.finKnown = true
	bs.finSeq = finalSeq
	var done bool
	if bs.headOff >= len(bs.head) && bs.recvNextSeq >= bs.finSeq {
		bs.rEOF = true
		bs.gapSinceNs = 0
		bs.stopNackTimerLocked()
		done = bs.wClosed
	} else if bs.recvNextSeq < bs.finSeq {
		if bs.gapSinceNs == 0 {
			bs.gapSinceNs = time.Now().UnixNano()
		}
		bs.armNackTimerLocked(bondGapTimerInit)
	}
	bs.rcond.Broadcast()
	bs.mu.Unlock()
	if done {
		bs.g.retireOrLingerStream(bs)
	}
}

func (bs *BondedStream) onRemoteWindow(add int64, hasAck bool, ackSeq uint32) {
	var doneLinger bool
	bs.mu.Lock()
	if add > 0 {
		bs.sendWin += add
		bs.wcond.Broadcast()
	}
	if hasAck && ackSeq > bs.ackedSeq {
		for seq := bs.ackedSeq; seq < ackSeq; seq++ {
			if sc, ok := bs.sentChunks[seq]; ok {
				putBondChunk(sc.bp)
				delete(bs.sentChunks, seq)
			}
		}
		bs.ackedSeq = ackSeq
		if bs.lingering && bs.ackedSeq >= bs.sendSeq {
			doneLinger = true
		}
	}
	bs.mu.Unlock()
	if doneLinger {
		bs.g.finishLinger(bs.id, bs)
	}
}

func (bs *BondedStream) handleNack(seqStart, count uint32) {
	if count == 0 {
		return
	}
	if count > bondMaxNackCount {
		count = bondMaxNackCount
	}
	type retransmitItem struct {
		seq  uint32
		bp   *[]byte
		b    []byte
		orig *Session
	}
	var items []retransmitItem
	nowNs := time.Now().UnixNano()

	bs.mu.Lock()
	if bs.aborted != nil {
		bs.mu.Unlock()
		return
	}
	for i := uint32(0); i < count; i++ {
		seq := seqStart + i
		sc, ok := bs.sentChunks[seq]
		if !ok {
			continue
		}
		if sc.lastNackNs != 0 && nowNs-sc.lastNackNs < int64(140*time.Millisecond) {
			continue
		}
		sc.lastNackNs = nowNs
		// Copy into an independent pooled chunk so ackThrough cannot race with frameBuf copy.
		bp, cp := getBondChunk(len(sc.b))
		copy(cp, sc.b)
		orig := sc.sess
		bs.sentChunks[seq] = sc
		items = append(items, retransmitItem{seq: seq, bp: bp, b: cp, orig: orig})
	}
	bs.mu.Unlock()

	if len(items) == 0 {
		return
	}
	// Penalize the carrier session(s) blamed for missing chunks so new traffic routes around them.
	penalized := make(map[*Session]struct{}, 2)
	for _, it := range items {
		if it.orig != nil {
			if _, seen := penalized[it.orig]; !seen {
				penalized[it.orig] = struct{}{}
				it.orig.NoteBondNackPenalty(bondPenaltyDur)
			}
		}
	}

	fb := GetBuf()
	frameBuf := *fb
	for _, it := range items {
		alt := bs.g.pickSendSession(it.orig)
		if alt == nil {
			alt = bs.g.pickSendSession(nil)
		}
		if alt != nil {
			binary.BigEndian.PutUint64(frameBuf[:8], bs.id)
			binary.BigEndian.PutUint32(frameBuf[8:12], it.seq)
			copy(frameBuf[12:], it.b)
			if err := alt.writeFrame(CmdBondData, 0, 0, frameBuf[:12+len(it.b)], 0); err != nil {
				if alt2 := bs.g.pickSendSession(alt); alt2 != nil {
					_ = alt2.writeFrame(CmdBondData, 0, 0, frameBuf[:12+len(it.b)], 0)
				}
			}
		}
		putBondChunk(it.bp)
	}
	PutBuf(fb)
}

func (bs *BondedStream) abort(err error) {
	bs.mu.Lock()
	if bs.aborted == nil {
		bs.aborted = err
	}
	bs.stopNackTimerLocked()
	if bs.lingerTimer != nil {
		bs.lingerTimer.Stop()
		bs.lingerTimer = nil
	}
	bs.freeReorderLocked()
	bs.freeSentLocked()
	bs.rcond.Broadcast()
	bs.wcond.Broadcast()
	bs.mu.Unlock()
}

func (bs *BondedStream) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	bs.mu.Lock()
	for bs.headOff >= len(bs.head) {
		if bs.headBP != nil {
			putBondChunk(bs.headBP)
			bs.headBP = nil
			bs.head = nil
			bs.headOff = 0
		}
		if ent, ok := bs.reorder[bs.recvNextSeq]; ok {
			delete(bs.reorder, bs.recvNextSeq)
			bs.recvNextSeq++
			bs.headBP = ent.bp
			bs.head = ent.b
			bs.headOff = 0
			bs.buffered -= len(ent.b)
			if len(bs.reorder) == 0 && !(bs.finKnown && bs.recvNextSeq < bs.finSeq) {
				bs.gapSinceNs = 0
				bs.stopNackTimerLocked()
			} else if _, nextOK := bs.reorder[bs.recvNextSeq]; !nextOK {
				bs.gapSinceNs = time.Now().UnixNano()
				bs.armNackTimerLocked(bondGapTimerInit)
			}
			break
		}
		if bs.aborted != nil {
			err := bs.aborted
			bs.mu.Unlock()
			return 0, err
		}
		if bs.rEOF || (bs.finKnown && bs.recvNextSeq >= bs.finSeq) {
			bs.rEOF = true
			bs.gapSinceNs = 0
			bs.stopNackTimerLocked()
			done := bs.wClosed
			bs.mu.Unlock()
			if done {
				bs.g.retireOrLingerStream(bs)
			}
			return 0, io.EOF
		}
		bs.rcond.Wait()
	}

	n := copy(p, bs.head[bs.headOff:])
	bs.headOff += n
	if bs.headOff >= len(bs.head) {
		if bs.headBP != nil {
			putBondChunk(bs.headBP)
			bs.headBP = nil
		}
		bs.head = nil
		bs.headOff = 0
	}
	bs.consumed += n
	bs.winConsumed += n

	var upd int
	step := bs.curWindow / 4
	if step < windowUpdateN {
		step = windowUpdateN
	}
	if bs.consumed >= step {
		upd, bs.consumed = bs.consumed, 0
		maxWin := effectiveBondMaxWindow()
		now := time.Now().UnixNano()
		if bs.curWindow < maxWin && bs.winConsumed >= bs.curWindow/2 {
			if now-bs.lastWinCheck <= int64(1500*time.Millisecond) {
				old := bs.curWindow
				bs.curWindow *= 2
				if bs.curWindow > maxWin {
					bs.curWindow = maxWin
				}
				upd += bs.curWindow - old
			}
			bs.winConsumed = 0
			bs.lastWinCheck = now
		} else if now-bs.lastWinCheck > int64(1500*time.Millisecond) {
			bs.winConsumed = 0
			bs.lastWinCheck = now
		}
	}
	ackSeq := bs.recvNextSeq
	sendAckOnly := upd == 0 && ackSeq-bs.lastAckSent >= 32
	if upd > 0 || sendAckOnly {
		bs.lastAckSent = ackSeq
	}
	bs.mu.Unlock()

	if upd > 0 || sendAckOnly {
		_ = bs.g.sendBondWindow(bs.id, uint32(upd), ackSeq)
	}
	return n, nil
}

func (bs *BondedStream) Write(p []byte) (int, error) {
	total := 0
	bp := GetBuf()
	defer PutBuf(bp)
	frameBuf := *bp

	for len(p) > 0 {
		bs.mu.Lock()
		for bs.sendWin <= 0 && bs.aborted == nil && !bs.wClosed {
			bs.wcond.Wait()
		}
		if bs.aborted != nil {
			err := bs.aborted
			bs.mu.Unlock()
			return total, err
		}
		if bs.wClosed {
			bs.mu.Unlock()
			return total, ErrStreamClosed
		}
		n := len(p)
		if n > bondChunkSize {
			n = bondChunkSize
		}
		if int64(n) > bs.sendWin {
			n = int(bs.sendWin)
		}
		seq := bs.sendSeq
		bs.sendSeq++
		bs.sendWin -= int64(n)
		bs.mu.Unlock()

		var s *Session
		if seq == 0 && bs.openSess != nil && !bs.openSess.draining.Load() {
			select {
			case <-bs.openSess.Done():
			default:
				s = bs.openSess
			}
		}
		if s == nil {
			s = bs.g.pickSendSession(nil)
		}
		if s == nil {
			bs.abort(ErrSessionClosed)
			bs.g.removeStream(bs.id)
			return total, ErrSessionClosed
		}

		// Store chunk in bounded retransmit cache before transmitting so early CmdBondNack never misses.
		cbp, cdata := getBondChunk(n)
		copy(cdata, p[:n])
		bs.mu.Lock()
		if bs.aborted != nil {
			bs.mu.Unlock()
			putBondChunk(cbp)
			return total, bs.aborted
		}
		if len(bs.sentChunks) >= bondRetransmitMaxCap && seq >= bondRetransmitMaxCap {
			evict := seq - bondRetransmitMaxCap
			if old, ok := bs.sentChunks[evict]; ok {
				putBondChunk(old.bp)
				delete(bs.sentChunks, evict)
			}
		}
		bs.sentChunks[seq] = sentBondChunk{bp: cbp, b: cdata, sess: s}
		bs.mu.Unlock()

		binary.BigEndian.PutUint64(frameBuf[:8], bs.id)
		binary.BigEndian.PutUint32(frameBuf[8:12], seq)
		copy(frameBuf[12:], p[:n])
		pl := frameBuf[:12+n]

		if err := s.writeFrame(CmdBondData, 0, 0, pl, 0); err != nil {
			alt := bs.g.pickSendSession(s)
			if alt == nil {
				bs.abort(err)
				bs.g.removeStream(bs.id)
				return total, err
			}
			bs.mu.Lock()
			if sc, ok := bs.sentChunks[seq]; ok {
				sc.sess = alt
				bs.sentChunks[seq] = sc
			}
			bs.mu.Unlock()
			if aerr := alt.writeFrame(CmdBondData, 0, 0, pl, 0); aerr != nil {
				bs.abort(aerr)
				bs.g.removeStream(bs.id)
				return total, aerr
			}
			s = alt
		}
		bs.Up.Add(uint64(n))
		s.UpBytes.Add(uint64(n))
		if s.OnBytes != nil {
			s.OnBytes(n, 0)
		}
		total += n
		p = p[n:]
	}
	return total, nil
}

func (bs *BondedStream) CloseWrite() error {
	bs.mu.Lock()
	if bs.wClosed {
		bs.mu.Unlock()
		return nil
	}
	bs.wClosed = true
	finalSeq := bs.sendSeq
	bs.wcond.Broadcast()
	done := bs.rEOF
	bs.mu.Unlock()

	err := bs.g.sendControl(nil, CmdBondClose, CloseFIN, bs.id, finalSeq)
	if done {
		bs.g.retireOrLingerStream(bs)
	}
	return err
}

func (bs *BondedStream) Close() error {
	_ = bs.CloseWrite()
	bs.mu.Lock()
	bs.rEOF = true
	bs.stopNackTimerLocked()
	bs.freeReorderLocked()
	bs.rcond.Broadcast()
	bs.wcond.Broadcast()
	bs.mu.Unlock()
	bs.g.retireOrLingerStream(bs)
	return nil
}
