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
	bondChunkSize  = 32 * 1024        // 32 KB striping chunk across pooled TCP sessions
	bondInitWindow = 8 * 1024 * 1024  // 8 MB initial bonded stream window
	bondMaxWindow  = 16 * 1024 * 1024 // 16 MB max dynamic bonded window
)

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
	recentlyClosed map[uint64]struct{}
	closedRing     []uint64
	onOpen         BondOpenHandler
	rr             atomic.Uint64
}

// NewBondGroup creates a BondGroup (server passes onOpen handler; client passes nil).
func NewBondGroup(onOpen BondOpenHandler) *BondGroup {
	return &BondGroup{
		streams:        make(map[uint64]*BondedStream),
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
	toAbort := make([]*BondedStream, 0, len(g.streams))
	for id, bs := range g.streams {
		delete(g.streams, id)
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

// pickSendSession picks a live, non-draining carrier session preferring zero
// in-flight write backlog (skipping sockets blocked in kernel TCP send buffers)
// and load-balancing round-robin across healthy idle sockets.
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

	start := int(g.rr.Add(1)-1) % len(snap)
	var best *Session
	var bestPending int64 = 1<<62 - 1

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
		if pend == 0 {
			return s
		}
		if pend < bestPending {
			bestPending = pend
			best = s
		}
	}
	return best
}

func (g *BondGroup) getStream(bondID uint64) *BondedStream {
	g.mu.Lock()
	bs := g.streams[bondID]
	g.mu.Unlock()
	return bs
}

func (g *BondGroup) removeStream(bondID uint64) {
	g.mu.Lock()
	bs := g.streams[bondID]
	delete(g.streams, bondID)
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
		if bs := g.getOrPrecreateForEarlyFrame(bondID); bs != nil {
			bs.addWindow(int64(add))
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

	s := prefer
	if s == nil {
		s = g.pickSendSession(nil)
	}
	if s == nil {
		return ErrSessionClosed
	}
	if err := s.writeFrame(cmd, flags, 0, pl[:], 0); err != nil {
		alt := g.pickSendSession(s)
		if alt == nil {
			return err
		}
		return alt.writeFrame(cmd, flags, 0, pl[:], 0)
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

	mu           sync.Mutex
	rcond        *sync.Cond
	wcond        *sync.Cond
	reorder      map[uint32][]byte
	head         []byte
	headOff      int
	buffered     int
	recvNextSeq  uint32
	finKnown     bool
	finSeq       uint32
	consumed     int
	curWindow    int
	winConsumed  int
	lastWinCheck int64
	rEOF         bool
	sendSeq      uint32
	sendWin      int64
	wClosed      bool
	aborted      error
}

func newBondedStream(g *BondGroup, id uint64, target string) *BondedStream {
	initWin := effectiveBondInitWindow()
	bs := &BondedStream{
		g:            g,
		id:           id,
		Target:       target,
		reorder:      make(map[uint32][]byte),
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
	return fmt.Sprintf("recvNext=%d reorderLen=%d firstKeys=%v finKnown=%v finSeq=%d rEOF=%v sendSeq=%d sendWin=%d wClosed=%v aborted=%v srvStreams=%d",
		bs.recvNextSeq, len(bs.reorder), seqs, bs.finKnown, bs.finSeq, bs.rEOF, bs.sendSeq, bs.sendWin, bs.wClosed, bs.aborted, bs.g.NumStreams())
}

func (bs *BondedStream) pushChunk(seq uint32, data []byte) error {
	bs.mu.Lock()
	defer bs.mu.Unlock()
	if bs.aborted != nil || bs.rEOF {
		return nil
	}
	if seq < bs.recvNextSeq {
		return nil
	}
	if bs.finKnown && seq >= bs.finSeq {
		return nil
	}
	if _, dup := bs.reorder[seq]; dup {
		return nil
	}
	maxWin := effectiveBondMaxWindow()
	limit := 2*bs.curWindow + 1024*1024
	if limit > 2*maxWin+1024*1024 {
		limit = 2*maxWin + 1024*1024
	}
	if bs.buffered+len(data) > limit {
		return ErrProtocol
	}
	cp := append([]byte(nil), data...)
	bs.reorder[seq] = cp
	bs.buffered += len(cp)
	bs.Down.Add(uint64(len(cp)))
	bs.rcond.Broadcast()
	return nil
}

func (bs *BondedStream) remoteClose(finalSeq uint32) {
	bs.mu.Lock()
	bs.finKnown = true
	bs.finSeq = finalSeq
	var done bool
	if bs.headOff >= len(bs.head) && bs.recvNextSeq >= bs.finSeq {
		bs.rEOF = true
		done = bs.wClosed
	}
	bs.rcond.Broadcast()
	bs.mu.Unlock()
	if done {
		bs.g.removeStream(bs.id)
	}
}

func (bs *BondedStream) addWindow(n int64) {
	bs.mu.Lock()
	bs.sendWin += n
	bs.wcond.Broadcast()
	bs.mu.Unlock()
}

func (bs *BondedStream) abort(err error) {
	bs.mu.Lock()
	if bs.aborted == nil {
		bs.aborted = err
	}
	bs.reorder = nil
	bs.head = nil
	bs.headOff = 0
	bs.buffered = 0
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
		if chunk, ok := bs.reorder[bs.recvNextSeq]; ok {
			delete(bs.reorder, bs.recvNextSeq)
			bs.recvNextSeq++
			bs.head = chunk
			bs.headOff = 0
			bs.buffered -= len(chunk)
			break
		}
		if bs.aborted != nil {
			err := bs.aborted
			bs.mu.Unlock()
			return 0, err
		}
		if bs.rEOF || (bs.finKnown && bs.recvNextSeq >= bs.finSeq) {
			bs.rEOF = true
			done := bs.wClosed
			bs.mu.Unlock()
			if done {
				bs.g.removeStream(bs.id)
			}
			return 0, io.EOF
		}
		bs.rcond.Wait()
	}

	n := copy(p, bs.head[bs.headOff:])
	bs.headOff += n
	if bs.headOff >= len(bs.head) {
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
	bs.mu.Unlock()

	if upd > 0 {
		_ = bs.g.sendControl(nil, CmdBondWindow, 0, bs.id, uint32(upd))
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

		binary.BigEndian.PutUint64(frameBuf[:8], bs.id)
		binary.BigEndian.PutUint32(frameBuf[8:12], seq)
		copy(frameBuf[12:], p[:n])
		pl := frameBuf[:12+n]

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
		if err := s.writeFrame(CmdBondData, 0, 0, pl, 0); err != nil {
			alt := bs.g.pickSendSession(s)
			if alt == nil {
				bs.abort(err)
				bs.g.removeStream(bs.id)
				return total, err
			}
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
		bs.g.removeStream(bs.id)
	}
	return err
}

func (bs *BondedStream) Close() error {
	_ = bs.CloseWrite()
	bs.mu.Lock()
	bs.rEOF = true
	bs.reorder = nil
	bs.head = nil
	bs.headOff = 0
	bs.buffered = 0
	bs.rcond.Broadcast()
	bs.wcond.Broadcast()
	bs.mu.Unlock()
	bs.g.removeStream(bs.id)
	return nil
}
