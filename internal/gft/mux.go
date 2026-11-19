package gft

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"math/rand/v2"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"ghostframe/internal/gftrtc"
)

// Ghost Frame v2 commands (8-byte header).
const (
	CmdConnect     byte = 0x01
	CmdData        byte = 0x02
	CmdClose       byte = 0x03
	CmdWindow      byte = 0x04
	CmdPing        byte = 0x05
	CmdParam       byte = 0x06
	CmdUDPDatagram byte = 0x07
	CmdUDPClose    byte = 0x08

	HeaderLen       = 8
	MaxPayload      = 65535
	maxChunk        = 63 * 1024        // 63 KB bulk framing chunk (fits within MaxPayload=65535)
	streamWindow    = 4 * 1024 * 1024  // 4 MB initial BDP window
	maxStreamWindow = 16 * 1024 * 1024 // 16 MB max dynamic BDP window
	windowUpdateN   = 256 * 1024       // minimum replenish step
	visionPhaseN    = 8                // first 8 data frames of each sub-stream get strong padding
)

// Close frame flags.
const (
	CloseFIN byte = 0x01
	CloseRST byte = 0x02
)

// Ping frame flags.
const (
	PingNoise byte = 0x00
	PingReq   byte = 0x01
	PingResp  byte = 0x02
)

var (
	ErrSessionClosed = errors.New("gft: session closed")
	ErrStreamClosed  = errors.New("gft: stream closed")
	ErrStreamReset   = errors.New("gft: stream reset")
	ErrProtocol      = errors.New("gft: protocol violation")
)

// ConnectHandler is invoked in its own goroutine for every incoming CmdConnect.
type ConnectHandler func(s *Stream, target string, first []byte)

// UDPHandler is invoked for incoming CmdUDPDatagram frames on the server.
type UDPHandler func(s *Session, id uint16, target string, data []byte)

// UDPCloseHandler is invoked when a client closes a UDP association (CmdUDPClose).
type UDPCloseHandler func(s *Session, id uint16)

// UDPPacket represents a decoded UDP payload received over CmdUDPDatagram or GFT-RTC.
type UDPPacket = gftrtc.UDPPacket

// StreamInfo is a snapshot of a stream for monitoring.
type StreamInfo struct {
	ID     uint16
	Target string
	Up     uint64
	Down   uint64
}

// Session multiplexes TCP streams and UDP associations over one post-knock connection.
type Session struct {
	conn     net.Conn
	isClient bool
	params   *ParamStore
	onParam  func(Params)
	onPing   func(rtt time.Duration)
	handler  ConnectHandler
	udpH     UDPHandler
	udpClose UDPCloseHandler

	// Optional ServerAck expected before v2/v3 frames on client side.
	hasAck   bool
	hasV3Ack bool
	ackPSK   []byte
	ackSalt  [16]byte

	mu         sync.Mutex
	streams    map[uint16]*Stream
	udpStreams map[uint16]*UDPStream
	nextID     uint16

	wmu  sync.Mutex
	sent int

	done      chan struct{}
	closeOnce sync.Once
	err       atomic.Value // error

	lastReal atomic.Int64 // UnixNano of last real business frame

	UpBytes   atomic.Uint64
	DownBytes atomic.Uint64
	OnBytes   func(up, down int)
}

// NewSession creates a GFT v2 session; call Run() to start reading frames.
func NewSession(c net.Conn, isClient bool, ps *ParamStore, h ConnectHandler) *Session {
	s := &Session{
		conn:       c,
		isClient:   isClient,
		params:     ps,
		handler:    h,
		streams:    make(map[uint16]*Stream),
		udpStreams: make(map[uint16]*UDPStream),
		nextID:     1,
		done:       make(chan struct{}),
	}
	s.lastReal.Store(time.Now().UnixNano())
	return s
}

func (s *Session) SetExpectedAck(psk []byte, salt [16]byte) {
	s.hasAck = true
	s.hasV3Ack = false
	s.ackPSK = append([]byte(nil), psk...)
	s.ackSalt = salt
}

// SetExpectedV3Ack configures the session reader to expect a v3 encrypted ServerAuthAck.
func (s *Session) SetExpectedV3Ack(psk []byte, salt []byte) {
	s.hasAck = false
	s.hasV3Ack = true
	s.ackPSK = append([]byte(nil), psk...)
	copy(s.ackSalt[:], salt)
}

func (s *Session) SetOnParam(f func(Params))       { s.onParam = f }
func (s *Session) SetOnPing(f func(time.Duration)) { s.onPing = f }
func (s *Session) SetUDPHandler(h UDPHandler, c UDPCloseHandler) {
	s.udpH = h
	s.udpClose = c
}
func (s *Session) Done() <-chan struct{}        { return s.done }
func (s *Session) SessionDone() <-chan struct{} { return s.done }

// SendUDPReply implements UDPReplySink for server-side TCP Mux sessions.
func (s *Session) SendUDPReply(id uint16, target string, data []byte) error {
	return s.SendUDPDatagram(id, target, data, visionPhaseN)
}

func (s *Session) Err() error {
	if e, ok := s.err.Load().(error); ok {
		return e
	}
	return nil
}

// TotalBytes returns cumulative payload bytes sent and received on this session.
func (s *Session) TotalBytes() uint64 { return s.UpBytes.Load() + s.DownBytes.Load() }

// Close tears down the session and all streams/UDP associations.
func (s *Session) Close() { s.fail(ErrSessionClosed) }

func (s *Session) fail(err error) {
	s.closeOnce.Do(func() {
		s.err.Store(err)
		close(s.done)
		_ = s.conn.Close()
		s.mu.Lock()
		for id, st := range s.streams {
			delete(s.streams, id)
			st.abort(err)
		}
		for id, ust := range s.udpStreams {
			delete(s.udpStreams, id)
			ust.closeLocal()
		}
		s.mu.Unlock()
	})
}

func (s *Session) StreamInfos() []StreamInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]StreamInfo, 0, len(s.streams))
	for _, st := range s.streams {
		out = append(out, StreamInfo{st.id, st.Target, st.Up.Load(), st.Down.Load()})
	}
	return out
}

// NumStreams returns the number of active TCP streams + UDP associations.
func (s *Session) NumStreams() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.streams) + len(s.udpStreams)
}

func (s *Session) touchReal() {
	s.lastReal.Store(time.Now().UnixNano())
}

// computePadding implements Section 5/6 Vision-inspired adaptive padding.
func (s *Session) computePadding(cmd byte, payload []byte, streamFrameIdx int64, p Params) int {
	switch cmd {
	case CmdConnect, CmdData, CmdUDPDatagram:
		// Phase 1: Handshake erasure (first 8 frames of sub-stream)
		if streamFrameIdx < visionPhaseN {
			return randRange(64, 512)
		}
		// Phase 2: High-speed direct pass (payload >= 1024B OR inner TLS 1.3 Application Data 0x17 0x03 0x03)
		if len(payload) >= 1024 || (len(payload) >= 5 && payload[0] == 0x17 && payload[1] == 0x03 && payload[2] == 0x03) {
			return 0
		}
		// Phase 3: Small-packet perturbation (frame >= 9 and payload < 256B)
		if len(payload) < 256 {
			if p.PadProb > 0 && rand.IntN(100) < p.PadProb {
				hi := p.PadMax
				if hi > 64 {
					hi = 64
				}
				lo := p.PadMin
				if lo > hi {
					lo = hi
				}
				return randRange(lo, hi)
			}
		}
		return 0
	default:
		return 0
	}
}

// writeFrame serialises one Ghost Frame v3 (8B header | payload | padding) via pooled buffer.
func (s *Session) writeFrame(cmd, flags byte, id uint16, payload []byte, streamFrameIdx int64) error {
	if len(payload) > MaxPayload {
		return ErrProtocol
	}
	select {
	case <-s.done:
		return ErrSessionClosed
	default:
	}

	p := s.params.Get()
	pad := s.computePadding(cmd, payload, streamFrameIdx, p)

	bp := GetBuf()
	buf := *bp
	buf[0] = cmd
	buf[1] = flags
	binary.BigEndian.PutUint16(buf[2:], id)
	binary.BigEndian.PutUint16(buf[4:], uint16(len(payload)))
	binary.BigEndian.PutUint16(buf[6:], uint16(pad))

	n := HeaderLen + copy(buf[HeaderLen:], payload)
	if pad > 0 {
		fillRandom(buf[n : n+pad])
		n += pad
	}

	s.wmu.Lock()
	s.sent++
	_, err := s.conn.Write(buf[:n])
	s.wmu.Unlock()
	PutBuf(bp)

	if err != nil {
		s.fail(err)
		return err
	}
	if cmd == CmdConnect || cmd == CmdData || cmd == CmdUDPDatagram {
		s.touchReal()
	}
	return nil
}

// Run processes incoming frames (after optional ServerAck) until connection failure.
func (s *Session) Run() error {
	br := bufio.NewReaderSize(s.conn, 64*1024)

	if s.hasV3Ack {
		p := s.params.Get()
		_ = s.conn.SetReadDeadline(time.Now().Add(time.Duration(p.HbMaxMs+15000) * time.Millisecond))
		ackParams, err := ReadServerAuthAck(br, s.ackPSK, s.ackSalt[:])
		if err != nil {
			s.fail(err)
			return err
		}
		s.params.Set(ackParams)
		if s.onParam != nil {
			s.onParam(ackParams)
		}
	} else if s.hasAck {
		p := s.params.Get()
		_ = s.conn.SetReadDeadline(time.Now().Add(time.Duration(p.HbMaxMs+15000) * time.Millisecond))
		ackParams, ok, err := ReadServerAck(br, s.ackPSK, s.ackSalt)
		if err != nil {
			s.fail(err)
			return err
		}
		if ok {
			s.params.Set(ackParams)
			if s.onParam != nil {
				s.onParam(ackParams)
			}
		}
	}

	go s.heartbeat()

	var hdr [HeaderLen]byte
	bp := GetBuf()
	defer PutBuf(bp)
	payload := (*bp)[:MaxPayload]

	for {
		p := s.params.Get()
		_ = s.conn.SetReadDeadline(time.Now().Add(time.Duration(3*p.HbMaxMs+30000) * time.Millisecond))
		if _, err := io.ReadFull(br, hdr[:]); err != nil {
			s.fail(err)
			return err
		}
		cmd := hdr[0]
		flags := hdr[1]
		id := binary.BigEndian.Uint16(hdr[2:])
		plen := int(binary.BigEndian.Uint16(hdr[4:]))
		pad := int(binary.BigEndian.Uint16(hdr[6:]))

		if plen > 0 {
			if _, err := io.ReadFull(br, payload[:plen]); err != nil {
				s.fail(err)
				return err
			}
		}
		if pad > 0 {
			if _, err := br.Discard(pad); err != nil {
				s.fail(err)
				return err
			}
		}
		if err := s.dispatch(cmd, flags, id, payload[:plen]); err != nil {
			s.fail(err)
			return err
		}
	}
}

func (s *Session) dispatch(cmd, flags byte, id uint16, pl []byte) error {
	switch cmd {
	case CmdConnect:
		if s.handler == nil {
			return ErrProtocol
		}
		s.touchReal()
		target, rest, err := DecodeAddr(pl)
		if err != nil {
			_ = s.writeFrame(CmdClose, CloseRST, id, nil, 0)
			return nil
		}
		s.mu.Lock()
		if _, dup := s.streams[id]; dup {
			s.mu.Unlock()
			return ErrProtocol
		}
		st := newStream(s, id)
		st.Target = target
		s.streams[id] = st
		s.mu.Unlock()
		var first []byte
		if len(rest) > 0 {
			first = append([]byte(nil), rest...)
		}
		go s.handler(st, target, first)

	case CmdData:
		s.touchReal()
		s.mu.Lock()
		st := s.streams[id]
		s.mu.Unlock()
		s.DownBytes.Add(uint64(len(pl)))
		if s.OnBytes != nil {
			s.OnBytes(0, len(pl))
		}
		if st != nil {
			return st.push(pl)
		}

	case CmdClose:
		s.mu.Lock()
		st := s.streams[id]
		s.mu.Unlock()
		if st != nil {
			if flags == CloseRST {
				st.abort(ErrStreamReset)
				s.removeStream(id)
			} else {
				st.remoteClose()
			}
		}

	case CmdWindow:
		if len(pl) >= 4 {
			s.mu.Lock()
			st := s.streams[id]
			s.mu.Unlock()
			if st != nil {
				st.addWindow(int64(binary.BigEndian.Uint32(pl)))
			}
		}

	case CmdPing:
		switch flags {
		case PingReq:
			// Echo exact nanosecond timestamp back to requester
			return s.writeFrame(CmdPing, PingResp, 0, pl, 0)
		case PingResp:
			if len(pl) >= 8 && s.onPing != nil {
				sentNs := int64(binary.BigEndian.Uint64(pl[:8]))
				rtt := time.Duration(time.Now().UnixNano() - sentNs)
				if rtt < 0 {
					rtt = time.Millisecond
				}
				s.onPing(rtt)
			}
		default:
			// PingNoise (0x00) silently dropped
		}

	case CmdParam:
		if s.onParam != nil {
			if p, err := UnmarshalParams(pl); err == nil && p.Validate() == nil {
				s.onParam(p)
			}
		}

	case CmdUDPDatagram:
		s.touchReal()
		target, data, err := DecodeAddr(pl)
		if err != nil {
			return nil
		}
		s.DownBytes.Add(uint64(len(data)))
		if s.OnBytes != nil {
			s.OnBytes(0, len(data))
		}
		if s.isClient {
			s.mu.Lock()
			ust := s.udpStreams[id]
			s.mu.Unlock()
			if ust != nil {
				cp := append([]byte(nil), data...)
				ust.push(UDPPacket{Target: target, Data: cp})
			}
		} else if s.udpH != nil {
			cp := append([]byte(nil), data...)
			s.udpH(s, id, target, cp)
		}

	case CmdUDPClose:
		if s.isClient {
			s.mu.Lock()
			ust := s.udpStreams[id]
			delete(s.udpStreams, id)
			s.mu.Unlock()
			if ust != nil {
				ust.closeLocal()
			}
		} else if s.udpClose != nil {
			s.udpClose(s, id)
		}

	default:
		// Unknown commands ignored for forward compatibility
	}
	return nil
}

// SendParams pushes updated obfuscation parameters to the peer.
func (s *Session) SendParams(p Params) error {
	return s.writeFrame(CmdParam, 0, 0, MarshalParams(p), 0)
}

// SendPingReq sends an in-band CmdPing request carrying an 8-byte nanosecond timestamp.
func (s *Session) SendPingReq() error {
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(time.Now().UnixNano()))
	return s.writeFrame(CmdPing, PingReq, 0, ts[:], 0)
}

// SendUDPDatagram sends a UDP datagram frame over the session for streamID.
func (s *Session) SendUDPDatagram(id uint16, target string, data []byte, frameIdx int64) error {
	addr, err := EncodeAddr(target)
	if err != nil {
		return err
	}
	if len(addr)+len(data) > MaxPayload {
		return ErrProtocol
	}
	pl := make([]byte, len(addr)+len(data))
	copy(pl, addr)
	copy(pl[len(addr):], data)
	if err := s.writeFrame(CmdUDPDatagram, 0, id, pl, frameIdx); err != nil {
		return err
	}
	s.UpBytes.Add(uint64(len(data)))
	if s.OnBytes != nil {
		s.OnBytes(len(data), 0)
	}
	return nil
}

// idle-aware heartbeat: only emits a PingNoise frame if real traffic has been idle
// for the randomized [HbMinMs, HbMaxMs] window.
func (s *Session) heartbeat() {
	t := time.NewTimer(time.Hour)
	defer t.Stop()
	var noise [64]byte

	for {
		p := s.params.Get()
		targetWait := time.Duration(randRange(p.HbMinMs, p.HbMaxMs)) * time.Millisecond
		for {
			last := time.Unix(0, s.lastReal.Load())
			idleFor := time.Since(last)
			if idleFor >= targetWait {
				break
			}
			rem := targetWait - idleFor
			if !t.Stop() {
				select {
				case <-t.C:
				default:
				}
			}
			t.Reset(rem)
			select {
			case <-s.done:
				return
			case <-t.C:
			}
		}
		n := rand.IntN(49) + 16 // 16..64 bytes random noise
		fillRandom(noise[:n])
		if s.writeFrame(CmdPing, PingNoise, 0, noise[:n], 0) != nil {
			return
		}
		s.touchReal()
	}
}

func (s *Session) allocStreamIDLocked() uint16 {
	for i := 0; i < 65535; i++ {
		c := s.nextID
		s.nextID++
		if s.nextID == 0 {
			s.nextID = 1
		}
		if c != 0 {
			_, usedTCP := s.streams[c]
			_, usedUDP := s.udpStreams[c]
			if !usedTCP && !usedUDP {
				return c
			}
		}
	}
	return 0
}

// OpenStream opens a client TCP sub-stream via 0-RTT CmdConnect.
func (s *Session) OpenStream(target string, first []byte) (*Stream, error) {
	addr, err := EncodeAddr(target)
	if err != nil {
		return nil, err
	}
	if len(first) > MaxPayload-len(addr) {
		first = first[:MaxPayload-len(addr)]
	}
	s.mu.Lock()
	select {
	case <-s.done:
		s.mu.Unlock()
		return nil, ErrSessionClosed
	default:
	}
	id := s.allocStreamIDLocked()
	if id == 0 {
		s.mu.Unlock()
		return nil, errors.New("gft: no free stream id")
	}
	st := newStream(s, id)
	st.Target = target
	s.streams[id] = st
	s.mu.Unlock()

	pl := make([]byte, 0, len(addr)+len(first))
	pl = append(pl, addr...)
	pl = append(pl, first...)
	idx := st.framesSent.Add(1) - 1
	if err := s.writeFrame(CmdConnect, 0, id, pl, idx); err != nil {
		s.removeStream(id)
		return nil, err
	}
	st.Up.Add(uint64(len(first)))
	s.UpBytes.Add(uint64(len(first)))
	if s.OnBytes != nil && len(first) > 0 {
		s.OnBytes(len(first), 0)
	}
	return st, nil
}

// OpenUDP allocates a client UDP association stream over this session.
func (s *Session) OpenUDP() (*UDPStream, error) {
	return s.OpenUDPWithID(0)
}

// OpenUDPWithID opens or rebinds a UDP association with an explicit AssocID (for NAT preservation).
func (s *Session) OpenUDPWithID(assocID uint16) (*UDPStream, error) {
	s.mu.Lock()
	select {
	case <-s.done:
		s.mu.Unlock()
		return nil, ErrSessionClosed
	default:
	}
	id := assocID
	if id == 0 {
		id = s.allocStreamIDLocked()
	}
	if id == 0 {
		s.mu.Unlock()
		return nil, errors.New("gft: no free stream id")
	}
	if existing := s.udpStreams[id]; existing != nil {
		s.mu.Unlock()
		return existing, nil
	}
	ust := &UDPStream{
		s:      s,
		id:     id,
		recvCh: make(chan UDPPacket, 128),
		done:   make(chan struct{}),
	}
	s.udpStreams[id] = ust
	s.mu.Unlock()
	return ust, nil
}

func (s *Session) removeStream(id uint16) {
	s.mu.Lock()
	delete(s.streams, id)
	s.mu.Unlock()
}

// ---------------------------------------------------------------------------
// UDPStream: multiplexed UDP association over CmdUDPDatagram / CmdUDPClose

type UDPStream struct {
	s          *Session
	id         uint16
	framesSent atomic.Int64
	recvCh     chan UDPPacket
	done       chan struct{}
	closeOnce  sync.Once
}

func (u *UDPStream) ID() uint16             { return u.id }
func (u *UDPStream) Recv() <-chan UDPPacket { return u.recvCh }
func (u *UDPStream) Done() <-chan struct{}  { return u.done }

func (u *UDPStream) push(pkt UDPPacket) {
	select {
	case <-u.done:
		return
	default:
	}
	select {
	case u.recvCh <- pkt:
	default:
		// Drop oldest on consumer backpressure
	}
}

func (u *UDPStream) SendTo(target string, data []byte) error {
	select {
	case <-u.done:
		return ErrStreamClosed
	default:
	}
	idx := u.framesSent.Add(1) - 1
	return u.s.SendUDPDatagram(u.id, target, data, idx)
}

func (u *UDPStream) closeLocal() {
	u.closeOnce.Do(func() {
		close(u.done)
	})
}

func (u *UDPStream) Close() error {
	u.closeOnce.Do(func() {
		close(u.done)
		u.s.mu.Lock()
		delete(u.s.udpStreams, u.id)
		u.s.mu.Unlock()
		_ = u.s.writeFrame(CmdUDPClose, 0, u.id, nil, 0)
	})
	return nil
}

// ---------------------------------------------------------------------------
// Stream: multiplexed bidirectional TCP byte stream with flow control

type Stream struct {
	s          *Session
	id         uint16
	Target     string
	Up         atomic.Uint64
	Down       atomic.Uint64
	framesSent atomic.Int64

	mu           sync.Mutex
	rcond        *sync.Cond
	wcond        *sync.Cond
	rbuf         []byte
	rpos         int
	consumed     int
	curWindow    int
	winConsumed  int
	lastWinCheck int64
	rEOF         bool  // remote finished sending
	sendWin      int64 // remaining credit to send
	wClosed      bool  // local write side closed
	aborted      error
}

func newStream(s *Session, id uint16) *Stream {
	initWin := EffectiveInitStreamWindow()
	st := &Stream{
		s:            s,
		id:           id,
		sendWin:      int64(initWin),
		curWindow:    initWin,
		lastWinCheck: time.Now().UnixNano(),
	}
	st.rcond = sync.NewCond(&st.mu)
	st.wcond = sync.NewCond(&st.mu)
	return st
}

// RemoteTarget satisfies DataStream.
func (st *Stream) RemoteTarget() string { return st.Target }

func (st *Stream) push(p []byte) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.aborted != nil || st.rEOF {
		return nil
	}
	maxWin := EffectiveMaxStreamWindow()
	limit := 2*st.curWindow + 512*1024
	if limit > 2*maxWin+512*1024 {
		limit = 2*maxWin + 512*1024
	}
	if len(st.rbuf)-st.rpos+len(p) > limit {
		return ErrProtocol
	}
	if st.rpos > 0 && st.rpos == len(st.rbuf) {
		if IsLowMemMode() && cap(st.rbuf) > 64*1024 {
			st.rbuf, st.rpos = nil, 0
		} else {
			st.rbuf, st.rpos = st.rbuf[:0], 0
		}
	} else if st.rpos > st.curWindow {
		n := copy(st.rbuf, st.rbuf[st.rpos:])
		st.rbuf, st.rpos = st.rbuf[:n], 0
	}
	st.rbuf = append(st.rbuf, p...)
	st.Down.Add(uint64(len(p)))
	st.rcond.Broadcast()
	return nil
}

func (st *Stream) remoteClose() {
	st.mu.Lock()
	st.rEOF = true
	st.rcond.Broadcast()
	done := st.wClosed
	st.mu.Unlock()
	if done {
		st.s.removeStream(st.id)
	}
}

func (st *Stream) addWindow(n int64) {
	st.mu.Lock()
	st.sendWin += n
	st.wcond.Broadcast()
	st.mu.Unlock()
}

func (st *Stream) abort(err error) {
	st.mu.Lock()
	if st.aborted == nil {
		st.aborted = err
	}
	st.rcond.Broadcast()
	st.wcond.Broadcast()
	st.mu.Unlock()
}

// Read implements io.Reader; returns io.EOF after the peer closes its write side.
func (st *Stream) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	st.mu.Lock()
	for st.rpos >= len(st.rbuf) {
		if st.aborted != nil {
			err := st.aborted
			st.mu.Unlock()
			return 0, err
		}
		if st.rEOF {
			st.mu.Unlock()
			return 0, io.EOF
		}
		st.rcond.Wait()
	}
	n := copy(p, st.rbuf[st.rpos:])
	st.rpos += n
	st.consumed += n
	st.winConsumed += n

	var upd int
	step := st.curWindow / 4
	if step < windowUpdateN {
		step = windowUpdateN
	}
	if st.consumed >= step {
		upd, st.consumed = st.consumed, 0
		maxWin := EffectiveMaxStreamWindow()
		now := time.Now().UnixNano()
		if st.curWindow < maxWin && st.winConsumed >= st.curWindow/2 {
			if now-st.lastWinCheck <= int64(1500*time.Millisecond) {
				old := st.curWindow
				st.curWindow *= 2
				if st.curWindow > maxWin {
					st.curWindow = maxWin
				}
				upd += st.curWindow - old
			}
			st.winConsumed = 0
			st.lastWinCheck = now
		} else if now-st.lastWinCheck > int64(1500*time.Millisecond) {
			st.winConsumed = 0
			st.lastWinCheck = now
		}
	}
	if st.rpos >= len(st.rbuf) && IsLowMemMode() && cap(st.rbuf) > 64*1024 {
		st.rbuf, st.rpos = nil, 0
	}
	st.mu.Unlock()
	if upd > 0 {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], uint32(upd))
		_ = st.s.writeFrame(CmdWindow, 0, st.id, b[:], 0)
	}
	return n, nil
}

// Write implements io.Writer with flow control and Vision-style adaptive padding.
func (st *Stream) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		st.mu.Lock()
		for st.sendWin <= 0 && st.aborted == nil && !st.wClosed {
			st.wcond.Wait()
		}
		if st.aborted != nil {
			err := st.aborted
			st.mu.Unlock()
			return total, err
		}
		if st.wClosed {
			st.mu.Unlock()
			return total, ErrStreamClosed
		}
		n := len(p)
		if n > maxChunk {
			n = maxChunk
		}
		if int64(n) > st.sendWin {
			n = int(st.sendWin)
		}
		st.sendWin -= int64(n)
		st.mu.Unlock()

		idx := st.framesSent.Add(1) - 1
		if err := st.s.writeFrame(CmdData, 0, st.id, p[:n], idx); err != nil {
			return total, err
		}
		st.Up.Add(uint64(n))
		st.s.UpBytes.Add(uint64(n))
		if st.s.OnBytes != nil {
			st.s.OnBytes(n, 0)
		}
		total += n
		p = p[n:]
	}
	return total, nil
}

// CloseWrite signals EOF on the outgoing side of the sub-stream (CloseFIN).
func (st *Stream) CloseWrite() error {
	st.mu.Lock()
	if st.wClosed {
		st.mu.Unlock()
		return nil
	}
	st.wClosed = true
	st.wcond.Broadcast()
	done := st.rEOF
	st.mu.Unlock()
	err := st.s.writeFrame(CmdClose, CloseFIN, st.id, nil, 0)
	if done {
		st.s.removeStream(st.id)
	}
	return err
}

// Close forcefully closes the stream.
func (st *Stream) Close() error {
	_ = st.CloseWrite()
	st.mu.Lock()
	st.rEOF = true
	st.rcond.Broadcast()
	st.mu.Unlock()
	st.s.removeStream(st.id)
	return nil
}
