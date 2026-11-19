package gftrtc

import (
	"context"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	mrand "math/rand/v2"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

const (
	numSSRCShards      = 256
	inboundQueueDepth  = 4096
	sessionIdleTimeout = 120 * time.Second
	keepaliveMinGap    = 18 * time.Second
	keepaliveMaxGap    = 28 * time.Second
	closedIDRingSize   = 2048
	hopOldCloseDelay   = 3 * time.Second
)

// StreamHandler handles an incoming reliable GFT-RTC stream.
type StreamHandler func(s *RTCStream, target string, first []byte)

// UDPHandler handles an incoming UDP datagram over GFT-RTC.
type UDPHandler func(sink UDPReplySink, id uint16, target string, data []byte)

// UDPCloseHandler handles remote closure of a UDP association.
type UDPCloseHandler func(sink UDPReplySink, id uint16)

// SessionStats reports live protocol-level metrics for telemetry & diagnostics.
type SessionStats struct {
	SSRC         uint32
	Cipher       string
	RemotePort   int
	RTTMs        int64
	SRTTMs       int64
	LossRate     float64
	FECRecovered uint64
	PacingMbps   float64
	UpBytes      uint64
	DownBytes    uint64
	ActiveStream int
}

type inboundPkt struct {
	buf  *[]byte
	n    int
	addr net.Addr
	at   time.Time
}

type closedIDSet struct {
	mu   sync.Mutex
	ring []uint32
	pos  int
	m    map[uint32]struct{}
}

func newClosedIDSet() *closedIDSet {
	return &closedIDSet{
		ring: make([]uint32, closedIDRingSize),
		m:    make(map[uint32]struct{}, 256),
	}
}

func (c *closedIDSet) add(id uint32) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.m[id]; exists {
		return
	}
	if old := c.ring[c.pos]; old != 0 {
		delete(c.m, old)
	}
	c.ring[c.pos] = id
	c.m[id] = struct{}{}
	c.pos = (c.pos + 1) % len(c.ring)
}

func (c *closedIDSet) has(id uint32) bool {
	c.mu.Lock()
	_, ok := c.m[id]
	c.mu.Unlock()
	return ok
}

// RTCSession represents a single GhostFrame-RTC encrypted session supporting Zero-HOL streams,
// 0ms XOR-FEC, Smart-Brutal CC, fragmented/fallback UDP, and 0ms socket migration (port hopping).
type RTCSession struct {
	isClient bool
	ssrc     uint32
	clientID [8]byte
	host     string
	keys     *SessionKeys
	txAEAD   cipher.AEAD
	rxAEAD   cipher.AEAD
	txIV     [4]byte
	rxIV     [4]byte
	txMask   uint64
	rxMask   uint64

	paramsJSON []byte
	startTime  time.Time
	baseTS90k  uint32
	rtpSeq     atomic.Uint32
	pktNum     atomic.Uint64

	listener *RTCListener // non-nil on server sessions

	connMu       sync.RWMutex
	curConn      net.PacketConn
	curOwn       bool
	curRemote    net.Addr
	curRemoteStr string
	remotePort   atomic.Int32
	oldConns     []net.PacketConn

	inboundCh chan inboundPkt
	sendKick  chan struct{}
	ackKick   chan struct{}
	pingCh    chan time.Duration

	replay *ReplayWindow
	loss   *LossTracker
	fecEnc *FECEncoder
	fecDec *FECDecoder
	cc     *SmartBrutalCC

	qMu         sync.Mutex
	retransmitQ []ReliableFrame
	ctrlQ       [][]byte
	udpQ        [][]byte
	sendRR      []*RTCStream
	sendRRIdx   int
	inSendRR    map[uint32]bool

	mu             sync.Mutex
	streams        map[uint32]*RTCStream
	pendingStreams map[uint32]*RTCStream
	closedIDs      *closedIDSet
	nextStream     uint32
	udps           map[uint16]*RTCUDPAssoc
	nextUDP        uint16
	nextMsgID      atomic.Uint32
	frags          map[uint32]*udpReassemblyEntry
	lastFragGC     int64
	udpFallback    *RTCStream
	udpFbMu        sync.Mutex

	streamCount atomic.Int64
	rttNs       atomic.Int64
	lastRecvNs  atomic.Int64
	lastSendNs  atomic.Int64
	lastUDPNs   atomic.Int64
	UpBytes     atomic.Uint64
	DownBytes   atomic.Uint64

	onStream      StreamHandler
	onUDP         UDPHandler
	onUDPClose    UDPCloseHandler
	onBytes       func(up, down int)
	handlersReady chan struct{}
	handlersOnce  sync.Once

	done      chan struct{}
	closeOnce sync.Once
	errVal    atomic.Value
}

func newRTCSession(isClient bool, ssrc uint32, clientID [8]byte, host string, remotePort int, keys *SessionKeys, targetMbps int, paramsJSON []byte, listener *RTCListener) *RTCSession {
	now := time.Now()
	txAEAD, rxAEAD := keys.S2CAEAD, keys.C2SAEAD
	txIV, rxIV := keys.S2CIV, keys.C2SIV
	txMask, rxMask := keys.S2CMask, keys.C2SMask
	nextStream := uint32(2) // server allocates even stream IDs
	if isClient {
		txAEAD, rxAEAD = keys.C2SAEAD, keys.S2CAEAD
		txIV, rxIV = keys.C2SIV, keys.S2CIV
		txMask, rxMask = keys.C2SMask, keys.S2CMask
		nextStream = 1 // client allocates odd stream IDs
	}

	s := &RTCSession{
		isClient:       isClient,
		ssrc:           ssrc,
		clientID:       clientID,
		host:           host,
		keys:           keys,
		txAEAD:         txAEAD,
		rxAEAD:         rxAEAD,
		txIV:           txIV,
		rxIV:           rxIV,
		txMask:         txMask,
		rxMask:         rxMask,
		paramsJSON:     paramsJSON,
		startTime:      now,
		baseTS90k:      mrand.Uint32(),
		listener:       listener,
		inboundCh:      make(chan inboundPkt, inboundQueueDepth),
		sendKick:       make(chan struct{}, 1),
		ackKick:        make(chan struct{}, 1),
		pingCh:         make(chan time.Duration, 4),
		replay:         &ReplayWindow{},
		loss:           NewLossTracker(),
		fecEnc:         NewFECEncoder(),
		fecDec:         NewFECDecoder(),
		cc:             NewSmartBrutalCC(targetMbps),
		inSendRR:       make(map[uint32]bool),
		streams:        make(map[uint32]*RTCStream),
		pendingStreams: make(map[uint32]*RTCStream),
		closedIDs:      newClosedIDSet(),
		nextStream:     nextStream,
		udps:           make(map[uint16]*RTCUDPAssoc),
		nextUDP:        1,
		frags:          make(map[uint32]*udpReassemblyEntry),
		handlersReady:  make(chan struct{}),
		done:           make(chan struct{}),
	}
	s.remotePort.Store(int32(remotePort))
	s.lastRecvNs.Store(now.UnixNano())
	s.lastSendNs.Store(now.UnixNano())
	return s
}

func (s *RTCSession) startLoops() {
	go s.inboundWorker()
	go s.sendLoop()
	go s.timerLoop()
}

// ClientID returns the persistent 8-byte client identifier authenticated during STUN handshake.
func (s *RTCSession) ClientID() [8]byte { return s.clientID }

// ParamsJSON returns the raw params JSON exchanged during Stage 1 handshake.
func (s *RTCSession) ParamsJSON() []byte { return s.paramsJSON }

// SSRC returns this session's unique 32-bit WebRTC SSRC identifier.
func (s *RTCSession) SSRC() uint32 { return s.ssrc }

// RemotePort returns the current destination UDP port.
func (s *RTCSession) RemotePort() int { return int(s.remotePort.Load()) }

// NumStreams returns the number of currently active streams.
func (s *RTCSession) NumStreams() int { return int(s.streamCount.Load()) }

// Done returns a channel closed when the session terminates.
func (s *RTCSession) Done() <-chan struct{} { return s.done }

// SessionDone satisfies UDPReplySink.
func (s *RTCSession) SessionDone() <-chan struct{} { return s.done }

// RTT returns the most recent measured RTT.
func (s *RTCSession) RTT() time.Duration { return time.Duration(s.rttNs.Load()) }

// LastUDPTime returns when UDP traffic was last exchanged on this session.
func (s *RTCSession) LastUDPTime() time.Time {
	ns := s.lastUDPNs.Load()
	if ns == 0 {
		return time.Time{}
	}
	return time.Unix(0, ns)
}

// SetHandlers attaches server-side callbacks for incoming streams and UDP associations.
func (s *RTCSession) SetHandlers(onStream StreamHandler, onUDP UDPHandler, onUDPClose UDPCloseHandler) {
	s.mu.Lock()
	s.onStream = onStream
	s.onUDP = onUDP
	s.onUDPClose = onUDPClose
	s.mu.Unlock()
	s.handlersOnce.Do(func() { close(s.handlersReady) })
}

// SetOnBytes installs a live byte counter hook (up, down).
func (s *RTCSession) SetOnBytes(fn func(up, down int)) {
	s.mu.Lock()
	s.onBytes = fn
	s.mu.Unlock()
}

// UpdateBandwidth adjusts the Smart-Brutal pacing target at runtime (0 = Auto-Probe).
func (s *RTCSession) UpdateBandwidth(targetMbps int) {
	s.cc.SetTargetMbps(targetMbps)
}

// Stats returns a live protocol telemetry snapshot.
func (s *RTCSession) Stats() SessionStats {
	srtt, _, _ := s.loss.RTTMetrics(time.Now())
	return SessionStats{
		SSRC:         s.ssrc,
		Cipher:       s.keys.CipherName,
		RemotePort:   int(s.remotePort.Load()),
		RTTMs:        time.Duration(s.rttNs.Load()).Milliseconds(),
		SRTTMs:       srtt.Milliseconds(),
		LossRate:     s.loss.LossRate(),
		FECRecovered: s.fecDec.RecoveredCount(),
		PacingMbps:   s.cc.PacingMbps(),
		UpBytes:      s.UpBytes.Load(),
		DownBytes:    s.DownBytes.Load(),
		ActiveStream: int(s.streamCount.Load()),
	}
}

func (s *RTCSession) decStreams() { s.streamCount.Add(-1) }

func (s *RTCSession) kickSend() {
	select {
	case s.sendKick <- struct{}{}:
	default:
	}
}

func (s *RTCSession) kickACK() {
	select {
	case s.ackKick <- struct{}{}:
	default:
	}
}

func (s *RTCSession) markStreamSendable(st *RTCStream) {
	s.qMu.Lock()
	if !s.inSendRR[st.id] {
		s.inSendRR[st.id] = true
		s.sendRR = append(s.sendRR, st)
	}
	s.qMu.Unlock()
	s.kickSend()
}

func (s *RTCSession) enqueueReliableFrame(frame []byte) {
	s.qMu.Lock()
	s.retransmitQ = append(s.retransmitQ, ReliableFrame{Bytes: frame})
	s.qMu.Unlock()
	s.kickSend()
}

func (s *RTCSession) enqueueCtrlFrame(frame []byte) {
	s.qMu.Lock()
	s.ctrlQ = append(s.ctrlQ, frame)
	s.qMu.Unlock()
	s.kickSend()
}

func (s *RTCSession) enqueueUDPFrame(frame []byte) {
	s.qMu.Lock()
	if len(s.udpQ) < 2048 {
		s.udpQ = append(s.udpQ, frame)
	}
	s.qMu.Unlock()
	s.kickSend()
}

func (s *RTCSession) removeStream(id uint32) {
	s.closedIDs.add(id)
	s.mu.Lock()
	delete(s.streams, id)
	delete(s.pendingStreams, id)
	s.mu.Unlock()
}

func (s *RTCSession) getOrCreatePendingStream(id uint32) *RTCStream {
	if s.closedIDs.has(id) {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if st := s.streams[id]; st != nil {
		return st
	}
	if st := s.pendingStreams[id]; st != nil {
		return st
	}
	if len(s.pendingStreams) >= 128 {
		return nil
	}
	st := newRTCStream(s, id, "")
	s.pendingStreams[id] = st
	return st
}

func (s *RTCSession) currentTS90k() uint32 {
	ns := time.Since(s.startTime).Nanoseconds()
	return s.baseTS90k + uint32((ns*90000)/1_000_000_000)
}

func (s *RTCSession) nextPktNum() uint64 {
	return s.pktNum.Add(1)
}

func (s *RTCSession) writeWirePacket(pkt []byte) error {
	s.connMu.RLock()
	pc := s.curConn
	raddr := s.curRemote
	s.connMu.RUnlock()
	if pc == nil || raddr == nil {
		return ErrSessionClosed
	}
	_, err := pc.WriteTo(pkt, raddr)
	if err == nil {
		s.lastSendNs.Store(time.Now().UnixNano())
	}
	return err
}

func (s *RTCSession) sealAndWrite(plain []byte, pt uint8, marker bool) (pktNum uint64, wireLen int, err error) {
	bp := GetPktBuf()
	defer PutPktBuf(bp)
	pktNum = s.nextPktNum()
	seq := uint16(s.rtpSeq.Add(1))
	ts := s.currentTS90k()
	sealed, serr := SealRTP(*bp, s.txAEAD, s.txIV, s.txMask, s.ssrc, seq, ts, pt, marker, pktNum, plain)
	if serr != nil {
		return 0, 0, serr
	}
	wireLen = len(sealed)
	err = s.writeWirePacket(sealed)
	return pktNum, wireLen, err
}

func (s *RTCSession) sendSACKNow() {
	now := time.Now()
	largest, delayUs, blocks, ok := s.replay.BuildSACK(now)
	if !ok {
		return
	}
	frame := encodeFrameSACK(largest, delayUs, blocks)
	var plain [FECHeaderLen + 160]byte
	copy(plain[FECHeaderLen:], frame)
	_, _, _ = s.sealAndWrite(plain[:FECHeaderLen+len(frame)], PTAudioCtrl, true)
}

func (s *RTCSession) popRetransmitOrPending(budget int) (frames [][]byte, reliable []ReliableFrame, pt uint8, hasStreamData bool) {
	s.qMu.Lock()
	defer s.qMu.Unlock()

	used := 0
	pt = PTAudioCtrl

	// 1. Retransmissions get top priority (zero head-of-line blocking recovery)
	for len(s.retransmitQ) > 0 {
		rf := s.retransmitQ[0]
		if used+len(rf.Bytes) > budget {
			if used == 0 {
				// Defensive clamp should never trigger (frames <= 1316)
				s.retransmitQ = s.retransmitQ[1:]
				continue
			}
			break
		}
		s.retransmitQ[0] = ReliableFrame{}
		s.retransmitQ = s.retransmitQ[1:]
		frames = append(frames, rf.Bytes)
		reliable = append(reliable, rf)
		used += len(rf.Bytes)
		hasStreamData = true
		pt = PTVideoData
	}

	// 2. Low-latency unreliable UDP datagrams
	for len(s.udpQ) > 0 {
		u := s.udpQ[0]
		if used+len(u) > budget {
			break
		}
		s.udpQ[0] = nil
		s.udpQ = s.udpQ[1:]
		frames = append(frames, u)
		used += len(u)
		if len(u) > 200 {
			pt = PTVideoData
		}
	}

	// 3. Control frames (Window updates, Pings, UDPClose)
	for len(s.ctrlQ) > 0 {
		cf := s.ctrlQ[0]
		if used+len(cf) > budget {
			break
		}
		s.ctrlQ[0] = nil
		s.ctrlQ = s.ctrlQ[1:]
		frames = append(frames, cf)
		used += len(cf)
	}

	// 4. Round-robin pull from active streams for fair zero-starvation bandwidth sharing
	if len(s.sendRR) > 0 {
		visited := 0
		for visited < len(s.sendRR) && used < budget {
			if s.sendRRIdx >= len(s.sendRR) {
				s.sendRRIdx = 0
			}
			st := s.sendRR[s.sendRRIdx]
			fr, needPad, more, ok := st.popSendFrame(budget - used)
			if !more {
				delete(s.inSendRR, st.id)
				last := len(s.sendRR) - 1
				s.sendRR[s.sendRRIdx] = s.sendRR[last]
				s.sendRR[last] = nil
				s.sendRR = s.sendRR[:last]
				// Don't increment sendRRIdx; new element shifted into s.sendRRIdx
			} else {
				s.sendRRIdx++
				visited++
			}
			if ok {
				frames = append(frames, fr)
				reliable = append(reliable, ReliableFrame{Bytes: fr})
				used += len(fr)
				hasStreamData = true
				pt = PTVideoData
				if needPad && budget-used >= 24 {
					maxPad := budget - used - 3
					if maxPad > 48 {
						maxPad = 48
					}
					padLen := 16
					if maxPad > 16 {
						padLen += mrand.IntN(maxPad - 15)
					}
					pf := encodeFramePadding(padLen)
					frames = append(frames, pf)
					used += len(pf)
				}
			} else if !more {
				continue
			} else {
				// Couldn't fit inside remaining space -> stop pulling streams into this packet
				break
			}
		}
		if len(s.retransmitQ) == 0 && cap(s.retransmitQ) > 256 {
			s.retransmitQ = nil
		}
		if len(s.ctrlQ) == 0 && cap(s.ctrlQ) > 256 {
			s.ctrlQ = nil
		}
		if len(s.udpQ) == 0 && cap(s.udpQ) > 256 {
			s.udpQ = nil
		}
	}

	return frames, reliable, pt, hasStreamData
}

func (s *RTCSession) hasPendingData() bool {
	s.qMu.Lock()
	has := len(s.retransmitQ) > 0 || len(s.udpQ) > 0 || len(s.ctrlQ) > 0 || len(s.sendRR) > 0
	s.qMu.Unlock()
	return has
}

func (s *RTCSession) sendLoop() {
	frameAreaPtr := GetPktBuf()
	plainPtr := GetPktBuf()
	defer PutPktBuf(frameAreaPtr)
	defer PutPktBuf(plainPtr)

	var paceTimer *time.Timer
	defer func() {
		if paceTimer != nil {
			paceTimer.Stop()
		}
	}()

	for {
		select {
		case <-s.done:
			return
		default:
		}

		// Fast path for SACK feedback (never blocked by CC pacer!)
		select {
		case <-s.ackKick:
			s.sendSACKNow()
		default:
		}

		if !s.hasPendingData() {
			select {
			case <-s.done:
				return
			case <-s.ackKick:
				s.sendSACKNow()
			case <-s.sendKick:
			}
			continue
		}

		now := time.Now()
		srtt, _, _ := s.loss.RTTMetrics(now)
		inFlight := s.loss.InFlightBytes()
		allowed, waitDur := s.cc.CanSend(inFlight, srtt, now)
		if !allowed {
			if paceTimer == nil {
				paceTimer = time.NewTimer(waitDur)
			} else {
				if !paceTimer.Stop() {
					select {
					case <-paceTimer.C:
					default:
					}
				}
				paceTimer.Reset(waitDur)
			}
			select {
			case <-s.done:
				return
			case <-s.ackKick:
				s.sendSACKNow()
			case <-paceTimer.C:
			}
			continue
		}

		lossRate := s.loss.LossRate()
		budget := MaxFrameArea
		if SelectFECCount(lossRate) > 0 {
			budget = MaxFECFrameArea
		}

		frames, reliable, pt, _ := s.popRetransmitOrPending(budget)
		if len(frames) == 0 {
			continue
		}

		used := 0
		area := (*frameAreaPtr)[:budget]
		for _, fr := range frames {
			copy(area[used:], fr)
			used += len(fr)
		}

		// Opportunistically piggyback pending SACK when room permits
		if s.replay.NeedsDelayedACK(now) || s.ackPendingCheck() {
			largest, delayUs, blocks, ok := s.replay.BuildSACK(now)
			if ok {
				sf := encodeFrameSACK(largest, delayUs, blocks)
				if used+len(sf) <= budget {
					copy(area[used:], sf)
					used += len(sf)
				} else {
					s.sendSACKNow()
				}
			}
		}

		srcPlain, preParity, postParity := s.fecEnc.WrapPlaintext((*plainPtr)[:], area[:used], lossRate, now)
		if preParity != nil {
			marker := s.cc.ConsumeBytes(len(preParity) + RTPOverhead)
			_, _, _ = s.sealAndWrite(preParity, PTVideoData, marker)
		}

		marker := s.cc.ConsumeBytes(len(srcPlain) + RTPOverhead)
		if postParity != nil {
			marker = false // parity finishes the micro-burst
		}
		pn, wlen, err := s.sealAndWrite(srcPlain, pt, marker)
		if err == nil && len(reliable) > 0 {
			s.loss.OnPacketSent(pn, wlen, reliable, now)
		}
		if postParity != nil {
			m2 := s.cc.ConsumeBytes(len(postParity) + RTPOverhead)
			_, _, _ = s.sealAndWrite(postParity, PTVideoData, m2)
		}
	}
}

func (s *RTCSession) ackPendingCheck() bool {
	s.replay.mu.Lock()
	p := s.replay.ackPending
	s.replay.mu.Unlock()
	return p
}

func (s *RTCSession) timerLoop() {
	t := time.NewTicker(5 * time.Millisecond)
	defer t.Stop()
	nextKeepalive := time.Now().Add(keepaliveMinGap + time.Duration(mrand.Int64N(int64(keepaliveMaxGap-keepaliveMinGap))))

	for {
		select {
		case <-s.done:
			return
		case now := <-t.C:
			if s.replay.NeedsDelayedACK(now) {
				s.kickACK()
			}

			if parity, ok := s.fecEnc.FlushIfDue(now); ok {
				_, _, _ = s.sealAndWrite(parity, PTVideoData, true)
			}

			lostFrames, ptoCount, lossRate, srtt, minRTT := s.loss.PollTimeouts(now)
			if len(lostFrames) > 0 {
				s.qMu.Lock()
				s.retransmitQ = append(s.retransmitQ, lostFrames...)
				s.qMu.Unlock()
				s.cc.OnFeedback(0, lossRate, srtt, minRTT, ptoCount, now)
				s.kickSend()
			}

			// Server idle timeout cleanup
			if !s.isClient {
				lastR := time.Unix(0, s.lastRecvNs.Load())
				if now.Sub(lastR) > sessionIdleTimeout {
					s.fail(errors.New("gftrtc: session idle timeout"))
					return
				}
			} else if now.After(nextKeepalive) {
				nextKeepalive = now.Add(keepaliveMinGap + time.Duration(mrand.Int64N(int64(keepaliveMaxGap-keepaliveMinGap))))
				lastSend := time.Unix(0, s.lastSendNs.Load())
				if now.Sub(lastSend) >= keepaliveMinGap {
					_ = s.writeWirePacket(BuildSTUNIndication())
				}
			}
		}
	}
}

func (s *RTCSession) enqueueInbound(pkt inboundPkt) {
	select {
	case s.inboundCh <- pkt:
	case <-s.done:
		PutPktBuf(pkt.buf)
	default:
		PutPktBuf(pkt.buf)
	}
}

func (s *RTCSession) inboundWorker() {
	ptPtr := GetPktBuf()
	defer PutPktBuf(ptPtr)

	for {
		select {
		case <-s.done:
			// Drain leftover pooled buffers
			for {
				select {
				case p := <-s.inboundCh:
					PutPktBuf(p.buf)
				default:
					return
				}
			}
		case pkt := <-s.inboundCh:
			s.handleInboundPacket(pkt, (*ptPtr)[:0])
			PutPktBuf(pkt.buf)
		}
	}
}

func (s *RTCSession) handleInboundPacket(pkt inboundPkt, dst []byte) {
	wire := (*pkt.buf)[:pkt.n]
	_, maskedPN, ok := ParseRTPHeaderFields(wire)
	if !ok {
		return
	}
	pn := maskedPN ^ s.rxMask
	if !s.replay.Allow(pn) {
		return
	}
	pktNum, pt, _, _, err := OpenRTP(dst, wire, s.rxAEAD, s.rxIV, s.rxMask)
	if err != nil || len(pt) < FECHeaderLen {
		return
	}

	s.lastRecvNs.Store(pkt.at.UnixNano())

	// 0ms Seamless Client Migration on server: authenticated AEAD proved sender owns session keys.
	if !s.isClient && pkt.addr != nil {
		addrStr := pkt.addr.String()
		s.connMu.RLock()
		curStr := s.curRemoteStr
		s.connMu.RUnlock()
		if addrStr != curStr {
			s.connMu.Lock()
			s.curRemote = pkt.addr
			s.curRemoteStr = addrStr
			s.connMu.Unlock()
		}
	}

	fecGID := binary.BigEndian.Uint32(pt[0:4])
	fecIdx := pt[4]
	fecCount := pt[5]
	body := pt[FECHeaderLen:]

	ackEliciting := false
	if fecCount > 0 && fecIdx == fecCount {
		// Parity packet
		ackEliciting = true
		if recovered, ok := s.fecDec.Process(fecGID, fecIdx, fecCount, body); ok {
			_ = s.dispatchFrames(recovered, pkt.at)
		}
	} else {
		// Source packet: deliver immediately at 0ms
		ackEliciting = s.dispatchFrames(body, pkt.at)
		if fecCount > 0 {
			if recovered, ok := s.fecDec.Process(fecGID, fecIdx, fecCount, body); ok {
				_ = s.dispatchFrames(recovered, pkt.at)
			}
		}
	}

	if s.replay.Commit(pktNum, ackEliciting, pkt.at) {
		s.kickACK()
	}
}

func (s *RTCSession) dispatchFrames(b []byte, now time.Time) (ackEliciting bool) {
	off := 0
	for off < len(b) {
		typ := b[off]
		off++
		switch typ {
		case FramePadding:
			if off+2 > len(b) {
				return ackEliciting
			}
			plen := int(binary.BigEndian.Uint16(b[off : off+2]))
			off += 2
			if off+plen > len(b) {
				return ackEliciting
			}
			off += plen

		case FrameStreamOpen:
			if off+5 > len(b) {
				return ackEliciting
			}
			ackEliciting = true
			streamID := binary.BigEndian.Uint32(b[off : off+4])
			alen := int(b[off+4])
			off += 5
			if alen == 0 || off+alen+2 > len(b) {
				return ackEliciting
			}
			addrBytes := b[off : off+alen]
			off += alen
			dlen := int(binary.BigEndian.Uint16(b[off : off+2]))
			off += 2
			if off+dlen > len(b) {
				return ackEliciting
			}
			first := make([]byte, dlen)
			copy(first, b[off:off+dlen])
			off += dlen

			target, rest, err := DecodeAddr(addrBytes)
			if err == nil && len(rest) == 0 {
				s.handleInboundStreamOpen(streamID, target, first)
			}

		case FrameStreamData:
			if off+10 > len(b) {
				return ackEliciting
			}
			ackEliciting = true
			streamID := binary.BigEndian.Uint32(b[off : off+4])
			seq := binary.BigEndian.Uint32(b[off+4 : off+8])
			dlen := int(binary.BigEndian.Uint16(b[off+8 : off+10]))
			off += 10
			if off+dlen > len(b) {
				return ackEliciting
			}
			payload := b[off : off+dlen]
			off += dlen
			st := s.getOrCreatePendingStream(streamID)
			if st != nil {
				st.deliverChunk(seq, payload)
			}

		case FrameStreamFIN:
			if off+8 > len(b) {
				return ackEliciting
			}
			ackEliciting = true
			streamID := binary.BigEndian.Uint32(b[off : off+4])
			finSeq := binary.BigEndian.Uint32(b[off+4 : off+8])
			off += 8
			st := s.getOrCreatePendingStream(streamID)
			if st != nil {
				st.deliverFIN(finSeq)
			}

		case FrameStreamRST:
			if off+4 > len(b) {
				return ackEliciting
			}
			ackEliciting = true
			streamID := binary.BigEndian.Uint32(b[off : off+4])
			off += 4
			s.mu.Lock()
			st := s.streams[streamID]
			if st == nil {
				st = s.pendingStreams[streamID]
				delete(s.pendingStreams, streamID)
			}
			s.mu.Unlock()
			if st != nil {
				st.deliverRST()
			}

		case FrameStreamWin:
			if off+8 > len(b) {
				return ackEliciting
			}
			streamID := binary.BigEndian.Uint32(b[off : off+4])
			maxAllowed := binary.BigEndian.Uint32(b[off+4 : off+8])
			off += 8
			s.mu.Lock()
			st := s.streams[streamID]
			s.mu.Unlock()
			if st != nil {
				st.updatePeerMaxSeq(maxAllowed)
			}

		case FrameSACK:
			if off+13 > len(b) {
				return ackEliciting
			}
			largest := binary.BigEndian.Uint64(b[off : off+8])
			delayUs := binary.BigEndian.Uint32(b[off+8 : off+12])
			cnt := int(b[off+12])
			off += 13
			if off+cnt*4 > len(b) {
				return ackEliciting
			}
			var blocks []SACKBlock
			if cnt > 0 {
				blocks = make([]SACKBlock, cnt)
				for i := 0; i < cnt; i++ {
					blocks[i] = SACKBlock{
						Gap: binary.BigEndian.Uint16(b[off : off+2]),
						Len: binary.BigEndian.Uint16(b[off+2 : off+4]),
					}
					off += 4
				}
			}
			sr := s.loss.OnSACK(largest, delayUs, blocks, now)
			if sr.HasRTT {
				s.rttNs.Store(int64(sr.RTTSample))
			}
			s.cc.OnFeedback(sr.AckedBytes, sr.LossRate, sr.SRTT, sr.MinRTT, 0, now)
			if len(sr.LostFrames) > 0 {
				s.qMu.Lock()
				s.retransmitQ = append(s.retransmitQ, sr.LostFrames...)
				s.qMu.Unlock()
				s.kickSend()
			}

		case FrameUDPDatagram:
			if off+8 > len(b) {
				return ackEliciting
			}
			assocID := binary.BigEndian.Uint16(b[off : off+2])
			msgID := binary.BigEndian.Uint16(b[off+2 : off+4])
			fragIdx := b[off+4]
			fragTotal := b[off+5]
			blen := int(binary.BigEndian.Uint16(b[off+6 : off+8]))
			off += 8
			if off+blen > len(b) {
				return ackEliciting
			}
			body := b[off : off+blen]
			off += blen
			s.handleInboundUDPDatagram(assocID, msgID, fragIdx, fragTotal, body, now)

		case FrameUDPClose:
			if off+2 > len(b) {
				return ackEliciting
			}
			assocID := binary.BigEndian.Uint16(b[off : off+2])
			off += 2
			s.handleInboundUDPClose(assocID)

		case FramePing:
			if off+8 > len(b) {
				return ackEliciting
			}
			ts := int64(binary.BigEndian.Uint64(b[off : off+8]))
			off += 8
			s.enqueueCtrlFrame(encodeFramePingPong(FramePong, ts))

		case FramePong:
			if off+8 > len(b) {
				return ackEliciting
			}
			sent := int64(binary.BigEndian.Uint64(b[off : off+8]))
			off += 8
			rtt := time.Duration(time.Now().UnixNano() - sent)
			if rtt <= 0 {
				rtt = time.Millisecond
			}
			s.rttNs.Store(int64(rtt))
			select {
			case s.pingCh <- rtt:
			default:
			}

		default:
			return ackEliciting
		}
	}
	return ackEliciting
}

func (s *RTCSession) handleInboundStreamOpen(streamID uint32, target string, first []byte) {
	if s.closedIDs.has(streamID) {
		return
	}
	s.mu.Lock()
	if _, exists := s.streams[streamID]; exists {
		s.mu.Unlock()
		return
	}
	st := s.pendingStreams[streamID]
	if st != nil {
		delete(s.pendingStreams, streamID)
		st.target = target
	} else {
		st = newRTCStream(s, streamID, target)
	}
	s.streams[streamID] = st
	h := s.onStream
	s.mu.Unlock()

	s.streamCount.Add(1)
	if len(first) > 0 {
		s.DownBytes.Add(uint64(len(first)))
		if s.onBytes != nil {
			s.onBytes(0, len(first))
		}
	}

	if target == udpFallbackTarget {
		go s.serveUDPStream(st, first)
		return
	}
	if h == nil && !s.isClient {
		go func() {
			t := time.NewTimer(time.Second)
			defer t.Stop()
			select {
			case <-s.handlersReady:
				s.mu.Lock()
				hh := s.onStream
				s.mu.Unlock()
				if hh != nil {
					hh(st, target, first)
					return
				}
			case <-t.C:
			case <-s.done:
				return
			}
			_ = st.Close()
		}()
		return
	}
	if h != nil {
		go h(st, target, first)
	} else {
		_ = st.Close()
	}
}

func (s *RTCSession) handleInboundUDPDatagram(assocID, msgID uint16, fragIdx, fragTotal uint8, body []byte, now time.Time) {
	if fragTotal == 1 && fragIdx == 0 {
		s.deliverInboundUDP(assocID, body, now)
		return
	}
	if fragTotal == 0 || fragTotal > maxUDPFrags || fragIdx >= fragTotal {
		return
	}
	key := (uint32(assocID) << 16) | uint32(msgID)

	s.mu.Lock()
	if now.UnixNano()-s.lastFragGC > int64(udpReassemblyTTL) {
		s.lastFragGC = now.UnixNano()
		for k, e := range s.frags {
			if now.Sub(e.createdAt) > udpReassemblyTTL {
				delete(s.frags, k)
			}
		}
	}
	entry, ok := s.frags[key]
	if !ok {
		if len(s.frags) >= maxUDPFragPoolSlot {
			for k := range s.frags {
				delete(s.frags, k)
				break
			}
		}
		entry = &udpReassemblyEntry{
			total:     int(fragTotal),
			parts:     make([][]byte, fragTotal),
			createdAt: now,
		}
		s.frags[key] = entry
	}
	if entry.total != int(fragTotal) {
		delete(s.frags, key)
		s.mu.Unlock()
		return
	}
	var assembled []byte
	if entry.parts[fragIdx] == nil {
		cp := make([]byte, len(body))
		copy(cp, body)
		entry.parts[fragIdx] = cp
		entry.received++
		if entry.received == entry.total {
			tot := 0
			for _, p := range entry.parts {
				tot += len(p)
			}
			if tot <= maxUDPStreamBody+512 {
				assembled = make([]byte, 0, tot)
				for _, p := range entry.parts {
					assembled = append(assembled, p...)
				}
			}
			delete(s.frags, key)
		}
	}
	s.mu.Unlock()

	if assembled != nil {
		s.deliverInboundUDP(assocID, assembled, now)
	}
}

func (s *RTCSession) deliverInboundUDP(assocID uint16, body []byte, now time.Time) {
	target, data, err := DecodeAddr(body)
	if err != nil {
		return
	}
	s.lastUDPNs.Store(now.UnixNano())
	s.DownBytes.Add(uint64(len(data)))
	if s.onBytes != nil {
		s.onBytes(0, len(data))
	}
	cp := make([]byte, len(data))
	copy(cp, data)

	s.mu.Lock()
	u := s.udps[assocID]
	uh := s.onUDP
	s.mu.Unlock()

	if s.isClient {
		if u != nil {
			u.push(UDPPacket{Target: target, Data: cp})
		}
	} else if uh != nil {
		uh(s, assocID, target, cp)
	}
}

func (s *RTCSession) handleInboundUDPClose(assocID uint16) {
	if s.isClient {
		s.mu.Lock()
		u := s.udps[assocID]
		delete(s.udps, assocID)
		s.mu.Unlock()
		if u != nil {
			u.CloseLocal()
		}
		return
	}
	s.mu.Lock()
	uch := s.onUDPClose
	s.mu.Unlock()
	if uch != nil {
		uch(s, assocID)
	}
}

func (s *RTCSession) serveUDPStream(st *RTCStream, first []byte) {
	defer st.Close()
	r := io.Reader(st)
	if len(first) > 0 {
		r = io.MultiReader(&sliceReader{b: first}, st)
	}
	var hdr [4]byte
	for {
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			return
		}
		id := binary.BigEndian.Uint16(hdr[0:2])
		blen := int(binary.BigEndian.Uint16(hdr[2:4]))
		if blen < 4 || blen > maxUDPStreamBody+512 {
			return
		}
		body := make([]byte, blen)
		if _, err := io.ReadFull(r, body); err != nil {
			return
		}
		s.deliverInboundUDP(id, body, time.Now())
	}
}

type sliceReader struct {
	b   []byte
	off int
}

func (r *sliceReader) Read(p []byte) (int, error) {
	if r.off >= len(r.b) {
		return 0, io.EOF
	}
	n := copy(p, r.b[r.off:])
	r.off += n
	return n, nil
}

// OpenStream opens a new Zero-HOL-Blocking reliable stream (0-RTT first bytes sent in FrameStreamOpen).
func (s *RTCSession) OpenStream(target string, first []byte) (*RTCStream, error) {
	select {
	case <-s.done:
		return nil, ErrSessionClosed
	default:
	}
	ab, err := EncodeAddr(target)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	select {
	case <-s.done:
		s.mu.Unlock()
		return nil, ErrSessionClosed
	default:
	}
	id := s.nextStream
	s.nextStream += 2
	if s.nextStream == 0 {
		s.nextStream += 2
	}
	st := newRTCStream(s, id, target)
	s.streams[id] = st
	s.mu.Unlock()
	s.streamCount.Add(1)

	maxInOpen := MaxFECFrameArea - (8 + len(ab))
	if maxInOpen < 0 {
		maxInOpen = 0
	}
	inOpen := first
	var overflow []byte
	if len(first) > maxInOpen {
		inOpen = first[:maxInOpen]
		overflow = first[maxInOpen:]
	}
	openFrame := encodeFrameStreamOpen(id, ab, inOpen)
	if len(inOpen) > 0 {
		s.UpBytes.Add(uint64(len(inOpen)))
		if s.onBytes != nil {
			s.onBytes(len(inOpen), 0)
		}
	}
	s.enqueueReliableFrame(openFrame)
	if len(overflow) > 0 {
		if _, werr := st.Write(overflow); werr != nil {
			_ = st.Close()
			return nil, werr
		}
	}
	return st, nil
}

// OpenUDP opens a new multiplexed UDP association with an automatically allocated ID.
func (s *RTCSession) OpenUDP() (*RTCUDPAssoc, error) {
	return s.OpenUDPWithID(0)
}

// OpenUDPWithID opens or reuses a UDP association with an explicit 16-bit AssocID.
func (s *RTCSession) OpenUDPWithID(assocID uint16) (*RTCUDPAssoc, error) {
	select {
	case <-s.done:
		return nil, ErrSessionClosed
	default:
	}
	s.mu.Lock()
	id := assocID
	if id == 0 {
		id = s.nextUDP
		s.nextUDP++
		if s.nextUDP == 0 {
			s.nextUDP = 1
		}
	}
	if existing := s.udps[id]; existing != nil {
		s.mu.Unlock()
		return existing, nil
	}
	u := &RTCUDPAssoc{
		sess:   s,
		id:     id,
		recvCh: make(chan UDPPacket, 256),
		done:   make(chan struct{}),
	}
	s.udps[id] = u
	s.mu.Unlock()
	return u, nil
}

func (s *RTCSession) sendUDPPacket(id uint16, target string, data []byte) error {
	select {
	case <-s.done:
		return ErrSessionClosed
	default:
	}
	if len(data) > maxUDPStreamBody {
		return errors.New("gftrtc: udp packet exceeds 65507 bytes")
	}
	ab, err := EncodeAddr(target)
	if err != nil {
		return err
	}
	bodyLen := len(ab) + len(data)
	body := make([]byte, bodyLen)
	copy(body, ab)
	copy(body[len(ab):], data)

	if bodyLen > maxUDPFrags*udpFragBodyCap || bodyLen > 16*1024 {
		return s.sendUDPOnStream(id, body, len(data))
	}

	msgID := uint16(s.nextMsgID.Add(1))
	totalFrags := (bodyLen + udpFragBodyCap - 1) / udpFragBodyCap
	if totalFrags <= 0 {
		totalFrags = 1
	}
	for i := 0; i < totalFrags; i++ {
		start := i * udpFragBodyCap
		end := start + udpFragBodyCap
		if end > bodyLen {
			end = bodyLen
		}
		fr := encodeFrameUDPDatagram(id, msgID, uint8(i), uint8(totalFrags), body[start:end])
		s.enqueueUDPFrame(fr)
	}
	s.lastUDPNs.Store(time.Now().UnixNano())
	s.UpBytes.Add(uint64(len(data)))
	if s.onBytes != nil {
		s.onBytes(len(data), 0)
	}
	return nil
}

func (s *RTCSession) sendUDPOnStream(id uint16, body []byte, origDataLen int) error {
	frame := make([]byte, 4+len(body))
	binary.BigEndian.PutUint16(frame[0:2], id)
	binary.BigEndian.PutUint16(frame[2:4], uint16(len(body)))
	copy(frame[4:], body)

	s.udpFbMu.Lock()
	defer s.udpFbMu.Unlock()
	if s.udpFallback == nil {
		st, err := s.OpenStream(udpFallbackTarget, nil)
		if err != nil {
			return err
		}
		s.udpFallback = st
	}
	if _, err := s.udpFallback.Write(frame); err != nil {
		_ = s.udpFallback.Close()
		s.udpFallback = nil
		return err
	}
	s.lastUDPNs.Store(time.Now().UnixNano())
	s.UpBytes.Add(uint64(origDataLen))
	if s.onBytes != nil {
		s.onBytes(origDataLen, 0)
	}
	return nil
}

// SendUDPReply implements UDPReplySink so server outbound sends UDP replies cleanly.
func (s *RTCSession) SendUDPReply(id uint16, target string, data []byte) error {
	return s.sendUDPPacket(id, target, data)
}

// ProbeRTT sends an in-band FramePing and returns the measured RTT.
func (s *RTCSession) ProbeRTT(timeout time.Duration) (time.Duration, error) {
	select {
	case <-s.done:
		return 0, ErrSessionClosed
	default:
	}
	for {
		select {
		case <-s.pingCh:
		default:
			goto send
		}
	}
send:
	s.enqueueCtrlFrame(encodeFramePingPong(FramePing, time.Now().UnixNano()))
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case d := <-s.pingCh:
		return d, nil
	case <-t.C:
		return 0, errors.New("gftrtc: ping timeout")
	case <-s.done:
		return 0, ErrSessionClosed
	}
}

// Hop migrates this client session to a fresh local UDP socket targeting newRemotePort
// with 0ms stream interruption (server auto-migrates remoteAddr upon AEAD verification).
func (s *RTCSession) Hop(newRemotePort int) error {
	if !s.isClient || s.host == "" || newRemotePort <= 0 {
		return errors.New("gftrtc: invalid hop parameters")
	}
	raddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(s.host, strconv.Itoa(newRemotePort)))
	if err != nil {
		return err
	}
	network := "udp"
	if raddr.IP != nil && raddr.IP.To4() != nil {
		network = "udp4"
	}
	newPC, err := net.ListenUDP(network, nil)
	if err != nil {
		return err
	}
	TuneUDPSocketBuffers(newPC)
	return s.HopWithPacketConn(newPC, true, raddr, newRemotePort)
}

// HopWithPacketConn atomically switches the client session onto newPC targeting newRemoteAddr,
// retiring the previous socket after 3 seconds of grace drain.
func (s *RTCSession) HopWithPacketConn(newPC net.PacketConn, ownPC bool, newRemoteAddr net.Addr, newRemotePort int) error {
	if newPC == nil || newRemoteAddr == nil {
		return errors.New("gftrtc: nil packet conn or remote addr")
	}
	select {
	case <-s.done:
		if ownPC {
			_ = newPC.Close()
		}
		return ErrSessionClosed
	default:
	}

	s.connMu.Lock()
	oldPC := s.curConn
	oldOwn := s.curOwn
	s.curConn = newPC
	s.curOwn = ownPC
	s.curRemote = newRemoteAddr
	s.curRemoteStr = newRemoteAddr.String()
	if ownPC && oldPC != nil && oldOwn {
		s.oldConns = append(s.oldConns, oldPC)
	}
	s.connMu.Unlock()
	if newRemotePort > 0 {
		s.remotePort.Store(int32(newRemotePort))
	}

	go s.clientReadLoop(newPC, ownPC)

	// Send lightweight Ping frame immediately so even an idle session updates its NAT path at server.
	s.enqueueCtrlFrame(encodeFramePingPong(FramePing, time.Now().UnixNano()))

	if oldOwn && oldPC != nil {
		time.AfterFunc(hopOldCloseDelay, func() {
			s.connMu.Lock()
			for i, c := range s.oldConns {
				if c == oldPC {
					last := len(s.oldConns) - 1
					s.oldConns[i] = s.oldConns[last]
					s.oldConns = s.oldConns[:last]
					break
				}
			}
			s.connMu.Unlock()
			_ = oldPC.Close()
		})
	}
	return nil
}

func (s *RTCSession) clientReadLoop(pc net.PacketConn, ownPC bool) {
	for {
		bp := GetPktBuf()
		n, addr, err := pc.ReadFrom(*bp)
		if err != nil {
			PutPktBuf(bp)
			// Only tear down session if this is STILL the active socket!
			s.connMu.RLock()
			stillActive := s.curConn == pc
			s.connMu.RUnlock()
			if stillActive && ownPC {
				s.fail(err)
			}
			return
		}
		if n < RTPOverhead || !IsRTPPacket((*bp)[:n]) {
			PutPktBuf(bp)
			continue
		}
		s.enqueueInbound(inboundPkt{
			buf:  bp,
			n:    n,
			addr: addr,
			at:   time.Now(),
		})
	}
}

func (s *RTCSession) fail(err error) {
	s.closeOnce.Do(func() {
		if err != nil {
			s.errVal.Store(err)
		}
		close(s.done)

		if s.listener != nil {
			s.listener.unregisterSSRC(s.ssrc)
		}

		s.connMu.Lock()
		if s.curOwn && s.curConn != nil {
			_ = s.curConn.Close()
		}
		for _, oc := range s.oldConns {
			_ = oc.Close()
		}
		s.oldConns = nil
		s.connMu.Unlock()

		s.mu.Lock()
		for _, st := range s.streams {
			st.mu.Lock()
			if st.aborted == nil {
				st.aborted = ErrSessionClosed
			}
			st.sendQ = nil
			st.finQueued = false
			st.rcond.Broadcast()
			st.wcond.Broadcast()
			st.mu.Unlock()
		}
		s.streams = make(map[uint32]*RTCStream)
		for id, u := range s.udps {
			delete(s.udps, id)
			u.CloseLocal()
		}
		s.mu.Unlock()
	})
}

// Close closes the RTCSession and all attached streams/UDP associations.
func (s *RTCSession) Close() { s.fail(ErrSessionClosed) }

// DialOptions configures a client GFT-RTC connection.
type DialOptions struct {
	Host       string
	Port       int
	PSK        []byte
	ClientID   [8]byte
	UpMbps     int
	DownMbps   int
	ParamsJSON []byte
	Timeout    time.Duration
}

// Dial opens an OS UDP socket with 8MB buffers and connects to a GhostFrame-RTC server.
func Dial(ctx context.Context, opts DialOptions) (*RTCSession, time.Duration, error) {
	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(opts.Host, strconv.Itoa(opts.Port)))
	if err != nil {
		return nil, 0, err
	}
	network := "udp"
	if addr.IP != nil && addr.IP.To4() != nil {
		network = "udp4"
	}
	pc, err := net.ListenUDP(network, nil)
	if err != nil {
		return nil, 0, err
	}
	TuneUDPSocketBuffers(pc)
	sess, rtt, err := DialWithPacketConn(ctx, pc, true, addr, opts)
	if err != nil {
		_ = pc.Close()
		return nil, 0, err
	}
	return sess, rtt, nil
}

// DialWithPacketConn executes the 1-RTT ICE-STUN handshake over pc (with 250/400/600ms retries).
func DialWithPacketConn(ctx context.Context, pc net.PacketConn, ownPC bool, raddr net.Addr, opts DialOptions) (*RTCSession, time.Duration, error) {
	if len(opts.PSK) < 16 {
		return nil, 0, errors.New("gftrtc: psk too short")
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 6 * time.Second
	}
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Retry backoff schedule: 250ms, 400ms, 600ms, 600ms (up to 4 retries / 5 attempts total).
	retryWaits := []time.Duration{
		250 * time.Millisecond,
		400 * time.Millisecond,
		600 * time.Millisecond,
		600 * time.Millisecond,
		600 * time.Millisecond,
	}

	var rxMbps uint16
	if opts.DownMbps > 0 && opts.DownMbps <= 65535 {
		rxMbps = uint16(opts.DownMbps)
	}

	buf := make([]byte, 2048)
	defer func() { _ = pc.SetReadDeadline(time.Time{}) }()

	for attempt, wait := range retryWaits {
		reqPkt, cliPriv, txID, err := BuildClientBindingReq(opts.PSK, opts.ClientID, rxMbps, 0, time.Now())
		if err != nil {
			return nil, 0, err
		}
		t0 := time.Now()
		if _, err := pc.WriteTo(reqPkt, raddr); err != nil {
			return nil, 0, err
		}

		deadline := time.Now().Add(wait)
		if dl, has := dialCtx.Deadline(); has && dl.Before(deadline) {
			deadline = dl
		}
		for {
			if dialCtx.Err() != nil {
				return nil, 0, dialCtx.Err()
			}
			_ = pc.SetReadDeadline(deadline)
			n, _, rerr := pc.ReadFrom(buf)
			if rerr != nil {
				break
			}
			resp, keys, ok := ParseServerBindingResp(buf[:n], opts.PSK, cliPriv, txID)
			if !ok {
				continue
			}
			_ = pc.SetReadDeadline(time.Time{})
			hsRTT := time.Since(t0)
			if hsRTT <= 0 {
				hsRTT = time.Millisecond
			}
			pj := opts.ParamsJSON
			if len(resp.ParamsJSON) > 0 {
				pj = resp.ParamsJSON
			}
			sess := newRTCSession(true, resp.SessionSSRC, opts.ClientID, opts.Host, opts.Port, keys, opts.UpMbps, pj, nil)
			sess.connMu.Lock()
			sess.curConn = pc
			sess.curOwn = ownPC
			sess.curRemote = raddr
			sess.curRemoteStr = raddr.String()
			sess.connMu.Unlock()
			sess.rttNs.Store(int64(hsRTT))
			sess.startLoops()
			go sess.clientReadLoop(pc, ownPC)
			return sess, hsRTT, nil
		}
		_ = attempt
	}
	return nil, 0, errors.New("gftrtc: stun handshake timeout")
}

// ---- Server Multi-Session Sharded Listener ------------------------------------

type ssrcShard struct {
	mu sync.RWMutex
	m  map[uint32]*RTCSession
}

// RTCListener multiplexes thousands of concurrent WebRTC-mimic sessions over one UDP socket
// with O(1) 256-shard SSRC lookup, silent invalid-packet dropping, and 0ms port migration.
type RTCListener struct {
	pc         net.PacketConn
	ownPC      bool
	psk        []byte
	paramsJSON []byte
	txMbps     int
	guard      *ReplayGuard
	shards     [numSSRCShards]ssrcShard
	acceptCh   chan *RTCSession
	done       chan struct{}
	closeOnce  sync.Once
	dropped    atomic.Uint64
	nextSSRC   atomic.Uint32
}

// NewListener starts accepting GhostFrame-RTC connections on pc.
func NewListener(pc net.PacketConn, ownPC bool, psk []byte, serverTxMbps int, paramsJSON []byte) (*RTCListener, error) {
	if len(psk) < 16 {
		return nil, errors.New("gftrtc: psk too short")
	}
	pskCopy := make([]byte, len(psk))
	copy(pskCopy, psk)
	var pjCopy []byte
	if len(paramsJSON) > 0 {
		pjCopy = make([]byte, len(paramsJSON))
		copy(pjCopy, paramsJSON)
	}
	ln := &RTCListener{
		pc:         pc,
		ownPC:      ownPC,
		psk:        pskCopy,
		paramsJSON: pjCopy,
		txMbps:     serverTxMbps,
		guard:      NewReplayGuard(),
		acceptCh:   make(chan *RTCSession, 256),
		done:       make(chan struct{}),
	}
	var seed [4]byte
	_, _ = rand.Read(seed[:])
	ln.nextSSRC.Store(binary.BigEndian.Uint32(seed[:]))
	for i := range ln.shards {
		ln.shards[i].m = make(map[uint32]*RTCSession)
	}
	go ln.readLoop()
	return ln, nil
}

func (l *RTCListener) allocSSRC() uint32 {
	for {
		s := l.nextSSRC.Add(1)
		if s == 0 {
			continue
		}
		sh := &l.shards[s&0xFF]
		sh.mu.RLock()
		_, dup := sh.m[s]
		sh.mu.RUnlock()
		if !dup {
			return s
		}
	}
}

func (l *RTCListener) registerSSRC(ssrc uint32, sess *RTCSession) {
	sh := &l.shards[ssrc&0xFF]
	sh.mu.Lock()
	sh.m[ssrc] = sess
	sh.mu.Unlock()
}

func (l *RTCListener) unregisterSSRC(ssrc uint32) {
	sh := &l.shards[ssrc&0xFF]
	sh.mu.Lock()
	delete(sh.m, ssrc)
	sh.mu.Unlock()
}

func (l *RTCListener) lookupSSRC(ssrc uint32) *RTCSession {
	sh := &l.shards[ssrc&0xFF]
	sh.mu.RLock()
	sess := sh.m[ssrc]
	sh.mu.RUnlock()
	return sess
}

// Dropped returns the count of silently dropped invalid/probe/replayed packets.
func (l *RTCListener) Dropped() uint64 { return l.dropped.Load() }

// Accept blocks until the next authenticated RTCSession arrives or ctx/listener closes.
func (l *RTCListener) Accept(ctx context.Context) (*RTCSession, error) {
	select {
	case sess := <-l.acceptCh:
		return sess, nil
	case <-l.done:
		return nil, net.ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (l *RTCListener) readLoop() {
	for {
		bp := GetPktBuf()
		n, addr, err := l.pc.ReadFrom(*bp)
		if err != nil {
			PutPktBuf(bp)
			l.Close()
			return
		}
		if addr == nil || n < 20 {
			PutPktBuf(bp)
			l.dropped.Add(1)
			continue
		}
		raw := (*bp)[:n]

		// WebRTC demux rule (RFC 7983):
		// - RTP v2 packets have bits 0..1 == 10b (0x80..0xBF)
		// - STUN packets have bits 0..1 == 00b (0x00..0x3F)
		if IsRTPPacket(raw) {
			ssrc, _, ok := ParseRTPHeaderFields(raw)
			if !ok {
				PutPktBuf(bp)
				l.dropped.Add(1)
				continue
			}
			sess := l.lookupSSRC(ssrc)
			if sess == nil {
				PutPktBuf(bp)
				l.dropped.Add(1)
				continue
			}
			sess.enqueueInbound(inboundPkt{
				buf:  bp,
				n:    n,
				addr: addr,
				at:   time.Now(),
			})
			continue
		}

		// Handle STUN packets (Binding Request 0x0001 or Keepalive Indication 0x0011)
		if n >= stunHeaderLen+8 && raw[0] == 0x00 {
			msgType := binary.BigEndian.Uint16(raw[0:2])
			if msgType == stunTypeBindingInd {
				if !IsValidSTUNIndication(raw) {
					l.dropped.Add(1)
				}
				PutPktBuf(bp)
				continue
			}
			if msgType == stunTypeBindingReq {
				// Copy STUN packet and recycle buffer immediately; validate handshake synchronously or inline
				pktCopy := make([]byte, n)
				copy(pktCopy, raw)
				PutPktBuf(bp)
				l.handleSTUNHandshake(pktCopy, addr)
				continue
			}
		}

		PutPktBuf(bp)
		l.dropped.Add(1)
	}
}

func (l *RTCListener) handleSTUNHandshake(pkt []byte, addr net.Addr) {
	req, ok := ParseClientBindingReq(pkt, l.psk, l.guard, time.Now())
	if !ok {
		l.dropped.Add(1)
		return
	}

	targetMbps := l.txMbps
	if req.ClientRxMbps > 0 && (targetMbps == 0 || int(req.ClientRxMbps) < targetMbps) {
		targetMbps = int(req.ClientRxMbps)
	}

	ssrc := l.allocSSRC()
	respPkt, keys, err := BuildServerBindingResp(l.psk, req, addr, ssrc, uint16(targetMbps), 0, l.paramsJSON)
	if err != nil {
		l.dropped.Add(1)
		return
	}

	sess := newRTCSession(false, ssrc, req.ClientID, "", 0, keys, targetMbps, l.paramsJSON, l)
	sess.connMu.Lock()
	sess.curConn = l.pc
	sess.curOwn = false
	sess.curRemote = addr
	sess.curRemoteStr = addr.String()
	sess.connMu.Unlock()

	// Register SSRC BEFORE sending STUN Binding Response so fast client 0-RTT RTP packets never miss!
	l.registerSSRC(ssrc, sess)
	sess.startLoops()

	if _, werr := l.pc.WriteTo(respPkt, addr); werr != nil {
		sess.Close()
		return
	}

	select {
	case l.acceptCh <- sess:
	case <-l.done:
		sess.Close()
	default:
		sess.Close()
	}
}

// Close stops the listener and all active RTC sessions.
func (l *RTCListener) Close() error {
	l.closeOnce.Do(func() {
		close(l.done)
		if l.ownPC && l.pc != nil {
			_ = l.pc.Close()
		}
		for i := range l.shards {
			l.shards[i].mu.RLock()
			var list []*RTCSession
			for _, s := range l.shards[i].m {
				list = append(list, s)
			}
			l.shards[i].mu.RUnlock()
			for _, s := range list {
				s.Close()
			}
		}
	})
	return nil
}

// LocalAddr returns the listening UDP address.
func (l *RTCListener) LocalAddr() net.Addr {
	if l.pc == nil {
		return nil
	}
	return l.pc.LocalAddr()
}
