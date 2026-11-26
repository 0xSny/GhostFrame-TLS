package gftrtc

import (
	"context"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	mrand "math/rand/v2"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"ghostframe/internal/netbind"
)

const (
	numSSRCShards      = 256
	inboundQueueDepth  = 4096
	sessionIdleTimeout = 180 * time.Second
	keepaliveMinGap    = 18 * time.Second
	keepaliveMaxGap    = 28 * time.Second
	closedIDRingSize   = 2048
	hopOldCloseDelay   = 3 * time.Second
	hopProbeTimeout    = 600 * time.Millisecond

	rekeyByteThreshold   int64 = 8 * 1024 * 1024 * 1024 // 8 GB
	rekeyTimeThreshold         = 60 * time.Minute       // 60 minutes
	rekeyGraceDuration         = 30 * time.Second       // 30s old-key decrypt window
	rtcpMimicMinGap            = 4 * time.Second
	rtcpMimicMaxGap            = 9 * time.Second
	rekeyRoleInit        byte  = 0
	rekeyRoleResp        byte  = 1
	activeTrafficMaxIdle       = 30 * time.Second
)

func effectiveRekeyBytes() int64 {
	raw := strings.TrimSpace(os.Getenv("KSL_REKEY_MB"))
	if raw == "" {
		raw = strings.TrimSpace(os.Getenv("GFT_REKEY_MB"))
	}
	if raw != "" {
		if mb, err := strconv.ParseInt(raw, 10, 64); err == nil && mb > 0 {
			return mb * 1024 * 1024
		}
	}
	return rekeyByteThreshold
}

type dirKeyState struct {
	aead       cipher.AEAD
	iv         [4]byte
	mask       uint64
	phase      uint8
	epoch      uint32
	graceUntil time.Time
}

type trafficBucket struct {
	sec   int64
	bytes uint64
}

// StreamHandler handles an incoming reliable Kestrel-RTC stream.
type StreamHandler func(s *RTCStream, target string, first []byte)

// UDPHandler handles an incoming UDP datagram over Kestrel-RTC.
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
	MinRTTMs     int64
	LossRate     float64
	FECRecovered uint64
	PacingMbps   float64
	UpBytes      uint64
	DownBytes    uint64
	ActiveStream int
	HopCount     uint64
	RekeyCount   uint64
	KeyEpoch     uint32
	Rate30sBps   uint64
}

type inboundPkt struct {
	buf  *[]byte
	n    int
	addr net.Addr
	pc   net.PacketConn
	at   time.Time
}

const closedChunkRingSize = 4096

type closedIDSet struct {
	mu         sync.Mutex
	ring       []uint32
	pos        int
	m          map[uint32]struct{}
	baseSeq    map[uint32]uint32
	acctBytes  map[uint32]int64
	reconciled map[uint32]struct{}
	localReset map[uint32]struct{}
	cRing      []uint64
	cPos       int
	cSet       map[uint64]struct{}
}

func newClosedIDSet() *closedIDSet {
	return &closedIDSet{
		ring:       make([]uint32, closedIDRingSize),
		m:          make(map[uint32]struct{}, 256),
		baseSeq:    make(map[uint32]uint32, 256),
		acctBytes:  make(map[uint32]int64, 256),
		reconciled: make(map[uint32]struct{}, 256),
		localReset: make(map[uint32]struct{}, 256),
		cRing:      make([]uint64, closedChunkRingSize),
		cSet:       make(map[uint64]struct{}, 512),
	}
}

func (c *closedIDSet) ensureRingLocked(id uint32) {
	if _, exists := c.m[id]; !exists {
		if old := c.ring[c.pos]; old != 0 {
			delete(c.m, old)
			delete(c.baseSeq, old)
			delete(c.acctBytes, old)
			delete(c.reconciled, old)
			delete(c.localReset, old)
		}
		c.ring[c.pos] = id
		c.m[id] = struct{}{}
		c.pos = (c.pos + 1) % len(c.ring)
	}
}

func (c *closedIDSet) addWithSeqs(id uint32, base uint32, extraSeqs []uint32) {
	c.addWithAcct(id, base, extraSeqs, 0, false)
}

func (c *closedIDSet) addWithAcct(id uint32, base uint32, extraSeqs []uint32, rxAcct int64, finalReconciled bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ensureRingLocked(id)
	if prev, hasBase := c.baseSeq[id]; !hasBase || base > prev {
		c.baseSeq[id] = base
	}
	if prevAcct, hasAcct := c.acctBytes[id]; !hasAcct || rxAcct > prevAcct {
		c.acctBytes[id] = rxAcct
	}
	if finalReconciled {
		c.reconciled[id] = struct{}{}
	}
	for _, seq := range extraSeqs {
		c.insertChunkLocked((uint64(id) << 32) | uint64(seq))
	}
}

func (c *closedIDSet) markLocalReset(id uint32) {
	c.mu.Lock()
	c.ensureRingLocked(id)
	c.localReset[id] = struct{}{}
	c.mu.Unlock()
}

func (c *closedIDSet) isLocalReset(id uint32) bool {
	c.mu.Lock()
	_, ok := c.localReset[id]
	c.mu.Unlock()
	return ok
}

func (c *closedIDSet) isFinalReconciled(id uint32) bool {
	c.mu.Lock()
	_, ok := c.reconciled[id]
	c.mu.Unlock()
	return ok
}

func (c *closedIDSet) claimRSTFinal(id uint32) (prevAcct int64, seen bool, alreadyReconciled bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.reconciled[id]; ok {
		return 0, true, true
	}
	c.ensureRingLocked(id)
	prevAcct, seen = c.acctBytes[id]
	c.reconciled[id] = struct{}{}
	return prevAcct, seen, false
}

func (c *closedIDSet) insertChunkLocked(key uint64) bool {
	if _, dup := c.cSet[key]; dup {
		return false
	}
	if old := c.cRing[c.cPos]; old != 0 {
		delete(c.cSet, old)
	}
	c.cRing[c.cPos] = key
	c.cSet[key] = struct{}{}
	c.cPos = (c.cPos + 1) % len(c.cRing)
	return true
}

func (c *closedIDSet) markChunkAccounted(id, seq uint32, nBytes int) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.reconciled[id]; ok {
		return false
	}
	if base, ok := c.baseSeq[id]; ok && seq < base {
		return false
	}
	if !c.insertChunkLocked((uint64(id) << 32) | uint64(seq)) {
		return false
	}
	if nBytes > 0 {
		c.ensureRingLocked(id)
		c.acctBytes[id] += int64(nBytes)
	}
	return true
}

func (c *closedIDSet) has(id uint32) bool {
	c.mu.Lock()
	_, ok := c.m[id]
	c.mu.Unlock()
	return ok
}

// RTCSession represents a single Kestrel-RTC encrypted session supporting Zero-HOL streams,
// 0ms XOR-FEC, Smart-Brutal CC, fragmented/fallback UDP, and 0ms socket migration (port hopping).
type RTCSession struct {
	isClient bool
	legacyV3 bool
	ssrc     uint32
	clientID [8]byte
	host     string
	keys     *SessionKeys

	keyMu             sync.RWMutex
	curKeys           *SessionKeys
	txState           *dirKeyState
	rxSlots           [2]*dirKeyState
	pendingKeys       *SessionKeys
	pendingTXState    *dirKeyState
	rekeyInFlight     bool
	rekeyAwaitPeer    bool
	rekeyStartedAt    time.Time
	rekeyPendingEpoch uint32
	rekeyEphPriv      *ecdh.PrivateKey
	lastRekeyAt       time.Time
	lastRekeyTotal    uint64
	rekeyThreshBytes  int64
	rekeyCount        atomic.Uint64
	keyEpoch          atomic.Uint32
	onRekey           atomic.Pointer[func(epoch uint32)]
	rtcpSeq           atomic.Uint64

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
	hopCount     atomic.Uint64

	probeMu   sync.Mutex
	probeConn net.PacketConn
	probeHit  chan struct{}

	inboundCh chan inboundPkt
	sendKick  chan struct{}
	udpKick   chan struct{}
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

	trafficMu      sync.Mutex
	trafficBuckets [30]trafficBucket

	winMu           sync.Mutex
	winCond         *sync.Cond
	flowAcctV2      atomic.Bool
	peerSessMax     atomic.Int64
	hasPeerSessWin  atomic.Bool
	txQueuedBytes   atomic.Int64
	txStreamBytes   atomic.Int64
	rxBufferedBytes atomic.Int64
	rxConsumedBytes atomic.Int64
	lastSentSessWin atomic.Int64

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
	lastRecvNs        atomic.Int64
	lastSendNs        atomic.Int64
	lastDataTxNs      atomic.Int64
	unackedTxSinceNs  atomic.Int64
	winBlockedSinceNs atomic.Int64
	winProbeSentAtNs  atomic.Int64
	lastUDPNs         atomic.Int64
	UpBytes          atomic.Uint64
	DownBytes        atomic.Uint64

	onStream      StreamHandler
	onUDP         UDPHandler
	onUDPClose    UDPCloseHandler
	onBytes       atomic.Pointer[func(up, down int)]
	handlersReady chan struct{}
	handlersOnce  sync.Once

	done      chan struct{}
	closeOnce sync.Once
	errVal    atomic.Value
}

func newDirKeyStates(isClient bool, keys *SessionKeys) (tx, rx *dirKeyState) {
	phase := uint8(keys.Epoch & 1)
	if isClient {
		tx = &dirKeyState{aead: keys.C2SAEAD, iv: keys.C2SIV, mask: keys.C2SMask, phase: phase, epoch: keys.Epoch}
		rx = &dirKeyState{aead: keys.S2CAEAD, iv: keys.S2CIV, mask: keys.S2CMask, phase: phase, epoch: keys.Epoch}
	} else {
		tx = &dirKeyState{aead: keys.S2CAEAD, iv: keys.S2CIV, mask: keys.S2CMask, phase: phase, epoch: keys.Epoch}
		rx = &dirKeyState{aead: keys.C2SAEAD, iv: keys.C2SIV, mask: keys.C2SMask, phase: phase, epoch: keys.Epoch}
	}
	return tx, rx
}

func newRTCSession(isClient bool, ssrc uint32, clientID [8]byte, host string, remotePort int, keys *SessionKeys, targetMbps int, paramsJSON []byte, listener *RTCListener) *RTCSession {
	now := time.Now()
	txState, rxState := newDirKeyStates(isClient, keys)
	nextStream := uint32(2) // server allocates even stream IDs
	if isClient {
		nextStream = 1 // client allocates odd stream IDs
	}

	s := &RTCSession{
		isClient:         isClient,
		ssrc:             ssrc,
		clientID:         clientID,
		host:             host,
		keys:             keys,
		curKeys:          keys,
		txState:          txState,
		lastRekeyAt:      now,
		rekeyThreshBytes: effectiveRekeyBytes(),
		paramsJSON:       paramsJSON,
		startTime:        now,
		baseTS90k:        mrand.Uint32(),
		listener:         listener,
		inboundCh:        make(chan inboundPkt, inboundQueueDepth),
		sendKick:         make(chan struct{}, 1),
		udpKick:          make(chan struct{}, 1),
		ackKick:          make(chan struct{}, 1),
		pingCh:           make(chan time.Duration, 4),
		replay:           &ReplayWindow{},
		loss:             NewLossTracker(),
		fecEnc:           NewFECEncoder(),
		fecDec:           NewFECDecoder(),
		cc:               NewSmartBrutalCCForRole(targetMbps, isClient),
		inSendRR:         make(map[uint32]bool),
		streams:          make(map[uint32]*RTCStream),
		pendingStreams:   make(map[uint32]*RTCStream),
		closedIDs:        newClosedIDSet(),
		nextStream:       nextStream,
		udps:             make(map[uint16]*RTCUDPAssoc),
		nextUDP:          1,
		frags:            make(map[uint32]*udpReassemblyEntry),
		handlersReady:    make(chan struct{}),
		done:             make(chan struct{}),
	}
	s.rxSlots[rxState.phase] = rxState
	s.winCond = sync.NewCond(&s.winMu)
	s.peerSessMax.Store(DefaultSessionMaxWindow)
	effWin := EffectiveSessionMaxWindow()
	s.lastSentSessWin.Store(effWin)
	s.remotePort.Store(int32(remotePort))
	s.lastRecvNs.Store(now.UnixNano())
	s.lastSendNs.Store(now.UnixNano())
	return s
}

func (s *RTCSession) applyPeerHandshakeFlags(peerFlags uint16) {
	if peerFlags&FlagFlowAcctV2 != 0 {
		s.flowAcctV2.Store(true)
	}
	if peerFlags&FlagLowMemSession != 0 {
		s.peerSessMax.Store(LowMemSessionMaxWindow)
		s.hasPeerSessWin.Store(true)
	}
}

func (s *RTCSession) startLoops() {
	go s.inboundWorker()
	go s.sendLoop()
	go s.timerLoop()
	if IsLowMemMode() {
		s.enqueueReliableFrame(encodeFrameSessionWin(uint64(EffectiveSessionMaxWindow())))
	}
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

// SetOnBytes installs a live byte counter hook (up, down) lock-freely.
func (s *RTCSession) SetOnBytes(fn func(up, down int)) {
	if fn == nil {
		s.onBytes.Store(nil)
		return
	}
	s.onBytes.Store(&fn)
}

func (s *RTCSession) emitBytes(up, down int) {
	if p := s.onBytes.Load(); p != nil && *p != nil {
		(*p)(up, down)
	}
}

// SetOnRekey installs an optional notification callback invoked when forward-secret Rekeying advances epoch.
func (s *RTCSession) SetOnRekey(fn func(epoch uint32)) {
	if fn == nil {
		s.onRekey.Store(nil)
		return
	}
	s.onRekey.Store(&fn)
}

// HopCount returns total successful make-before-break port hops executed by this session.
func (s *RTCSession) HopCount() uint64 { return s.hopCount.Load() }

// RekeyCount returns how many zero-downtime key rotations have completed on this session.
func (s *RTCSession) RekeyCount() uint64 { return s.rekeyCount.Load() }

// KeyEpoch returns the current active transmit key epoch.
func (s *RTCSession) KeyEpoch() uint32 { return s.keyEpoch.Load() }

// LossSentLen returns the number of in-flight / pending-origin entries held by LossTracker.
func (s *RTCSession) LossSentLen() int { return s.loss.SentLen() }

// ActiveUDPCount returns active client/session UDP association count.
func (s *RTCSession) ActiveUDPCount() int {
	s.mu.Lock()
	n := len(s.udps)
	s.mu.Unlock()
	return n
}

// ResetRTTOnWake clears stale RTT / pacing history immediately after OS sleep/wake or network handoff.
func (s *RTCSession) ResetRTTOnWake() {
	s.loss.ResetRTT()
	s.cc.ResetOnWake(time.Now())
	s.rttNs.Store(0)
}

func (s *RTCSession) recordTraffic(n int, at time.Time) {
	if n <= 0 {
		return
	}
	sec := at.Unix()
	slot := int(sec % 30)
	if slot < 0 {
		slot += 30
	}
	s.trafficMu.Lock()
	if s.trafficBuckets[slot].sec != sec {
		s.trafficBuckets[slot] = trafficBucket{sec: sec, bytes: uint64(n)}
	} else {
		s.trafficBuckets[slot].bytes += uint64(n)
	}
	s.trafficMu.Unlock()
}

// Recent30sBytesPerSec returns the average up+down rate (bytes/sec) over the trailing 30s window.
func (s *RTCSession) Recent30sBytesPerSec() uint64 {
	now := time.Now()
	nowSec := now.Unix()
	cutoff := nowSec - 30
	var total uint64
	s.trafficMu.Lock()
	for i := range s.trafficBuckets {
		if s.trafficBuckets[i].sec > cutoff && s.trafficBuckets[i].sec <= nowSec {
			total += s.trafficBuckets[i].bytes
		}
	}
	s.trafficMu.Unlock()
	winSec := int64(30)
	if elapsed := int64(now.Sub(s.startTime).Seconds()); elapsed > 0 && elapsed < winSec {
		if elapsed < 5 {
			elapsed = 5
		}
		winSec = elapsed
	}
	return total / uint64(winSec)
}

func (s *RTCSession) sendBacklogLimited() bool {
	queued := s.txQueuedBytes.Load()
	if queued >= s.peerSessMax.Load() {
		return true
	}
	if s.isClient && (queued-s.txStreamBytes.Load()) >= ClientMaxSendBacklog {
		return true
	}
	return false
}

func (s *RTCSession) waitSessionSendBudget(streamDone *atomic.Bool) error {
	if !s.sendBacklogLimited() {
		return nil
	}
	s.winMu.Lock()
	defer s.winMu.Unlock()
	for s.sendBacklogLimited() {
		if streamDone != nil && streamDone.Load() {
			return ErrStreamClosed
		}
		select {
		case <-s.done:
			return ErrSessionClosed
		default:
		}
		s.winCond.Wait()
	}
	return nil
}

func (s *RTCSession) releaseQueuedTxBytes(n int) {
	if n <= 0 {
		return
	}
	for {
		cur := s.txQueuedBytes.Load()
		nxt := cur - int64(n)
		if nxt < 0 {
			nxt = 0
		}
		if s.txQueuedBytes.CompareAndSwap(cur, nxt) {
			break
		}
	}
	s.winCond.Broadcast()
}

func (s *RTCSession) onStreamBytesConsumed(n int) {
	s.accountStreamWindow(n, n)
}

func (s *RTCSession) accountStreamWindow(bufferedRelease, creditBytes int) {
	if bufferedRelease > 0 {
		for {
			cur := s.rxBufferedBytes.Load()
			nxt := cur - int64(bufferedRelease)
			if nxt < 0 {
				nxt = 0
			}
			if s.rxBufferedBytes.CompareAndSwap(cur, nxt) {
				break
			}
		}
	}
	if creditBytes <= 0 {
		return
	}
	consumed := s.rxConsumedBytes.Add(int64(creditBytes))
	newMax := consumed + EffectiveSessionMaxWindow()
	for {
		prev := s.lastSentSessWin.Load()
		if newMax <= prev || newMax-prev < sessionWinStepBytes {
			break
		}
		if s.lastSentSessWin.CompareAndSwap(prev, newMax) {
			s.enqueueReliableFrame(encodeFrameSessionWin(uint64(newMax)))
			break
		}
	}
}

// UpdateBandwidth adjusts the Smart-Brutal pacing target at runtime (0 = Auto-Probe).
func (s *RTCSession) UpdateBandwidth(targetMbps int) {
	s.cc.SetTargetMbps(targetMbps)
}

// TimeSinceLastRecv returns elapsed duration since the last valid server packet arrived.
func (s *RTCSession) TimeSinceLastRecv() time.Duration {
	if s == nil {
		return 0
	}
	ns := s.lastRecvNs.Load()
	if ns <= 0 {
		return 0
	}
	return time.Since(time.Unix(0, ns))
}

// Stats returns a live protocol telemetry snapshot.
func (s *RTCSession) Stats() SessionStats {
	srtt, minRTT, _ := s.loss.RTTMetrics(time.Now())
	return SessionStats{
		SSRC:         s.ssrc,
		Cipher:       s.keys.CipherName,
		RemotePort:   int(s.remotePort.Load()),
		RTTMs:        time.Duration(s.rttNs.Load()).Milliseconds(),
		SRTTMs:       srtt.Milliseconds(),
		MinRTTMs:     minRTT.Milliseconds(),
		LossRate:     s.loss.LossRate(),
		FECRecovered: s.fecDec.RecoveredCount(),
		PacingMbps:   s.cc.PacingMbps(),
		UpBytes:      s.UpBytes.Load(),
		DownBytes:    s.DownBytes.Load(),
		ActiveStream: int(s.streamCount.Load()),
		HopCount:     s.hopCount.Load(),
		RekeyCount:   s.rekeyCount.Load(),
		KeyEpoch:     s.keyEpoch.Load(),
		Rate30sBps:   s.Recent30sBytesPerSec(),
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
	if len(frame) <= 450 {
		select {
		case s.udpKick <- struct{}{}:
		default:
		}
	}
	s.kickSend()
}

func (s *RTCSession) removeStream(id uint32) {
	s.removeStreamWithSeqs(id, 0, nil)
}

func (s *RTCSession) removeStreamWithSeqs(id uint32, baseSeq uint32, extraSeqs []uint32) {
	s.removeStreamWithAcct(id, baseSeq, extraSeqs, 0, false)
}

func (s *RTCSession) removeStreamWithAcct(id uint32, baseSeq uint32, extraSeqs []uint32, rxAcct int64, finalReconciled bool) {
	s.closedIDs.addWithAcct(id, baseSeq, extraSeqs, rxAcct, finalReconciled)
	s.removeStreamFromMaps(id)
}

func (s *RTCSession) removeStreamFromMaps(id uint32) {
	s.mu.Lock()
	delete(s.streams, id)
	delete(s.pendingStreams, id)
	s.mu.Unlock()
}

func (s *RTCSession) pruneStreamRetransmits(streamID uint32) {
	s.closedIDs.markLocalReset(streamID)
	s.qMu.Lock()
	if len(s.retransmitQ) > 0 {
		kept := s.retransmitQ[:0]
		for _, rf := range s.retransmitQ {
			if len(rf.Bytes) >= 5 && rf.Bytes[0] == FrameStreamData && binary.BigEndian.Uint32(rf.Bytes[1:5]) == streamID {
				continue
			}
			kept = append(kept, rf)
		}
		for i := len(kept); i < len(s.retransmitQ); i++ {
			s.retransmitQ[i] = ReliableFrame{}
		}
		s.retransmitQ = kept
	}
	s.qMu.Unlock()
}

func (s *RTCSession) appendLostFrames(lostFrames []ReliableFrame) {
	if len(lostFrames) == 0 {
		return
	}
	s.qMu.Lock()
	for _, rf := range lostFrames {
		if len(rf.Bytes) >= 5 && rf.Bytes[0] == FrameStreamData {
			sid := binary.BigEndian.Uint32(rf.Bytes[1:5])
			if s.closedIDs.isLocalReset(sid) {
				continue
			}
		}
		s.retransmitQ = append(s.retransmitQ, rf)
	}
	s.qMu.Unlock()
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

func (s *RTCSession) currentTXState() *dirKeyState {
	s.keyMu.RLock()
	st := s.txState
	s.keyMu.RUnlock()
	return st
}

func (s *RTCSession) getRXState(phase uint8, now time.Time) *dirKeyState {
	s.keyMu.RLock()
	st := s.rxSlots[phase&1]
	s.keyMu.RUnlock()
	if st == nil {
		return nil
	}
	if !st.graceUntil.IsZero() && now.After(st.graceUntil) {
		return nil
	}
	return st
}

func (s *RTCSession) TriggerRekey() error {
	select {
	case <-s.done:
		return ErrSessionClosed
	default:
	}
	s.keyMu.Lock()
	if s.rekeyInFlight {
		s.keyMu.Unlock()
		return nil
	}
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		s.keyMu.Unlock()
		return err
	}
	nextEpoch := s.curKeys.Epoch + 1
	s.rekeyInFlight = true
	s.rekeyAwaitPeer = false
	s.rekeyStartedAt = time.Now()
	s.rekeyPendingEpoch = nextEpoch
	s.rekeyEphPriv = priv
	var pub32 [32]byte
	copy(pub32[:], priv.PublicKey().Bytes())
	s.keyMu.Unlock()

	s.enqueueReliableFrame(encodeFrameRekey(rekeyRoleInit, nextEpoch, pub32))
	return nil
}

func (s *RTCSession) sealAndWriteTo(pc net.PacketConn, raddr net.Addr, plain []byte, pt uint8, marker bool) (pktNum uint64, wireLen int, err error) {
	if pc == nil || raddr == nil {
		return 0, 0, ErrSessionClosed
	}
	bp := GetPktBuf()
	defer PutPktBuf(bp)
	pktNum = s.nextPktNum()
	seq := uint16(s.rtpSeq.Add(1))
	ts := s.currentTS90k()
	tx := s.currentTXState()
	sealed, serr := SealRTPPhase(*bp, tx.aead, tx.iv, tx.mask, tx.phase, s.ssrc, seq, ts, pt, marker, pktNum, plain)
	if serr != nil {
		return 0, 0, serr
	}
	wireLen = len(sealed)
	if _, err = pc.WriteTo(sealed, raddr); err == nil {
		nowNs := time.Now().UnixNano()
		s.lastSendNs.Store(nowNs)
		if s.isClient && pt != PTAudioCtrl {
			s.lastDataTxNs.Store(nowNs)
			s.unackedTxSinceNs.CompareAndSwap(0, nowNs)
		}
	}
	return pktNum, wireLen, err
}

func (s *RTCSession) sendRTCPMimicPacket() {
	s.connMu.RLock()
	pc := s.curConn
	raddr := s.curRemote
	s.connMu.RUnlock()
	if pc == nil || raddr == nil {
		return
	}
	bp := GetPktBuf()
	defer PutPktBuf(bp)
	tx := s.currentTXState()
	seq := s.rtcpSeq.Add(1)
	pkt, err := SealRTCPMimic(*bp, tx.aead, tx.iv, tx.mask, tx.phase, s.ssrc, seq, nil)
	if err != nil {
		return
	}
	if _, err := pc.WriteTo(pkt, raddr); err == nil {
		s.lastSendNs.Store(time.Now().UnixNano())
	}
}

func (s *RTCSession) sealAndWrite(plain []byte, pt uint8, marker bool) (pktNum uint64, wireLen int, err error) {
	s.connMu.RLock()
	pc := s.curConn
	raddr := s.curRemote
	s.connMu.RUnlock()
	return s.sealAndWriteTo(pc, raddr, plain, pt, marker)
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

func (s *RTCSession) popRetransmitOrPending(budget int, udpFastOnly bool) (frames [][]byte, reliable []ReliableFrame, pt uint8, hasStreamData bool, hasUDPData bool) {
	s.qMu.Lock()
	defer s.qMu.Unlock()

	used := 0
	pt = PTAudioCtrl

	// 1. Retransmissions get top priority (zero head-of-line blocking recovery)
	if !udpFastOnly {
		for len(s.retransmitQ) > 0 {
			rf := s.retransmitQ[0]
			if used+len(rf.Bytes) > budget {
				if used == 0 && len(rf.Bytes) <= MaxFrameArea {
					// Frame slightly exceeds jittered budget: let it use physical MaxFrameArea without dropping.
				} else {
					break
				}
			}
			s.retransmitQ[0] = ReliableFrame{}
			s.retransmitQ = s.retransmitQ[1:]
			frames = append(frames, rf.Bytes)
			reliable = append(reliable, rf)
			used += len(rf.Bytes)
			hasStreamData = true
			pt = PTVideoData
		}
	}

	// 2. Low-latency unreliable UDP datagrams
	for len(s.udpQ) > 0 {
		u := s.udpQ[0]
		if udpFastOnly && len(u) > 450 {
			break
		}
		if used+len(u) > budget {
			if used == 0 && len(u) <= MaxFrameArea {
			} else {
				break
			}
		}
		s.udpQ[0] = nil
		s.udpQ = s.udpQ[1:]
		frames = append(frames, u)
		used += len(u)
		hasUDPData = true
		if len(u) > 200 {
			pt = PTVideoData
		}
	}

	// 3. Control frames (Window updates, Pings, Rekey, UDPClose)
	for len(s.ctrlQ) > 0 {
		cf := s.ctrlQ[0]
		if used+len(cf) > budget {
			if used == 0 && len(cf) <= MaxFrameArea {
			} else {
				break
			}
		}
		s.ctrlQ[0] = nil
		s.ctrlQ = s.ctrlQ[1:]
		frames = append(frames, cf)
		used += len(cf)
	}

	// 4. Round-robin pull from active streams for fair zero-starvation bandwidth sharing
	if !udpFastOnly && len(s.sendRR) > 0 {
		visited := 0
		for visited < len(s.sendRR) && used < budget {
			if s.sendRRIdx >= len(s.sendRR) {
				s.sendRRIdx = 0
			}
			st := s.sendRR[s.sendRRIdx]
			allowData := s.txStreamBytes.Load() < s.peerSessMax.Load()
			fr, dataLen, needPad, more, ok := st.popSendFrame(budget-used, allowData)
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
				if dataLen > 0 {
					s.txStreamBytes.Add(int64(dataLen))
				}
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
			} else if !allowData {
				// Stream blocked on session window; continue scanning other streams for FIN-only frames.
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

	return frames, reliable, pt, hasStreamData, hasUDPData
}

func (s *RTCSession) hasPendingData() bool {
	s.qMu.Lock()
	has := len(s.retransmitQ) > 0 || len(s.udpQ) > 0 || len(s.ctrlQ) > 0 || len(s.sendRR) > 0
	s.qMu.Unlock()
	return has
}

func (s *RTCSession) hasSmallPendingUDP(maxBytes int) bool {
	s.qMu.Lock()
	has := len(s.udpQ) > 0 && len(s.udpQ[0]) <= maxBytes
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
		fastUDP := !allowed && s.hasSmallPendingUDP(450) && inFlight < s.cc.MaxInFlightBytes(srtt)
		if !allowed && !fastUDP {
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
			case <-s.udpKick:
			case <-paceTimer.C:
			}
			continue
		}

		lossRate := s.loss.LossRate()
		udpActive := now.Sub(s.LastUDPTime()) < 5*time.Second
		fecEnabled := SelectFECCountForTraffic(lossRate, udpActive) > 0
		budget := s.cc.FrameBudget(fecEnabled)

		frames, reliable, pt, hasStreamData, hasUDPData := s.popRetransmitOrPending(budget, !allowed)
		if hasStreamData {
			s.winCond.Broadcast()
		}
		if len(frames) == 0 {
			// Session flow-control backpressure or empty queues: park until SACK/Window/Kick arrives.
			select {
			case <-s.done:
				return
			case <-s.ackKick:
				s.sendSACKNow()
			case <-s.udpKick:
			case <-s.sendKick:
			}
			continue
		}

		used := 0
		maxBuf := budget
		for _, fr := range frames {
			if used+len(fr) > maxBuf {
				maxBuf = used + len(fr)
			}
			used += len(fr)
		}
		used = 0
		area := (*frameAreaPtr)[:maxBuf]
		for _, fr := range frames {
			copy(area[used:], fr)
			used += len(fr)
		}

		// Opportunistically piggyback pending SACK when room permits
		if s.replay.NeedsDelayedACK(now) || s.ackPendingCheck() {
			largest, delayUs, blocks, ok := s.replay.BuildSACK(now)
			if ok {
				sf := encodeFrameSACK(largest, delayUs, blocks)
				if used+len(sf) <= len(area) {
					copy(area[used:], sf)
					used += len(sf)
				} else {
					s.sendSACKNow()
				}
			}
		}

		// Append 8..64B random tail padding on data packets to flatten packet-length histograms.
		if hasStreamData && len(area)-used >= 11 {
			maxPad := len(area) - used - 3
			if maxPad > 64 {
				maxPad = 64
			}
			if maxPad >= 8 {
				padLen := 8
				if maxPad > 8 {
					padLen += mrand.IntN(maxPad - 7)
				}
				pf := encodeFramePadding(padLen)
				copy(area[used:], pf)
				used += len(pf)
			}
		}

		srcPlain, preParity, postParity := s.fecEnc.WrapPlaintextAdaptive((*plainPtr)[:], area[:used], lossRate, udpActive, now)
		if preParity != nil {
			marker := s.cc.ConsumeBytes(len(preParity) + RTPOverhead)
			_, _, _ = s.sealAndWrite(preParity, PTVideoData, marker)
		}

		marker := s.cc.ConsumeBytes(len(srcPlain) + RTPOverhead)
		if postParity != nil {
			marker = false // parity finishes the micro-burst
		}
		pn, wlen, err := s.sealAndWrite(srcPlain, pt, marker)
		if err == nil && (len(reliable) > 0 || hasUDPData) {
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

func randomRTCPGap() time.Duration {
	return rtcpMimicMinGap + time.Duration(mrand.Int64N(int64(rtcpMimicMaxGap-rtcpMimicMinGap)))
}

func (s *RTCSession) timerLoop() {
	t := time.NewTicker(5 * time.Millisecond)
	defer t.Stop()
	nextKeepalive := time.Now().Add(keepaliveMinGap + time.Duration(mrand.Int64N(int64(keepaliveMaxGap-keepaliveMinGap))))
	nextRTCP := time.Now().Add(randomRTCPGap())
	nextMaint := time.Now().Add(250 * time.Millisecond)

	for {
		select {
		case <-s.done:
			return
		case now := <-t.C:
			if s.replay.NeedsDelayedACK(now) {
				s.kickACK()
			}

			flushDelay := fecFlushDelay
			if now.Sub(s.LastUDPTime()) < 5*time.Second {
				flushDelay = fecGameFlushDelay
			}
			if parity, ok := s.fecEnc.FlushIfDueWithDelay(now, flushDelay); ok {
				_, _, _ = s.sealAndWrite(parity, PTVideoData, true)
			}

			lostFrames, ptoCount, lossRate, srtt, minRTT := s.loss.PollTimeouts(now)
			if len(lostFrames) > 0 {
				s.appendLostFrames(lostFrames)
				s.cc.OnFeedback(0, lossRate, srtt, minRTT, ptoCount, now)
				s.kickSend()
			}
			if ptoCount >= 6 && now.Sub(time.Unix(0, s.lastRecvNs.Load())) >= 10*time.Second {
				s.fail(errors.New("gftrtc: peer unresponsive"))
				return
			}
			// Dead-session watchdog: only trigger when outbound bytes are genuinely in-flight or queued
			// and zero valid packets arrived from peer for >= 4s.
			if s.isClient {
				if u := s.unackedTxSinceNs.Load(); u > 0 {
					if s.loss.InFlightBytes() > 0 || s.hasPendingData() {
						lastR := time.Unix(0, s.lastRecvNs.Load())
						if now.Sub(time.Unix(0, u)) >= 4*time.Second && now.Sub(lastR) >= 4*time.Second {
							s.fail(errors.New("gftrtc: dead-session watchdog (tx >4s with zero rx)"))
							return
						}
					} else {
						s.unackedTxSinceNs.Store(0)
					}
				}
			}

			// Session flow-control anti-deadlock patrol: send idempotent DATA_BLOCKED (or Ping fallback)
			// after max(2*SRTT, 250ms) and keep alive while valid RX packets are still arriving.
			if (s.sendBacklogLimited() || s.txStreamBytes.Load() >= s.peerSessMax.Load()) &&
				s.loss.InFlightBytes() == 0 && s.hasPendingData() {
				nowNs := now.UnixNano()
				s.winBlockedSinceNs.CompareAndSwap(0, nowNs)
				blockedSince := s.winBlockedSinceNs.Load()
				if blockedSince > 0 {
					blockedDur := now.Sub(time.Unix(0, blockedSince))
					curSRTT := srtt
					if curSRTT <= 0 {
						curSRTT = time.Duration(s.rttNs.Load())
					}
					if curSRTT <= 0 {
						curSRTT = 100 * time.Millisecond
					}
					probeThreshold := 2 * curSRTT
					if probeThreshold < 250*time.Millisecond {
						probeThreshold = 250 * time.Millisecond
					}
					probeGap := curSRTT
					if probeGap < 250*time.Millisecond {
						probeGap = 250 * time.Millisecond
					}
					if blockedDur >= probeThreshold {
						lastProbe := s.winProbeSentAtNs.Load()
						if lastProbe == 0 || now.Sub(time.Unix(0, lastProbe)) >= probeGap {
							s.winProbeSentAtNs.Store(nowNs)
							if s.flowAcctV2.Load() {
								s.enqueueCtrlFrame(encodeFrameDataBlocked(uint64(s.txStreamBytes.Load())))
							} else {
								s.enqueueCtrlFrame(encodeFramePingPong(FramePing, nowNs))
							}
						}
					}
					if s.isClient && blockedDur >= 5*time.Second && now.Sub(time.Unix(0, s.lastRecvNs.Load())) >= 10*time.Second {
						s.fail(errors.New("gftrtc: session flow-control window stalled"))
						return
					}
				}
			} else {
				s.winBlockedSinceNs.Store(0)
			}

			// Rekey maintenance, orphan pending stream cleanup (15s TTL), 30s grace key shredding, and RTCP-Mux mimic scheduling.
			if now.After(nextMaint) {
				nextMaint = now.Add(250 * time.Millisecond)
				s.maintainKeys(now)
				s.sweepOrphanPendingStreams(now)
			}
			if now.After(nextRTCP) {
				nextRTCP = now.Add(randomRTCPGap())
				if !s.legacyV3 {
					lastAct := s.lastSendNs.Load()
					if r := s.lastRecvNs.Load(); r > lastAct {
						lastAct = r
					}
					if now.Sub(time.Unix(0, lastAct)) < activeTrafficMaxIdle {
						s.sendRTCPMimicPacket()
					}
				}
			}

			// Server idle timeout cleanup
			if !s.isClient {
				lastR := time.Unix(0, s.lastRecvNs.Load())
				if now.Sub(lastR) > sessionIdleTimeout {
					s.fail(errors.New("gftrtc: session idle timeout"))
					return
				}
			} else if now.After(nextKeepalive) {
				if IsLowMemMode() {
					recentTraffic := s.streamCount.Load() > 0 ||
						now.Sub(time.Unix(0, s.lastDataTxNs.Load())) <= 120*time.Second ||
						now.Sub(time.Unix(0, s.lastRecvNs.Load())) <= 120*time.Second
					if recentTraffic {
						nextKeepalive = now.Add(15 * time.Second)
						if now.Sub(time.Unix(0, s.lastRecvNs.Load())) >= 15*time.Second {
							s.enqueueCtrlFrame(encodeFramePingPong(FramePing, now.UnixNano()))
						}
						continue
					}
				}
				nextKeepalive = now.Add(keepaliveMinGap + time.Duration(mrand.Int64N(int64(keepaliveMaxGap-keepaliveMinGap))))
				lastSend := time.Unix(0, s.lastSendNs.Load())
				if now.Sub(lastSend) >= keepaliveMinGap {
					_ = s.writeWirePacket(BuildSTUNIndication())
				}
			}
		}
	}
}

func (s *RTCSession) maintainKeys(now time.Time) {
	var shouldRekey bool
	totalTraffic := s.UpBytes.Load() + s.DownBytes.Load()

	s.keyMu.Lock()
	for i := range s.rxSlots {
		slot := s.rxSlots[i]
		if slot != nil && !slot.graceUntil.IsZero() && now.After(slot.graceUntil) {
			s.rxSlots[i] = nil
		}
	}
	if s.rekeyInFlight && now.Sub(s.rekeyStartedAt) > 15*time.Second {
		s.rekeyInFlight = false
		s.rekeyAwaitPeer = false
		s.rekeyEphPriv = nil
		s.pendingTXState = nil
		s.pendingKeys = nil
	}
	if !s.legacyV3 && !s.rekeyInFlight && s.isClient {
		bytesDelta := int64(0)
		if totalTraffic > s.lastRekeyTotal {
			bytesDelta = int64(totalTraffic - s.lastRekeyTotal)
		}
		if (s.rekeyThreshBytes > 0 && bytesDelta >= s.rekeyThreshBytes) || now.Sub(s.lastRekeyAt) >= rekeyTimeThreshold {
			shouldRekey = true
		}
	}
	s.keyMu.Unlock()

	if shouldRekey {
		_ = s.TriggerRekey()
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
	phase := ExtractKeyPhase(wire)

	if IsRTCPMimic(wire) {
		rx := s.getRXState(phase, pkt.at)
		if rx == nil {
			return
		}
		if _, err := OpenRTCPMimic(dst, wire, rx.aead, rx.iv, rx.mask); err != nil {
			return
		}
		s.lastRecvNs.Store(pkt.at.UnixNano())
		s.unackedTxSinceNs.Store(0)
		s.maybePromotePeerPhase(phase, pkt.at)
		if s.isClient && pkt.pc != nil {
			s.notifyProbeHit(pkt.pc)
		}
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
		return
	}

	_, maskedPN, ok := ParseRTPHeaderFields(wire)
	if !ok {
		return
	}
	rx := s.getRXState(phase, pkt.at)
	if rx == nil {
		return
	}
	pn := maskedPN ^ rx.mask
	if !s.replay.Allow(pn) {
		return
	}
	pktNum, pt, _, _, _, err := OpenRTPPhase(dst, wire, rx.aead, rx.iv, rx.mask)
	if err != nil || len(pt) < FECHeaderLen {
		return
	}

	s.lastRecvNs.Store(pkt.at.UnixNano())
	s.maybePromotePeerPhase(phase, pkt.at)
	if s.isClient && pkt.pc != nil {
		s.notifyProbeHit(pkt.pc)
	}

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

	if s.loss.InFlightBytes() == 0 {
		s.unackedTxSinceNs.Store(0)
	} else {
		s.unackedTxSinceNs.Store(pkt.at.UnixNano())
	}
}

func (s *RTCSession) maybePromotePeerPhase(phase uint8, now time.Time) {
	var fn *func(uint32)
	var newEpoch uint32
	var promoted bool

	s.keyMu.Lock()
	if s.rekeyAwaitPeer && s.pendingTXState != nil && phase == s.pendingTXState.phase {
		oldPhase := s.txState.phase
		if s.rxSlots[oldPhase] != nil {
			s.rxSlots[oldPhase].graceUntil = now.Add(rekeyGraceDuration)
		}
		s.txState = s.pendingTXState
		s.curKeys = s.pendingKeys
		s.pendingTXState = nil
		s.pendingKeys = nil
		s.rekeyAwaitPeer = false
		s.rekeyInFlight = false
		s.lastRekeyAt = now
		s.lastRekeyTotal = s.UpBytes.Load() + s.DownBytes.Load()
		newEpoch = s.curKeys.Epoch
		s.rekeyCount.Add(1)
		s.keyEpoch.Store(newEpoch)
		fn = s.onRekey.Load()
		promoted = true
	}
	s.keyMu.Unlock()

	if promoted && fn != nil && *fn != nil {
		(*fn)(newEpoch)
	}
}

func (s *RTCSession) handleInboundRekey(role byte, epoch uint32, pubBytes []byte, now time.Time) {
	if len(pubBytes) != 32 {
		return
	}
	if role == rekeyRoleInit {
		s.keyMu.Lock()
		expectedEpoch := s.curKeys.Epoch + 1
		if epoch != expectedEpoch || (s.rekeyAwaitPeer && s.rekeyPendingEpoch == epoch) {
			s.keyMu.Unlock()
			return
		}
		if s.rekeyInFlight {
			if s.isClient {
				s.keyMu.Unlock()
				return
			}
			s.rekeyInFlight = false
			s.rekeyEphPriv = nil
		}
		peerPub, err := ecdh.X25519().NewPublicKey(pubBytes)
		if err != nil {
			s.keyMu.Unlock()
			return
		}
		respPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			s.keyMu.Unlock()
			return
		}
		shared, err := respPriv.ECDH(peerPub)
		if err != nil {
			s.keyMu.Unlock()
			return
		}
		nextKeys, err := s.curKeys.RatchetKeys(shared)
		if err != nil {
			s.keyMu.Unlock()
			return
		}
		nextTX, nextRX := newDirKeyStates(s.isClient, nextKeys)
		s.rxSlots[nextRX.phase] = nextRX
		s.pendingTXState = nextTX
		s.pendingKeys = nextKeys
		s.rekeyInFlight = true
		s.rekeyAwaitPeer = true
		s.rekeyStartedAt = now
		s.rekeyPendingEpoch = epoch
		var pub32 [32]byte
		copy(pub32[:], respPriv.PublicKey().Bytes())
		s.keyMu.Unlock()

		s.enqueueReliableFrame(encodeFrameRekey(rekeyRoleResp, epoch, pub32))
		return
	}

	if role == rekeyRoleResp {
		var fn *func(uint32)
		var newEpoch uint32
		var promoted bool

		s.keyMu.Lock()
		if !s.rekeyInFlight || s.rekeyAwaitPeer || s.rekeyPendingEpoch != epoch || s.rekeyEphPriv == nil {
			s.keyMu.Unlock()
			return
		}
		peerPub, err := ecdh.X25519().NewPublicKey(pubBytes)
		if err != nil {
			s.keyMu.Unlock()
			return
		}
		shared, err := s.rekeyEphPriv.ECDH(peerPub)
		if err != nil {
			s.keyMu.Unlock()
			return
		}
		nextKeys, err := s.curKeys.RatchetKeys(shared)
		if err != nil {
			s.keyMu.Unlock()
			return
		}
		nextTX, nextRX := newDirKeyStates(s.isClient, nextKeys)
		oldPhase := s.txState.phase
		if s.rxSlots[oldPhase] != nil {
			s.rxSlots[oldPhase].graceUntil = now.Add(rekeyGraceDuration)
		}
		s.rxSlots[nextRX.phase] = nextRX
		s.txState = nextTX
		s.curKeys = nextKeys
		s.rekeyInFlight = false
		s.rekeyEphPriv = nil
		s.lastRekeyAt = now
		s.lastRekeyTotal = s.UpBytes.Load() + s.DownBytes.Load()
		newEpoch = nextKeys.Epoch
		s.rekeyCount.Add(1)
		s.keyEpoch.Store(newEpoch)
		fn = s.onRekey.Load()
		promoted = true
		s.keyMu.Unlock()

		if promoted {
			s.enqueueCtrlFrame(encodeFramePingPong(FramePing, now.UnixNano()))
			if fn != nil && *fn != nil {
				(*fn)(newEpoch)
			}
		}
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
			} else if len(payload) > 0 && s.closedIDs.markChunkAccounted(streamID, seq, len(payload)) {
				s.onStreamBytesConsumed(len(payload))
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
			var blockBuf [MaxSACKBlocks]SACKBlock
			var blocks []SACKBlock
			if cnt > 0 {
				if cnt <= MaxSACKBlocks {
					blocks = blockBuf[:cnt]
				} else {
					blocks = make([]SACKBlock, cnt)
				}
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
				s.appendLostFrames(sr.LostFrames)
				s.kickSend()
			}

		case FrameUDPDatagram:
			if off+8 > len(b) {
				return ackEliciting
			}
			ackEliciting = true
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

		case FrameRekey:
			if off+37 > len(b) {
				return ackEliciting
			}
			ackEliciting = true
			role := b[off]
			epoch := binary.BigEndian.Uint32(b[off+1 : off+5])
			pubBytes := b[off+5 : off+37]
			off += 37
			s.handleInboundRekey(role, epoch, pubBytes, now)

		case FrameSessionWin:
			if off+8 > len(b) {
				return ackEliciting
			}
			ackEliciting = true
			maxWin := int64(binary.BigEndian.Uint64(b[off : off+8]))
			off += 8
			if maxWin > 0 {
				for {
					cur := s.peerSessMax.Load()
					if maxWin <= cur {
						break
					}
					if s.peerSessMax.CompareAndSwap(cur, maxWin) {
						break
					}
				}
				s.hasPeerSessWin.Store(true)
				s.winCond.Broadcast()
				s.kickSend()
			}

		case FrameStreamRSTFinal:
			if off+12 > len(b) {
				return ackEliciting
			}
			ackEliciting = true
			streamID := binary.BigEndian.Uint32(b[off : off+4])
			finalWireBytes := binary.BigEndian.Uint64(b[off+4 : off+12])
			off += 12
			s.handleInboundRSTFinal(streamID, finalWireBytes)

		case FrameDataBlocked:
			if off+8 > len(b) {
				return ackEliciting
			}
			ackEliciting = true
			_ = binary.BigEndian.Uint64(b[off : off+8])
			off += 8
			newMax := s.rxConsumedBytes.Load() + EffectiveSessionMaxWindow()
			for {
				prev := s.lastSentSessWin.Load()
				if newMax <= prev {
					break
				}
				if s.lastSentSessWin.CompareAndSwap(prev, newMax) {
					break
				}
			}
			s.enqueueCtrlFrame(encodeFrameSessionWin(uint64(newMax)))

		default:
			return ackEliciting
		}
	}
	return ackEliciting
}

func (s *RTCSession) sweepOrphanPendingStreams(now time.Time) {
	var expired []*RTCStream
	s.mu.Lock()
	for id, st := range s.pendingStreams {
		if now.Sub(st.createdAt) > 15*time.Second {
			delete(s.pendingStreams, id)
			expired = append(expired, st)
		}
	}
	s.mu.Unlock()
	for _, st := range expired {
		st.abort(ErrStreamReset, false)
	}
}

func (s *RTCSession) handleInboundRSTFinal(streamID uint32, finalWireBytes uint64) {
	s.mu.Lock()
	st := s.streams[streamID]
	if st == nil {
		st = s.pendingStreams[streamID]
		delete(s.pendingStreams, streamID)
	}
	s.mu.Unlock()
	if st != nil {
		st.deliverRSTFinal(finalWireBytes)
		return
	}
	prevAcct, seen, alreadyReconciled := s.closedIDs.claimRSTFinal(streamID)
	if alreadyReconciled {
		return
	}
	var delta int64
	if seen {
		delta = int64(finalWireBytes) - prevAcct
	} else {
		delta = int64(finalWireBytes)
	}
	if delta > 0 {
		s.accountStreamWindow(0, int(delta))
	}
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
		s.recordTraffic(len(first), time.Now())
		s.emitBytes(0, len(first))
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
	s.recordTraffic(len(data), now)
	s.emitBytes(0, len(data))
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

	maxInOpen := maxStreamChunk - (8 + len(ab))
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
		s.recordTraffic(len(inOpen), time.Now())
		s.emitBytes(len(inOpen), 0)
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
	now := time.Now()
	s.lastUDPNs.Store(now.UnixNano())
	s.UpBytes.Add(uint64(len(data)))
	s.recordTraffic(len(data), now)
	s.emitBytes(len(data), 0)
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
	now := time.Now()
	s.lastUDPNs.Store(now.UnixNano())
	s.UpBytes.Add(uint64(origDataLen))
	s.recordTraffic(origDataLen, now)
	s.emitBytes(origDataLen, 0)
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

func (s *RTCSession) notifyProbeHit(pc net.PacketConn) {
	s.probeMu.Lock()
	if s.probeConn == pc && s.probeHit != nil {
		select {
		case s.probeHit <- struct{}{}:
		default:
		}
	}
	s.probeMu.Unlock()
}

// Hop validates and migrates this client session using Make-Before-Break to newRemotePort
// with 0ms stream interruption (server auto-migrates remoteAddr upon AEAD verification).
func (s *RTCSession) Hop(newRemotePort int) error {
	_, err := s.HopValidated(func() int { return newRemotePort }, 1, hopProbeTimeout)
	return err
}

// HopValidated probes candidate destination ports using Make-Before-Break before switching the
// active socket. If a candidate port fails to respond within probeTimeout, the original healthy
// socket remains completely uninterrupted and up to maxAttempts candidates are tried.
func (s *RTCSession) HopValidated(pickPort func() int, maxAttempts int, probeTimeout time.Duration) (int, error) {
	if !s.isClient || s.host == "" || pickPort == nil {
		return 0, errors.New("gftrtc: invalid hop parameters")
	}
	if maxAttempts <= 0 {
		maxAttempts = 4
	}
	if probeTimeout <= 0 {
		probeTimeout = hopProbeTimeout
	}

	tried := make(map[int]struct{}, maxAttempts)
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		port := pickPort()
		if maxAttempts > 1 {
			curPort := s.RemotePort()
			for retry := 0; retry < 6; retry++ {
				if _, seen := tried[port]; !seen && port != curPort {
					break
				}
				port = pickPort()
			}
		}
		if port <= 0 {
			lastErr = errors.New("gftrtc: invalid candidate hop port")
			continue
		}
		tried[port] = struct{}{}

		raddr, err := netbind.ResolveUDPAddr(context.Background(), s.host, port)
		if err != nil {
			lastErr = err
			continue
		}
		network := "udp"
		if raddr.IP != nil {
			if raddr.IP.To4() != nil {
				network = "udp4"
			} else {
				network = "udp6"
			}
		}
		candPC, err := listenClientUDPRaw(network, raddr.IP)
		if err != nil {
			lastErr = fmt.Errorf("gftrtc: listen %s for %s: %w", network, raddr.String(), err)
			continue
		}
		if perr := s.HopWithProbePC(candPC, true, raddr, port, probeTimeout); perr != nil {
			lastErr = perr
			continue
		}
		return port, nil
	}
	if lastErr == nil {
		lastErr = errors.New("gftrtc: hop probe exhausted all attempts")
	}
	return 0, lastErr
}

// HopWithProbePC executes Make-Before-Break probing on newPC targeting newRemoteAddr before
// switching curConn. Active traffic continues on curConn until an AEAD-verified response
// arrives on newPC within probeTimeout; otherwise newPC is discarded cleanly.
func (s *RTCSession) HopWithProbePC(newPC net.PacketConn, ownPC bool, newRemoteAddr net.Addr, newRemotePort int, probeTimeout time.Duration) error {
	if newPC == nil || newRemoteAddr == nil {
		return errors.New("gftrtc: nil packet conn or remote addr")
	}
	if probeTimeout <= 0 {
		probeTimeout = hopProbeTimeout
	}
	select {
	case <-s.done:
		if ownPC {
			_ = newPC.Close()
		}
		return ErrSessionClosed
	default:
	}

	hitCh := make(chan struct{}, 1)
	s.probeMu.Lock()
	s.probeConn = newPC
	s.probeHit = hitCh
	s.probeMu.Unlock()
	defer func() {
		s.probeMu.Lock()
		if s.probeConn == newPC {
			s.probeConn = nil
			s.probeHit = nil
		}
		s.probeMu.Unlock()
	}()

	go s.clientReadLoop(newPC, ownPC)

	sendProbePing := func() error {
		pingFrame := encodeFramePingPong(FramePing, time.Now().UnixNano())
		var plain [FECHeaderLen + 9]byte
		copy(plain[FECHeaderLen:], pingFrame)
		_, _, err := s.sealAndWriteTo(newPC, newRemoteAddr, plain[:], PTAudioCtrl, true)
		return err
	}
	if err := sendProbePing(); err != nil {
		if ownPC {
			_ = newPC.Close()
		}
		return err
	}

	retryAfter := probeTimeout / 3
	if retryAfter < 40*time.Millisecond {
		retryAfter = 40 * time.Millisecond
	}
	retryTimer := time.NewTimer(retryAfter)
	timeoutTimer := time.NewTimer(probeTimeout)
	defer retryTimer.Stop()
	defer timeoutTimer.Stop()

	for {
		select {
		case <-hitCh:
			s.promoteMigratedSocket(newPC, ownPC, newRemoteAddr, newRemotePort)
			return nil
		case <-retryTimer.C:
			_ = sendProbePing()
		case <-timeoutTimer.C:
			if ownPC {
				_ = newPC.Close()
			}
			return errors.New("gftrtc: hop probe timeout")
		case <-s.done:
			if ownPC {
				_ = newPC.Close()
			}
			return ErrSessionClosed
		}
	}
}

func (s *RTCSession) promoteMigratedSocket(newPC net.PacketConn, ownPC bool, newRemoteAddr net.Addr, newRemotePort int) {
	TuneUDPSocketBuffers(newPC)
	s.connMu.Lock()
	oldPC := s.curConn
	oldOwn := s.curOwn
	s.curConn = newPC
	s.curOwn = ownPC
	s.curRemote = newRemoteAddr
	s.curRemoteStr = newRemoteAddr.String()
	if ownPC && oldPC != nil && oldOwn && oldPC != newPC {
		s.oldConns = append(s.oldConns, oldPC)
	}
	s.connMu.Unlock()
	if newRemotePort > 0 {
		s.remotePort.Store(int32(newRemotePort))
	}
	s.hopCount.Add(1)
	if oldOwn && oldPC != nil && oldPC != newPC {
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

	s.promoteMigratedSocket(newPC, ownPC, newRemoteAddr, newRemotePort)
	go s.clientReadLoop(newPC, ownPC)

	// Send lightweight Ping frame immediately so even an idle session updates its NAT path at server.
	s.enqueueCtrlFrame(encodeFramePingPong(FramePing, time.Now().UnixNano()))
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
		raw := (*bp)[:n]
		if !IsRTPPacket(raw) && !IsRTCPMimic(raw) {
			PutPktBuf(bp)
			continue
		}
		s.enqueueInbound(inboundPkt{
			buf:  bp,
			n:    n,
			addr: addr,
			pc:   pc,
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
		s.winCond.Broadcast()

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

		s.qMu.Lock()
		s.retransmitQ = nil
		s.ctrlQ = nil
		s.udpQ = nil
		s.sendRR = nil
		clear(s.inSendRR)
		s.qMu.Unlock()
		s.loss.Clear()
	})
}

// Close closes the RTCSession and all attached streams/UDP associations.
func (s *RTCSession) Close() { s.fail(ErrSessionClosed) }

// DialOptions configures a client Kestrel-RTC connection.
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

func listenClientUDPRaw(network string, targetIP net.IP) (*net.UDPConn, error) {
	var lc net.ListenConfig
	if targetIP == nil || !targetIP.IsLoopback() {
		lc.Control = netbind.Control
	}
	pc, err := lc.ListenPacket(context.Background(), network, "")
	if err != nil {
		return nil, err
	}
	upc, ok := pc.(*net.UDPConn)
	if !ok {
		pc.Close()
		return nil, errors.New("gftrtc: unexpected non-UDP socket from ListenPacket")
	}
	return upc, nil
}

func listenClientUDP(network string, targetIP net.IP) (*net.UDPConn, error) {
	upc, err := listenClientUDPRaw(network, targetIP)
	if err != nil {
		return nil, err
	}
	TuneUDPSocketBuffers(upc)
	return upc, nil
}

// Dial opens an OS UDP socket with tuned buffers and connects to a Kestrel-RTC server.
func Dial(ctx context.Context, opts DialOptions) (*RTCSession, time.Duration, error) {
	addr, err := netbind.ResolveUDPAddr(ctx, opts.Host, opts.Port)
	if err != nil {
		return nil, 0, err
	}
	network := "udp"
	if addr.IP != nil {
		if addr.IP.To4() != nil {
			network = "udp4"
		} else {
			network = "udp6"
		}
	}
	pc, err := listenClientUDP(network, addr.IP)
	if err != nil {
		return nil, 0, fmt.Errorf("gftrtc: listen %s for %s: %w", network, addr.String(), err)
	}
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

	// Retry backoff schedule: 250ms, 400ms, 600ms, 600ms, 600ms, 800ms, 1000ms
	// (strictly capped by dialCtx deadline so callers get their full Timeout under high packet loss).
	retryWaits := []time.Duration{
		250 * time.Millisecond,
		400 * time.Millisecond,
		600 * time.Millisecond,
		600 * time.Millisecond,
		600 * time.Millisecond,
		800 * time.Millisecond,
		1000 * time.Millisecond,
	}

	var rxMbps uint16
	if opts.DownMbps > 0 && opts.DownMbps <= 65535 {
		rxMbps = uint16(opts.DownMbps)
	}

	buf := make([]byte, 2048)
	defer func() { _ = pc.SetReadDeadline(time.Time{}) }()

	for attempt, wait := range retryWaits {
		// Attempts 0, 1, 4 use Stealth STUN (100% RFC 5389/8489 standard attributes, zero 0xC057);
		// attempt 2 falls back to legacy v4.0-v4.2.1 0xC057+FastMAC for un-upgraded v4.x servers;
		// attempt 3 falls back to v3.4 tickets for un-upgraded v3.4 servers.
		useLegacyV4 := attempt == 2
		useLegacyV3 := attempt == 3
		var (
			reqPkt  []byte
			cliPriv *ecdh.PrivateKey
			txID    [12]byte
			err     error
		)
		if useLegacyV3 {
			reqPkt, cliPriv, txID, err = BuildClientBindingReqLegacyV3(opts.PSK, opts.ClientID, rxMbps, 0, time.Now())
		} else if useLegacyV4 {
			reqPkt, cliPriv, txID, err = BuildClientBindingReqLegacyV4(opts.PSK, opts.ClientID, rxMbps, 0, time.Now())
		} else {
			reqPkt, cliPriv, txID, err = BuildClientBindingReq(opts.PSK, opts.ClientID, rxMbps, 0, time.Now())
		}
		if err != nil {
			return nil, 0, err
		}
		t0 := time.Now()
		if _, err := pc.WriteTo(reqPkt, raddr); err != nil {
			return nil, 0, fmt.Errorf("gftrtc: write stun to %s: %w", raddr.String(), err)
		}

		deadline := time.Now().Add(wait)
		if dl, has := dialCtx.Deadline(); has && dl.Before(deadline) {
			deadline = dl
		}
		for {
			if dialCtx.Err() != nil {
				return nil, 0, fmt.Errorf("gftrtc: stun dial %s: %w", raddr.String(), dialCtx.Err())
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
			sess.legacyV3 = useLegacyV3
			sess.applyPeerHandshakeFlags(resp.Flags)
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
	return nil, 0, fmt.Errorf("gftrtc: stun handshake timeout (%s)", raddr.String())
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
	paramsJSON atomic.Pointer[[]byte]
	txMbps     int
	guard      *ReplayGuard
	shards     [numSSRCShards]ssrcShard
	acceptCh   chan *RTCSession
	done       chan struct{}
	closeOnce  sync.Once
	dropped    atomic.Uint64
	nextSSRC   atomic.Uint32
}

// SetParamsJSON atomically updates the params JSON sent in future STUN Binding Responses.
func (l *RTCListener) SetParamsJSON(paramsJSON []byte) {
	if l == nil {
		return
	}
	var pjCopy []byte
	if len(paramsJSON) > 0 {
		pjCopy = make([]byte, len(paramsJSON))
		copy(pjCopy, paramsJSON)
	}
	l.paramsJSON.Store(&pjCopy)
}

func (l *RTCListener) getParamsJSON() []byte {
	if p := l.paramsJSON.Load(); p != nil {
		return *p
	}
	return nil
}

// NewListener starts accepting Kestrel-RTC connections on pc.
func NewListener(pc net.PacketConn, ownPC bool, psk []byte, serverTxMbps int, paramsJSON []byte) (*RTCListener, error) {
	if len(psk) < 16 {
		return nil, errors.New("gftrtc: psk too short")
	}
	pskCopy := make([]byte, len(psk))
	copy(pskCopy, psk)
	ln := &RTCListener{
		pc:       pc,
		ownPC:    ownPC,
		psk:      pskCopy,
		txMbps:   serverTxMbps,
		guard:    NewReplayGuard(),
		acceptCh: make(chan *RTCSession, 256),
		done:     make(chan struct{}),
	}
	ln.SetParamsJSON(paramsJSON)
	var seed [4]byte
	_, _ = rand.Read(seed[:])
	ln.nextSSRC.Store(binary.BigEndian.Uint32(seed[:]))
	for i := range ln.shards {
		ln.shards[i].m = make(map[uint32]*RTCSession)
	}
	go ln.readLoop()
	go ln.sweepLoop()
	return ln, nil
}

func (l *RTCListener) sweepLoop() {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-l.done:
			return
		case now := <-t.C:
			l.guard.Sweep(now.Unix())
			var stale []*RTCSession
			for i := range l.shards {
				sh := &l.shards[i]
				sh.mu.RLock()
				for _, s := range sh.m {
					lastR := time.Unix(0, s.lastRecvNs.Load())
					if !s.isClient && now.Sub(lastR) > sessionIdleTimeout {
						stale = append(stale, s)
					}
				}
				sh.mu.RUnlock()
			}
			for _, s := range stale {
				s.fail(errors.New("gftrtc: listener idle sweep"))
			}
		}
	}
}

// ActiveSessions returns the number of registered active server sessions across all SSRC shards.
func (l *RTCListener) ActiveSessions() int {
	total := 0
	for i := range l.shards {
		sh := &l.shards[i]
		sh.mu.RLock()
		total += len(sh.m)
		sh.mu.RUnlock()
	}
	return total
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

		// WebRTC demux rule (RFC 7983 / RFC 5761):
		// - RTCP Receiver Report mimic has byte0 top bits 10b & PT=201 (64..112B)
		// - RTP v2 packets have bits 0..1 == 10b (0x80..0xBF)
		// - STUN packets have bits 0..1 == 00b (0x00..0x3F)
		if IsRTCPMimic(raw) {
			ssrc := binary.BigEndian.Uint32(raw[4:8])
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
				// Zero-allocation HMAC FastMAC + Fingerprint pre-screening before copying or ECDH.
				if !PreScreenClientBindingReq(raw, l.psk) {
					PutPktBuf(bp)
					l.dropped.Add(1)
					continue
				}
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
	pj := l.getParamsJSON()
	respPkt, keys, err := BuildServerBindingResp(l.psk, req, addr, ssrc, uint16(targetMbps), 0, pj)
	if err != nil {
		l.dropped.Add(1)
		return
	}

	sess := newRTCSession(false, ssrc, req.ClientID, "", 0, keys, targetMbps, pj, l)
	sess.applyPeerHandshakeFlags(req.ClientFlags)
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
