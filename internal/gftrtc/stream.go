package gftrtc

import (
	"encoding/binary"
	"errors"
	"io"
	mrand "math/rand/v2"
	"sync"
	"sync/atomic"
	"time"
)

// Inner frame type identifiers carried inside decrypted SRTP plaintext after the 6-byte FEC header.
const (
	FramePadding     byte = 0x00
	FrameStreamOpen  byte = 0x01
	FrameStreamData  byte = 0x02
	FrameStreamFIN   byte = 0x03
	FrameStreamRST   byte = 0x04
	FrameStreamWin   byte = 0x05
	FrameSACK        byte = 0x06
	FrameUDPDatagram byte = 0x07
	FrameUDPClose    byte = 0x08
	FramePing        byte = 0x09
	FramePong        byte = 0x0A
	FrameRekey       byte = 0x0B
	FrameSessionWin  byte = 0x0C
)

const (
	maxStreamChunk      = 1100 // 11B FrameStreamData hdr + 1100B = 1111B (fits inside min 1116B dynamic FrameBudget)
	streamWindowStepMin = 256 * 1024
	streamWinCheckDur   = 1500 * time.Millisecond

	// Session-level aggregate flow-control window ceilings (Tier 2/3 backpressure).
	DefaultSessionMaxWindow int64 = 32 * 1024 * 1024
	LowMemSessionMaxWindow  int64 = 8 * 1024 * 1024
	sessionWinStepBytes     int64 = 1024 * 1024

	udpFragBodyCap     = 1050
	maxUDPFrags        = 16
	maxUDPStreamBody   = 65507
	maxUDPFragPoolSlot = 256
	udpReassemblyTTL   = 2 * time.Second
	udpFallbackTarget  = "__gft_udp_stream__:1"
)

// EffectiveSessionMaxWindow returns the session aggregate memory flow-control ceiling (32MB / 8MB low-mem).
func EffectiveSessionMaxWindow() int64 {
	if IsLowMemMode() {
		return LowMemSessionMaxWindow
	}
	return DefaultSessionMaxWindow
}

var (
	ErrSessionClosed = errors.New("gftrtc: session closed")
	ErrStreamClosed  = errors.New("gftrtc: stream closed")
	ErrStreamReset   = errors.New("gftrtc: stream reset")
	ErrProtocol      = errors.New("gftrtc: protocol error")
)

// UDPPacket represents a decoded UDP payload received over GFT-RTC.
type UDPPacket struct {
	Target string
	Data   []byte
}

// UDPReplySink lets server outbound forward UDP replies back over GFT-RTC.
type UDPReplySink interface {
	SendUDPReply(id uint16, target string, data []byte) error
	SessionDone() <-chan struct{}
}

// Frame encoders (all produce compact binary payloads ready to append into packet frame area).

func encodeFramePadding(padLen int) []byte {
	b := make([]byte, 3+padLen)
	b[0] = FramePadding
	binary.BigEndian.PutUint16(b[1:3], uint16(padLen))
	fillFastRandom(b[3:])
	return b
}

func encodeFrameStreamOpen(streamID uint32, encodedAddr, first []byte) []byte {
	b := make([]byte, 8+len(encodedAddr)+len(first))
	b[0] = FrameStreamOpen
	binary.BigEndian.PutUint32(b[1:5], streamID)
	b[5] = byte(len(encodedAddr))
	copy(b[6:6+len(encodedAddr)], encodedAddr)
	off := 6 + len(encodedAddr)
	binary.BigEndian.PutUint16(b[off:off+2], uint16(len(first)))
	copy(b[off+2:], first)
	return b
}

func encodeFrameStreamData(streamID, chunkSeq uint32, data []byte) []byte {
	b := make([]byte, 11+len(data))
	b[0] = FrameStreamData
	binary.BigEndian.PutUint32(b[1:5], streamID)
	binary.BigEndian.PutUint32(b[5:9], chunkSeq)
	binary.BigEndian.PutUint16(b[9:11], uint16(len(data)))
	copy(b[11:], data)
	return b
}

func encodeFrameStreamFIN(streamID, finalSeq uint32) []byte {
	b := make([]byte, 9)
	b[0] = FrameStreamFIN
	binary.BigEndian.PutUint32(b[1:5], streamID)
	binary.BigEndian.PutUint32(b[5:9], finalSeq)
	return b
}

func encodeFrameStreamRST(streamID uint32) []byte {
	b := make([]byte, 5)
	b[0] = FrameStreamRST
	binary.BigEndian.PutUint32(b[1:5], streamID)
	return b
}

func encodeFrameStreamWin(streamID, maxAllowedSeq uint32) []byte {
	b := make([]byte, 9)
	b[0] = FrameStreamWin
	binary.BigEndian.PutUint32(b[1:5], streamID)
	binary.BigEndian.PutUint32(b[5:9], maxAllowedSeq)
	return b
}

func encodeFrameSACK(largest uint64, delayUs uint32, blocks []SACKBlock) []byte {
	if len(blocks) > MaxSACKBlocks {
		blocks = blocks[:MaxSACKBlocks]
	}
	b := make([]byte, 14+len(blocks)*4)
	b[0] = FrameSACK
	binary.BigEndian.PutUint64(b[1:9], largest)
	binary.BigEndian.PutUint32(b[9:13], delayUs)
	b[13] = byte(len(blocks))
	off := 14
	for _, blk := range blocks {
		binary.BigEndian.PutUint16(b[off:off+2], blk.Gap)
		binary.BigEndian.PutUint16(b[off+2:off+4], blk.Len)
		off += 4
	}
	return b
}

func encodeFrameUDPDatagram(assocID, msgID uint16, fragIdx, fragTotal uint8, body []byte) []byte {
	b := make([]byte, 9+len(body))
	b[0] = FrameUDPDatagram
	binary.BigEndian.PutUint16(b[1:3], assocID)
	binary.BigEndian.PutUint16(b[3:5], msgID)
	b[5] = fragIdx
	b[6] = fragTotal
	binary.BigEndian.PutUint16(b[7:9], uint16(len(body)))
	copy(b[9:], body)
	return b
}

func encodeFrameUDPClose(assocID uint16) []byte {
	var b [3]byte
	b[0] = FrameUDPClose
	binary.BigEndian.PutUint16(b[1:3], assocID)
	return b[:]
}

func encodeFramePingPong(typ byte, tsNano int64) []byte {
	var b [9]byte
	b[0] = typ
	binary.BigEndian.PutUint64(b[1:9], uint64(tsNano))
	return b[:]
}

func encodeFrameRekey(role byte, epoch uint32, pub [32]byte) []byte {
	b := make([]byte, 38)
	b[0] = FrameRekey
	b[1] = role
	binary.BigEndian.PutUint32(b[2:6], epoch)
	copy(b[6:38], pub[:])
	return b
}

func encodeFrameSessionWin(maxBytes uint64) []byte {
	b := make([]byte, 9)
	b[0] = FrameSessionWin
	binary.BigEndian.PutUint64(b[1:9], maxBytes)
	return b
}

type queuedSendChunk struct {
	seq     uint32
	frame   []byte
	dataLen int
	needPad bool
}

// RTCStream implements a Zero-HOL-Blocking bidirectional reliable stream (`gft.DataStream`)
// over GhostFrame-RTC with independent per-stream out-of-order reassembly and BDP sliding flow control.
type RTCStream struct {
	sess   *RTCSession
	id     uint32
	target string

	Up   atomic.Uint64
	Down atomic.Uint64

	mu    sync.Mutex
	rcond *sync.Cond
	wcond *sync.Cond

	// Receive / reassembly state (completely independent from other streams)
	nextReadSeq    uint32
	reorderBuf     map[uint32][]byte
	reorderBytes   int
	readyBuf       []byte
	readyOff       int
	hasFIN         bool
	finSeq         uint32
	rEOF           bool
	curWinBytes    int
	consumedBytes  int
	winConsumed    int
	lastWinCheck   int64
	lastSentMaxSeq uint32

	// Transmit / flow control state
	nextSendSeq uint32
	peerMaxSeq  uint32
	sendQ       []queuedSendChunk
	finQueued   bool
	wClosed     bool
	aborted     error
	writeDone   atomic.Bool
	closeOnce   sync.Once
	closed      atomic.Bool
}

func newRTCStream(sess *RTCSession, id uint32, target string) *RTCStream {
	initWin := EffectiveInitStreamWindow()
	initChunks := uint32(initWin / maxStreamChunk)
	if initChunks < 512 {
		initChunks = 512
	}
	st := &RTCStream{
		sess:           sess,
		id:             id,
		target:         target,
		reorderBuf:     make(map[uint32][]byte, 16),
		curWinBytes:    initWin,
		lastWinCheck:   time.Now().UnixNano(),
		lastSentMaxSeq: initChunks,
		peerMaxSeq:     initChunks,
	}
	st.rcond = sync.NewCond(&st.mu)
	st.wcond = sync.NewCond(&st.mu)
	return st
}

// RemoteTarget returns the target address string requested when opening the stream.
func (s *RTCStream) RemoteTarget() string { return s.target }

func (s *RTCStream) computeMaxAllowedSeqLocked() uint32 {
	freeBytes := s.curWinBytes - (s.reorderBytes + len(s.readyBuf) - s.readyOff)
	if freeBytes < 0 {
		freeBytes = 0
	}
	freeChunks := uint32(freeBytes / maxStreamChunk)
	if freeBytes > 0 && freeChunks < 512 {
		freeChunks = 512
	}
	return s.nextReadSeq + freeChunks
}

func (s *RTCStream) deliverChunk(seq uint32, data []byte) {
	var winFrame []byte

	s.mu.Lock()
	if seq < s.nextReadSeq {
		s.mu.Unlock()
		return
	}
	if s.aborted != nil || s.rEOF || (s.hasFIN && seq >= s.finSeq) {
		_, dup := s.reorderBuf[seq]
		s.mu.Unlock()
		if !dup && len(data) > 0 && s.sess.closedIDs.markChunkAccounted(s.id, seq) {
			s.sess.onStreamBytesConsumed(len(data))
		}
		return
	}
	if len(data) > 0 {
		added := 0
		if seq == s.nextReadSeq {
			if s.readyOff > 0 && s.readyOff == len(s.readyBuf) {
				s.readyBuf = s.readyBuf[:0]
				s.readyOff = 0
			}
			s.readyBuf = append(s.readyBuf, data...)
			added = len(data)
			s.nextReadSeq++
			for {
				nxt, ok := s.reorderBuf[s.nextReadSeq]
				if !ok {
					break
				}
				delete(s.reorderBuf, s.nextReadSeq)
				s.reorderBytes -= len(nxt)
				if s.reorderBytes < 0 {
					s.reorderBytes = 0
				}
				s.readyBuf = append(s.readyBuf, nxt...)
				s.nextReadSeq++
			}
		} else {
			if _, dup := s.reorderBuf[seq]; !dup {
				cp := make([]byte, len(data))
				copy(cp, data)
				s.reorderBuf[seq] = cp
				s.reorderBytes += len(cp)
				added = len(cp)
			}
		}
		if added > 0 {
			s.sess.rxBufferedBytes.Add(int64(added))
			s.Down.Add(uint64(added))
			s.sess.DownBytes.Add(uint64(added))
			s.sess.recordTraffic(added, time.Now())
			s.sess.emitBytes(0, added)
		}
	} else if seq == s.nextReadSeq {
		s.nextReadSeq++
	}

	if s.hasFIN && s.nextReadSeq >= s.finSeq {
		s.rEOF = true
	}

	maxSeq := s.computeMaxAllowedSeqLocked()
	if maxSeq > s.lastSentMaxSeq && maxSeq-s.lastSentMaxSeq >= 256 {
		s.lastSentMaxSeq = maxSeq
		winFrame = encodeFrameStreamWin(s.id, maxSeq)
	}
	s.rcond.Broadcast()
	s.mu.Unlock()

	if winFrame != nil {
		s.sess.enqueueReliableFrame(winFrame)
	}
}

func (s *RTCStream) collectAccountedSeqsLocked() (uint32, []uint32) {
	base := s.nextReadSeq
	if len(s.reorderBuf) == 0 {
		return base, nil
	}
	extra := make([]uint32, 0, len(s.reorderBuf))
	for seq := range s.reorderBuf {
		extra = append(extra, seq)
	}
	return base, extra
}

func (s *RTCStream) deliverFIN(finalSeq uint32) {
	var baseSeq uint32
	var extraSeqs []uint32
	s.mu.Lock()
	if !s.hasFIN {
		s.hasFIN = true
		s.finSeq = finalSeq
	}
	if s.nextReadSeq >= s.finSeq {
		s.rEOF = true
	}
	bothDone := s.rEOF && s.wClosed && len(s.sendQ) == 0 && !s.finQueued
	if bothDone {
		baseSeq, extraSeqs = s.collectAccountedSeqsLocked()
	}
	s.rcond.Broadcast()
	s.mu.Unlock()
	if bothDone {
		s.sess.removeStreamWithSeqs(s.id, baseSeq, extraSeqs)
	}
}

func (s *RTCStream) deliverRST() {
	s.abort(ErrStreamReset, false)
}

func (s *RTCStream) updatePeerMaxSeq(maxAllowed uint32) {
	s.mu.Lock()
	if maxAllowed > s.peerMaxSeq {
		s.peerMaxSeq = maxAllowed
		s.wcond.Broadcast()
	}
	s.mu.Unlock()
	s.sess.kickSend()
}

func (s *RTCStream) abort(err error, sendRST bool) {
	if err == nil {
		err = ErrStreamClosed
	}
	s.writeDone.Store(true)
	s.mu.Lock()
	if s.aborted == nil {
		s.aborted = err
	}
	discardQueued := 0
	for i := range s.sendQ {
		discardQueued += s.sendQ[i].dataLen
	}
	s.sendQ = nil
	s.finQueued = false
	baseSeq, extraSeqs := s.collectAccountedSeqsLocked()
	unread := (len(s.readyBuf) - s.readyOff) + s.reorderBytes
	s.readyBuf = nil
	s.readyOff = 0
	s.reorderBuf = nil
	s.reorderBytes = 0
	s.rcond.Broadcast()
	s.wcond.Broadcast()
	s.mu.Unlock()

	if discardQueued > 0 {
		s.sess.releaseQueuedTxBytes(discardQueued)
	}
	if unread > 0 {
		s.sess.onStreamBytesConsumed(unread)
	}
	s.sess.winCond.Broadcast()
	if sendRST {
		s.sess.enqueueReliableFrame(encodeFrameStreamRST(s.id))
	}
	if s.closed.CompareAndSwap(false, true) {
		s.sess.decStreams()
	}
	s.sess.removeStreamWithSeqs(s.id, baseSeq, extraSeqs)
}

// Read reads contiguous in-order stream bytes.
func (s *RTCStream) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	s.mu.Lock()
	for s.readyOff >= len(s.readyBuf) {
		if s.aborted != nil {
			err := s.aborted
			s.mu.Unlock()
			return 0, err
		}
		if s.rEOF {
			s.mu.Unlock()
			return 0, io.EOF
		}
		s.rcond.Wait()
	}

	n := copy(p, s.readyBuf[s.readyOff:])
	s.readyOff += n
	if s.readyOff >= len(s.readyBuf) {
		if cap(s.readyBuf) > 128*1024 && IsLowMemMode() {
			s.readyBuf = nil
		} else {
			s.readyBuf = s.readyBuf[:0]
		}
		s.readyOff = 0
	}

	s.consumedBytes += n
	s.winConsumed += n

	var winFrame []byte
	step := s.curWinBytes / 4
	if step < streamWindowStepMin {
		step = streamWindowStepMin
	}
	if step > 512*1024 {
		step = 512 * 1024
	}
	if s.consumedBytes >= step {
		s.consumedBytes = 0
		maxWin := EffectiveMaxStreamWindow()
		now := time.Now().UnixNano()
		if s.curWinBytes < maxWin && s.winConsumed >= s.curWinBytes/2 {
			if now-s.lastWinCheck <= int64(streamWinCheckDur) {
				s.curWinBytes *= 2
				if s.curWinBytes > maxWin {
					s.curWinBytes = maxWin
				}
			}
			s.winConsumed = 0
			s.lastWinCheck = now
		} else if now-s.lastWinCheck > int64(streamWinCheckDur) {
			s.winConsumed = 0
			s.lastWinCheck = now
		}
		maxSeq := s.computeMaxAllowedSeqLocked()
		if maxSeq > s.lastSentMaxSeq {
			s.lastSentMaxSeq = maxSeq
			winFrame = encodeFrameStreamWin(s.id, maxSeq)
		}
	}
	s.mu.Unlock()

	if n > 0 {
		s.sess.onStreamBytesConsumed(n)
	}
	if winFrame != nil {
		s.sess.enqueueReliableFrame(winFrame)
	}
	return n, nil
}

// Write chunks data cleanly into FrameStreamData frames subject to per-stream and session-level flow control.
func (s *RTCStream) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	total := 0
	for len(p) > 0 {
		if err := s.sess.waitSessionSendBudget(&s.writeDone); err != nil {
			return total, err
		}
		s.mu.Lock()
		for s.aborted == nil && !s.wClosed && s.nextSendSeq >= s.peerMaxSeq && len(s.sendQ) >= 256 {
			s.wcond.Wait()
		}
		if s.aborted != nil {
			err := s.aborted
			s.mu.Unlock()
			return total, err
		}
		if s.wClosed {
			s.mu.Unlock()
			return total, ErrStreamClosed
		}

		// Queue up to 64 chunks per lock acquisition to keep lock hold minimal and multi-stream fair.
		budgetChunks := int(s.peerMaxSeq - s.nextSendSeq)
		if budgetChunks <= 0 {
			for s.aborted == nil && !s.wClosed && s.nextSendSeq >= s.peerMaxSeq {
				s.wcond.Wait()
			}
			s.mu.Unlock()
			continue
		}
		if budgetChunks > 64 {
			budgetChunks = 64
		}

		writtenNow := 0
		for len(p) > 0 && budgetChunks > 0 {
			n := len(p)
			if n > maxStreamChunk {
				n = maxStreamChunk
			}
			seq := s.nextSendSeq
			s.nextSendSeq++
			frame := encodeFrameStreamData(s.id, seq, p[:n])
			s.sendQ = append(s.sendQ, queuedSendChunk{
				seq:     seq,
				frame:   frame,
				dataLen: n,
				needPad: seq < 6,
			})
			p = p[n:]
			writtenNow += n
			budgetChunks--
		}
		s.mu.Unlock()

		total += writtenNow
		if writtenNow > 0 {
			s.sess.txQueuedBytes.Add(int64(writtenNow))
			s.sess.recordTraffic(writtenNow, time.Now())
		}
		s.Up.Add(uint64(writtenNow))
		s.sess.UpBytes.Add(uint64(writtenNow))
		s.sess.emitBytes(writtenNow, 0)
		s.sess.markStreamSendable(s)
	}
	return total, nil
}

// popSendFrame pops at most one outgoing reliable frame respecting budget <= maxLen.
// When allowData is false, buffered data chunks are withheld for session flow-control while FIN stays unblocked.
func (s *RTCStream) popSendFrame(maxLen int, allowData bool) (frame []byte, dataLen int, needPad bool, more bool, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.aborted != nil {
		return nil, 0, false, false, false
	}
	if len(s.sendQ) > 0 {
		if !allowData {
			return nil, 0, false, true, false
		}
		head := s.sendQ[0]
		if len(head.frame) > maxLen {
			return nil, 0, false, true, false
		}
		s.sendQ[0] = queuedSendChunk{}
		s.sendQ = s.sendQ[1:]
		if len(s.sendQ) == 0 && cap(s.sendQ) > 128 {
			s.sendQ = nil
		}
		return head.frame, head.dataLen, head.needPad, len(s.sendQ) > 0 || s.finQueued, true
	}
	if s.finQueued {
		fin := encodeFrameStreamFIN(s.id, s.nextSendSeq)
		if len(fin) > maxLen {
			return nil, 0, false, true, false
		}
		s.finQueued = false
		return fin, 0, false, false, true
	}
	return nil, 0, false, false, false
}

// CloseWrite half-closes outgoing writes and schedules FrameStreamFIN after all pending chunks.
func (s *RTCStream) CloseWrite() error {
	s.writeDone.Store(true)
	s.sess.winCond.Broadcast()
	s.mu.Lock()
	if s.wClosed {
		s.mu.Unlock()
		return nil
	}
	s.wClosed = true
	s.finQueued = true
	s.wcond.Broadcast()
	s.mu.Unlock()
	s.sess.markStreamSendable(s)
	return nil
}

// Close cleanly shuts down the stream; sends RST only if neither EOF nor graceful CloseWrite occurred.
func (s *RTCStream) Close() error {
	var sendRST bool
	s.closeOnce.Do(func() {
		s.writeDone.Store(true)
		var unread int
		var baseSeq uint32
		var extraSeqs []uint32
		s.mu.Lock()
		hadEOF := s.rEOF
		wasWClosed := s.wClosed
		alreadyAborted := s.aborted != nil
		discardQueued := 0
		if !s.wClosed {
			s.wClosed = true
			s.finQueued = true
		}
		if !alreadyAborted {
			baseSeq, extraSeqs = s.collectAccountedSeqsLocked()
			unread = (len(s.readyBuf) - s.readyOff) + s.reorderBytes
			s.readyBuf = nil
			s.readyOff = 0
			s.reorderBuf = nil
			s.reorderBytes = 0
			if !hadEOF {
				s.rEOF = true
				if !wasWClosed {
					sendRST = true
					for i := range s.sendQ {
						discardQueued += s.sendQ[i].dataLen
					}
					s.sendQ = nil
					s.finQueued = false
				}
			}
		} else {
			baseSeq = s.nextReadSeq
		}
		s.rcond.Broadcast()
		s.wcond.Broadcast()
		s.mu.Unlock()

		if discardQueued > 0 {
			s.sess.releaseQueuedTxBytes(discardQueued)
		}
		if unread > 0 {
			s.sess.onStreamBytesConsumed(unread)
		}
		s.sess.winCond.Broadcast()
		if sendRST {
			s.sess.enqueueReliableFrame(encodeFrameStreamRST(s.id))
		} else {
			s.sess.markStreamSendable(s)
		}
		if s.closed.CompareAndSwap(false, true) {
			s.sess.decStreams()
		}
		s.sess.removeStreamWithSeqs(s.id, baseSeq, extraSeqs)
	})
	return nil
}

type udpReassemblyEntry struct {
	total     int
	received  int
	parts     [][]byte
	createdAt time.Time
}

// RTCUDPAssoc implements `gft.UDPAssociation` over GFT-RTC datagrams with <=16-frag
// reassembly and automatic dedicated reliable stream fallback for >16KB datagrams.
type RTCUDPAssoc struct {
	sess      *RTCSession
	id        uint16
	recvCh    chan UDPPacket
	done      chan struct{}
	closeOnce sync.Once
}

func (u *RTCUDPAssoc) ID() uint16             { return u.id }
func (u *RTCUDPAssoc) Recv() <-chan UDPPacket { return u.recvCh }
func (u *RTCUDPAssoc) Done() <-chan struct{}  { return u.done }

func (u *RTCUDPAssoc) push(pkt UDPPacket) {
	select {
	case <-u.done:
		return
	default:
	}
	select {
	case u.recvCh <- pkt:
	default:
	}
}

// SendTo transmits a UDP datagram (single frame, up to 16-fragment frame, or stream fallback if >16KB).
func (u *RTCUDPAssoc) SendTo(target string, data []byte) error {
	select {
	case <-u.done:
		return ErrStreamClosed
	default:
	}
	return u.sess.sendUDPPacket(u.id, target, data)
}

// CloseLocal closes local notification channels without sending FrameUDPClose to remote peer.
func (u *RTCUDPAssoc) CloseLocal() {
	u.closeOnce.Do(func() {
		close(u.done)
	})
}

// Close closes the UDP association and notifies the peer via FrameUDPClose.
func (u *RTCUDPAssoc) Close() error {
	u.closeOnce.Do(func() {
		close(u.done)
		u.sess.mu.Lock()
		delete(u.sess.udps, u.id)
		u.sess.mu.Unlock()
		u.sess.enqueueCtrlFrame(encodeFrameUDPClose(u.id))
	})
	return nil
}

// Ensure compile-time match with standard UDP packet handling
var _ = mrand.IntN
