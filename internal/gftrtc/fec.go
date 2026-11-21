package gftrtc

import (
	"encoding/binary"
	"sync"
	"sync/atomic"
	"time"
)

const (
	fecMaxK           = 10
	fecSlotDataCap    = MaxFrameArea // 1318 = [uint16(len) || frameBytes(<=1316)]
	fecDefaultRings   = 64
	fecLowMemRings    = 16
	fecFlushDelay     = 8 * time.Millisecond
	fecGameFlushDelay = 5 * time.Millisecond
)

func xorBytes64(dst, src []byte) {
	n := len(src)
	i := 0
	for ; i+8 <= n; i += 8 {
		v := binary.LittleEndian.Uint64(dst[i:]) ^ binary.LittleEndian.Uint64(src[i:])
		binary.LittleEndian.PutUint64(dst[i:], v)
	}
	for ; i < n; i++ {
		dst[i] ^= src[i]
	}
}

// SelectFECCount picks adaptive XOR group size K from live packet loss rate.
func SelectFECCount(lossRate float64) uint8 {
	switch {
	case lossRate >= 0.06:
		return 6
	case lossRate >= 0.015:
		return 10
	default:
		return 0
	}
}

// SelectFECCountForTraffic picks adaptive XOR group size K, lowering the activation threshold
// to 0.2% (K=8) during interactive UDP gaming flows so mild loss triggers immediate XOR-FEC recovery.
func SelectFECCountForTraffic(lossRate float64, interactiveUDP bool) uint8 {
	if !interactiveUDP {
		return SelectFECCount(lossRate)
	}
	switch {
	case lossRate >= 0.06:
		return 6
	case lossRate >= 0.002:
		return 8
	default:
		return 0
	}
}

// FECEncoder performs fast uint64 word-aligned XOR parity encoding for outgoing source packets.
type FECEncoder struct {
	mu      sync.Mutex
	groupID uint32
	k       uint8
	count   uint8
	maxLen  int
	firstAt time.Time
	xorBuf  [fecSlotDataCap]byte
	scratch [fecSlotDataCap]byte
	parity  [FECHeaderLen + fecSlotDataCap]byte
}

// NewFECEncoder creates an adaptive XOR-FEC encoder starting at group 1.
func NewFECEncoder() *FECEncoder {
	return &FECEncoder{groupID: 1}
}

// WrapPlaintext builds the complete plaintext `[6B FEC hdr | frameArea]` into out[:],
// and returns an optional parity plaintext (already prefixed with `[6B FEC hdr]`)
// whenever a group of K source packets completes.
// If flushParity is returned non-nil prior to encoding this packet (e.g., adaptive K switched to 0),
// both parities are returned cleanly.
func (e *FECEncoder) WrapPlaintext(dst []byte, frameArea []byte, lossRate float64, now time.Time) (srcPlain []byte, preFlushParity []byte, completedParity []byte) {
	return e.WrapPlaintextAdaptive(dst, frameArea, lossRate, false, now)
}

// WrapPlaintextAdaptive works like WrapPlaintext while allowing interactive UDP flows to use
// tighter loss thresholds for zero-stall FEC activation.
func (e *FECEncoder) WrapPlaintextAdaptive(dst []byte, frameArea []byte, lossRate float64, interactiveUDP bool, now time.Time) (srcPlain []byte, preFlushParity []byte, completedParity []byte) {
	e.mu.Lock()
	defer e.mu.Unlock()

	targetK := SelectFECCountForTraffic(lossRate, interactiveUDP)

	// If currently mid-group with an old K and FEC just disabled (or K shrunk past current count),
	// flush the pending group cleanly first so indices stay consistent.
	if e.count > 0 && (targetK == 0 || targetK <= e.count) {
		preFlushParity = e.emitParityLocked()
	}

	if targetK == 0 {
		out := dst[:FECHeaderLen+len(frameArea)]
		binary.BigEndian.PutUint32(out[0:4], 0)
		out[4] = 0
		out[5] = 0
		copy(out[FECHeaderLen:], frameArea)
		return out, preFlushParity, nil
	}

	if e.count == 0 {
		e.k = targetK
		e.maxLen = 0
		e.firstAt = now
		clear(e.xorBuf[:])
	}

	if len(frameArea) > MaxFECFrameArea {
		frameArea = frameArea[:MaxFECFrameArea]
	}

	recLen := 2 + len(frameArea)
	binary.BigEndian.PutUint16(e.scratch[0:2], uint16(len(frameArea)))
	copy(e.scratch[2:recLen], frameArea)
	// Pad trailing bytes up to recLen rounded to 8 if needed (zeros past recLen).
	if recLen > e.maxLen {
		e.maxLen = recLen
	}
	xorBytes64(e.xorBuf[:recLen], e.scratch[:recLen])

	idx := e.count
	gid := e.groupID
	k := e.k
	e.count++

	out := dst[:FECHeaderLen+len(frameArea)]
	binary.BigEndian.PutUint32(out[0:4], gid)
	out[4] = idx
	out[5] = k
	copy(out[FECHeaderLen:], frameArea)

	if e.count == e.k {
		completedParity = e.emitParityLocked()
	}
	return out, preFlushParity, completedParity
}

// FlushIfDue seals and returns a shortened parity packet if the oldest un-flushed source packet
// is at least 8ms old, avoiding tail-packet delay on interactive/sparse traffic.
func (e *FECEncoder) FlushIfDue(now time.Time) ([]byte, bool) {
	return e.FlushIfDueWithDelay(now, fecFlushDelay)
}

// FlushIfDueWithDelay seals and returns a shortened parity packet after the specified delay.
func (e *FECEncoder) FlushIfDueWithDelay(now time.Time, delay time.Duration) ([]byte, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if delay <= 0 {
		delay = fecFlushDelay
	}
	if e.count == 0 || now.Sub(e.firstAt) < delay {
		return nil, false
	}
	p := e.emitParityLocked()
	return p, true
}

func (e *FECEncoder) emitParityLocked() []byte {
	actualCount := e.count
	if actualCount == 0 {
		return nil
	}
	mlen := e.maxLen
	if mlen < 2 {
		mlen = 2
	}
	binary.BigEndian.PutUint32(e.parity[0:4], e.groupID)
	e.parity[4] = actualCount // FECIdx == FECCount signals parity & carries exact group count
	e.parity[5] = actualCount
	copy(e.parity[FECHeaderLen:FECHeaderLen+mlen], e.xorBuf[:mlen])

	res := make([]byte, FECHeaderLen+mlen)
	copy(res, e.parity[:FECHeaderLen+mlen])

	e.groupID++
	if e.groupID == 0 {
		e.groupID = 1
	}
	e.count = 0
	e.maxLen = 0
	return res
}

type fecGroupSlot struct {
	groupID   uint32
	expectedK uint8
	recvMask  uint16
	recvCount uint8
	hasParity bool
	recovered bool
	maxLen    int
	src       [fecMaxK][fecSlotDataCap]byte
	srcLen    [fecMaxK]int
	parity    [fecSlotDataCap]byte
	parityLen int
}

// FECDecoder maintains a fixed-size ring pool of XOR-FEC groups for 0ms single-loss recovery.
type FECDecoder struct {
	mu        sync.Mutex
	slots     []fecGroupSlot
	mask      uint32
	recovered atomic.Uint64
	work      [fecSlotDataCap]byte
}

// NewFECDecoder constructs an adaptive ring-buffer XOR-FEC decoder.
func NewFECDecoder() *FECDecoder {
	n := fecDefaultRings
	if IsLowMemMode() {
		n = fecLowMemRings
	}
	return &FECDecoder{
		slots: make([]fecGroupSlot, n),
		mask:  uint32(n - 1),
	}
}

// RecoveredCount returns the total number of packets reconstructed at 0ms by XOR-FEC.
func (d *FECDecoder) RecoveredCount() uint64 { return d.recovered.Load() }

// Process feeds one decrypted source or parity packet into the FEC ring pool.
// If a missing source packet from this group is immediately reconstructed, it returns
// the recovered frameArea slice (copied safely for caller processing) and ok=true.
func (d *FECDecoder) Process(groupID uint32, fecIdx, fecCount uint8, body []byte) (recoveredFrameArea []byte, ok bool) {
	if fecCount == 0 || fecCount > fecMaxK || groupID == 0 || fecIdx > fecCount {
		return nil, false
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	slot := &d.slots[groupID&d.mask]
	if slot.groupID != groupID {
		slot.groupID = groupID
		slot.expectedK = fecCount
		slot.recvMask = 0
		slot.recvCount = 0
		slot.hasParity = false
		slot.recovered = false
		slot.maxLen = 0
		slot.parityLen = 0
	}

	if fecIdx == fecCount {
		// Parity packet: fecCount carries the authoritative actual packet count in this group.
		slot.expectedK = fecCount
		if len(body) < 2 || len(body) > fecSlotDataCap {
			return nil, false
		}
		if !slot.hasParity {
			copy(slot.parity[:len(body)], body)
			slot.parityLen = len(body)
			slot.hasParity = true
			if len(body) > slot.maxLen {
				slot.maxLen = len(body)
			}
		}
	} else {
		// Source packet [0 .. fecCount-1]
		if len(body) > MaxFECFrameArea {
			return nil, false
		}
		bit := uint16(1) << fecIdx
		if slot.recvMask&bit == 0 {
			recLen := 2 + len(body)
			binary.BigEndian.PutUint16(slot.src[fecIdx][0:2], uint16(len(body)))
			copy(slot.src[fecIdx][2:recLen], body)
			slot.srcLen[fecIdx] = recLen
			slot.recvMask |= bit
			slot.recvCount++
			if recLen > slot.maxLen {
				slot.maxLen = recLen
			}
		}
		// Keep expectedK updated if parity hasn't narrowed it yet
		if !slot.hasParity && fecCount > slot.expectedK {
			slot.expectedK = fecCount
		}
	}

	if !slot.hasParity || slot.recovered || slot.expectedK == 0 {
		return nil, false
	}

	// Count received source packets strictly below expectedK
	k := int(slot.expectedK)
	present := 0
	missingIdx := -1
	for i := 0; i < k; i++ {
		if slot.recvMask&(uint16(1)<<i) != 0 {
			present++
		} else {
			missingIdx = i
		}
	}
	if present != k-1 || missingIdx < 0 {
		return nil, false
	}

	mlen := slot.parityLen
	if mlen < 2 || mlen > fecSlotDataCap {
		return nil, false
	}
	copy(d.work[:mlen], slot.parity[:mlen])
	for i := 0; i < k; i++ {
		if i == missingIdx {
			continue
		}
		slen := slot.srcLen[i]
		if slen > mlen {
			slen = mlen
		}
		xorBytes64(d.work[:slen], slot.src[i][:slen])
	}

	origLen := int(binary.BigEndian.Uint16(d.work[0:2]))
	if origLen > MaxFECFrameArea || 2+origLen > fecSlotDataCap {
		return nil, false
	}
	slot.recovered = true
	d.recovered.Add(1)

	out := make([]byte, origLen)
	copy(out, d.work[2:2+origLen])
	return out, true
}
