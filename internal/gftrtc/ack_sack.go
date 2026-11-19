package gftrtc

import (
	"sync"
	"time"
)

const (
	replayWindowBits  = 8192
	replayWindowWords = replayWindowBits / 64 // 128
	MaxSACKBlocks     = 32
	ackDelayMax       = 6 * time.Millisecond
	lossWinBuckets    = 20
	lossBucketDur     = 100 * time.Millisecond // 20 * 100ms = 2s sliding loss window
	minRTTWindowDur   = 10 * time.Second       // 3 buckets = 30s sliding minRTT window
)

// SACKBlock represents a contiguous run of acknowledged packets relative to the previous cursor.
type SACKBlock struct {
	Gap uint16
	Len uint16
}

// ReplayWindow provides 8192-packet anti-replay validation and 32-interval SACK synthesis.
type ReplayWindow struct {
	mu            sync.Mutex
	init          bool
	largest       uint64
	largestTime   time.Time
	words         [replayWindowWords]uint64
	unackedCount  int
	oldestUnacked time.Time
	ackPending    bool
}

// Allow verifies pktNum against the 8192-packet sliding anti-replay window WITHOUT mutating state.
// State is only updated by Commit after AEAD verification succeeds.
func (w *ReplayWindow) Allow(pktNum uint64) bool {
	if pktNum == 0 {
		return false
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.init {
		return true
	}
	if pktNum > w.largest {
		return true
	}
	delta := w.largest - pktNum
	if delta >= replayWindowBits {
		return false
	}
	return (w.words[delta>>6] & (uint64(1) << (delta & 63))) == 0
}

// Commit marks pktNum as authenticated & received and returns whether an immediate SACK should be sent.
func (w *ReplayWindow) Commit(pktNum uint64, ackEliciting bool, now time.Time) (immediateSACK bool) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if !w.init {
		w.init = true
		w.largest = pktNum
		w.largestTime = now
		w.words[0] = 1
	} else if pktNum > w.largest {
		shift := pktNum - w.largest
		w.shiftLeftLocked(shift)
		w.largest = pktNum
		w.largestTime = now
		w.words[0] |= 1
	} else {
		delta := w.largest - pktNum
		if delta < replayWindowBits {
			w.words[delta>>6] |= uint64(1) << (delta & 63)
		}
	}

	if ackEliciting {
		if !w.ackPending {
			w.oldestUnacked = now
		}
		w.ackPending = true
		w.unackedCount++
		if w.unackedCount >= 2 {
			return true
		}
	}
	return false
}

func (w *ReplayWindow) shiftLeftLocked(shift uint64) {
	if shift >= replayWindowBits {
		clear(w.words[:])
		return
	}
	wordShift := int(shift >> 6)
	bitShift := uint(shift & 63)
	for i := replayWindowWords - 1; i >= 0; i-- {
		src := i - wordShift
		var val uint64
		if src >= 0 {
			val = w.words[src] << bitShift
			if bitShift > 0 && src-1 >= 0 {
				val |= w.words[src-1] >> (64 - bitShift)
			}
		}
		w.words[i] = val
	}
}

// NeedsDelayedACK reports whether >= 6ms elapsed since oldest unacked ack-eliciting packet.
func (w *ReplayWindow) NeedsDelayedACK(now time.Time) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.ackPending || !w.init {
		return false
	}
	return w.unackedCount >= 2 || now.Sub(w.oldestUnacked) >= ackDelayMax
}

// BuildSACK builds up to 32 (Gap, Len) blocks describing received packets in the window.
func (w *ReplayWindow) BuildSACK(now time.Time) (largest uint64, ackDelayUs uint32, blocks []SACKBlock, ok bool) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if !w.init {
		return 0, 0, nil, false
	}
	w.ackPending = false
	w.unackedCount = 0
	largest = w.largest
	if !w.largestTime.IsZero() && now.After(w.largestTime) {
		us := now.Sub(w.largestTime).Microseconds()
		if us > 0 && us < 0x7FFFFFFF {
			ackDelayUs = uint32(us)
		}
	}

	blocks = make([]SACKBlock, 0, 8)
	limit := replayWindowBits
	if largest < uint64(limit) {
		limit = int(largest)
	}

	gap := 0
	inBlock := false
	blockLen := 0
	// Walk from delta=0 (largest) downward, skipping zero words when searching gaps.
	for d := 0; d < limit; d++ {
		if !inBlock && (d&63) == 0 && d+64 <= limit && w.words[d>>6] == 0 {
			gap += 64
			d += 63
			continue
		}
		set := (w.words[d>>6] & (uint64(1) << (d & 63))) != 0
		if set {
			if !inBlock {
				inBlock = true
				blockLen = 1
			} else {
				blockLen++
			}
		} else {
			if inBlock {
				if gap > 65535 {
					break
				}
				blocks = append(blocks, SACKBlock{Gap: uint16(gap), Len: uint16(blockLen)})
				if len(blocks) >= MaxSACKBlocks {
					inBlock = false
					break
				}
				inBlock = false
				gap = 1
				blockLen = 0
			} else {
				gap++
			}
		}
	}
	if inBlock && len(blocks) < MaxSACKBlocks && gap <= 65535 {
		blocks = append(blocks, SACKBlock{Gap: uint16(gap), Len: uint16(blockLen)})
	}
	return largest, ackDelayUs, blocks, true
}

// ReliableFrame holds serialized reliable payload bytes tied to an in-flight packet for RACK retransmission.
type ReliableFrame struct {
	Bytes    []byte
	OriginPN uint64
}

type inFlightPkt struct {
	pktNum      uint64
	sentAt      time.Time
	retiredAt   time.Time
	wireBytes   int
	frames      []ReliableFrame
	retired     bool
	pendingOrig int
}

type lossBucket struct {
	secIdx int64
	acked  uint32
	lost   uint32
}

type minRTTBucket struct {
	period int64
	minVal time.Duration
}

// LossTracker tracks sent packets, smoothed/min RTT, RACK + packet-threshold loss detection,
// PTO timeouts, and 2s sliding packet loss statistics.
type LossTracker struct {
	mu             sync.Mutex
	sent           map[uint64]*inFlightPkt
	inFlightBytes  int
	largestSent    uint64
	largestAcked   uint64
	largestAckSent time.Time
	hasAck         bool

	srtt          time.Duration
	rttVar        time.Duration
	minRTTBuckets [3]minRTTBucket
	ptoBackoff    int
	lastPTOAt     time.Time

	lossWin        [lossWinBuckets]lossBucket
	cachedLossRate float64
	totalAckedPkts uint64
	totalLostPkts  uint64
}

// NewLossTracker creates a sender-side packet/RTT/loss tracker.
// Uses RFC 9002 kInitialRtt (333ms) before the first RTT sample arrives so high-latency WAN
// links never suffer spurious RTO cascades prior to receiving the first SACK.
func NewLossTracker() *LossTracker {
	return &LossTracker{
		sent:   make(map[uint64]*inFlightPkt, 256),
		srtt:   333 * time.Millisecond,
		rttVar: 166 * time.Millisecond,
	}
}

func (lt *LossTracker) recordOutcomeLocked(now time.Time, ackedAdd, lostAdd uint32) {
	bIdx := now.UnixNano() / int64(lossBucketDur)
	slot := &lt.lossWin[bIdx%lossWinBuckets]
	if slot.secIdx != bIdx {
		slot.secIdx = bIdx
		slot.acked = 0
		slot.lost = 0
	}
	slot.acked += ackedAdd
	slot.lost += lostAdd
	lt.totalAckedPkts += uint64(ackedAdd)
	lt.totalLostPkts += uint64(lostAdd)

	cutoff := bIdx - lossWinBuckets + 1
	var sumAck, sumLost uint64
	for i := range lt.lossWin {
		if lt.lossWin[i].secIdx >= cutoff {
			sumAck += uint64(lt.lossWin[i].acked)
			sumLost += uint64(lt.lossWin[i].lost)
		}
	}
	tot := sumAck + sumLost
	if tot >= 4 {
		lt.cachedLossRate = float64(sumLost) / float64(tot)
	}
}

func (lt *LossTracker) updateMinRTTLocked(sample time.Duration, now time.Time) time.Duration {
	if sample <= 0 {
		sample = time.Millisecond
	}
	p := now.UnixNano() / int64(minRTTWindowDur)
	slot := &lt.minRTTBuckets[p%3]
	if slot.period != p || slot.minVal == 0 || sample < slot.minVal {
		slot.period = p
		slot.minVal = sample
	}
	minR := time.Duration(0)
	cutoff := p - 2
	for i := range lt.minRTTBuckets {
		if lt.minRTTBuckets[i].period >= cutoff && lt.minRTTBuckets[i].minVal > 0 {
			if minR == 0 || lt.minRTTBuckets[i].minVal < minR {
				minR = lt.minRTTBuckets[i].minVal
			}
		}
	}
	return minR
}

func (lt *LossTracker) updateRTTLocked(sample time.Duration, now time.Time) {
	if sample <= 0 {
		sample = time.Millisecond
	}
	_ = lt.updateMinRTTLocked(sample, now)
	if !lt.hasAck {
		lt.hasAck = true
		lt.srtt = sample
		lt.rttVar = sample / 2
		return
	}
	diff := lt.srtt - sample
	if diff < 0 {
		diff = -diff
	}
	lt.rttVar = (3*lt.rttVar + diff) / 4
	lt.srtt = (7*lt.srtt + sample) / 8
	if lt.srtt < time.Millisecond {
		lt.srtt = time.Millisecond
	}
}

// OnPacketSent registers an outgoing packet containing zero or more reliable frames.
func (lt *LossTracker) OnPacketSent(pktNum uint64, wireBytes int, frames []ReliableFrame, now time.Time) {
	lt.mu.Lock()
	defer lt.mu.Unlock()
	if pktNum > lt.largestSent {
		lt.largestSent = pktNum
	}
	lt.sent[pktNum] = &inFlightPkt{
		pktNum:    pktNum,
		sentAt:    now,
		wireBytes: wireBytes,
		frames:    frames,
	}
	lt.inFlightBytes += wireBytes
}

// InFlightBytes returns current unacknowledged bytes on the wire.
func (lt *LossTracker) InFlightBytes() int {
	lt.mu.Lock()
	defer lt.mu.Unlock()
	return lt.inFlightBytes
}

// Clear releases all tracked in-flight packet references when a session shuts down.
func (lt *LossTracker) Clear() {
	lt.mu.Lock()
	clear(lt.sent)
	lt.inFlightBytes = 0
	lt.mu.Unlock()
}

// LossRate returns the smoothed 2-second packet loss rate in [0, 1].
func (lt *LossTracker) LossRate() float64 {
	lt.mu.Lock()
	defer lt.mu.Unlock()
	return lt.cachedLossRate
}

// RTTMetrics returns (srtt, minRTT, hasAck).
func (lt *LossTracker) RTTMetrics(now time.Time) (srtt, minRTT time.Duration, has bool) {
	lt.mu.Lock()
	defer lt.mu.Unlock()
	if !lt.hasAck {
		return lt.srtt, lt.srtt, false
	}
	p := now.UnixNano() / int64(minRTTWindowDur)
	cutoff := p - 2
	for i := range lt.minRTTBuckets {
		if lt.minRTTBuckets[i].period >= cutoff && lt.minRTTBuckets[i].minVal > 0 {
			if minRTT == 0 || lt.minRTTBuckets[i].minVal < minRTT {
				minRTT = lt.minRTTBuckets[i].minVal
			}
		}
	}
	if minRTT == 0 {
		minRTT = lt.srtt
	}
	return lt.srtt, minRTT, true
}

// Stats returns cumulative acked and lost packet counts along with live loss rate.
func (lt *LossTracker) Stats() (acked, lost uint64, lossRate float64) {
	lt.mu.Lock()
	defer lt.mu.Unlock()
	return lt.totalAckedPkts, lt.totalLostPkts, lt.cachedLossRate
}

// SACKResult summarizes acknowledgements, RTT updates, and newly declared lost frames.
type SACKResult struct {
	AckedBytes int
	AckedPkts  int
	HasRTT     bool
	RTTSample  time.Duration
	SRTT       time.Duration
	MinRTT     time.Duration
	LossRate   float64
	LostFrames []ReliableFrame
}

// OnSACK processes a received SACK frame, updating RTT, freeing acked packets, and detecting RACK/reordering losses.
func (lt *LossTracker) OnSACK(largestAcked uint64, ackDelayUs uint32, blocks []SACKBlock, now time.Time) SACKResult {
	lt.mu.Lock()
	defer lt.mu.Unlock()

	var res SACKResult
	lt.ptoBackoff = 0

	if largestAcked > lt.largestAcked {
		lt.largestAcked = largestAcked
		if p, ok := lt.sent[largestAcked]; ok && !p.retired {
			raw := now.Sub(p.sentAt)
			delay := time.Duration(ackDelayUs) * time.Microsecond
			if delay > 0 && delay < raw && delay < 50*time.Millisecond {
				raw -= delay
			}
			if raw < time.Millisecond {
				raw = time.Millisecond
			}
			lt.updateRTTLocked(raw, now)
			lt.largestAckSent = p.sentAt
			res.HasRTT = true
			res.RTTSample = raw
		}
	}

	ackOne := func(pn uint64) {
		p, ok := lt.sent[pn]
		if !ok {
			return
		}
		delete(lt.sent, pn)
		for _, f := range p.frames {
			if f.OriginPN != 0 && f.OriginPN != pn {
				if orig, exists := lt.sent[f.OriginPN]; exists && orig.retired {
					orig.pendingOrig--
					if orig.pendingOrig <= 0 {
						delete(lt.sent, f.OriginPN)
					}
				}
			}
		}
		if !p.retired {
			lt.inFlightBytes -= p.wireBytes
			if lt.inFlightBytes < 0 {
				lt.inFlightBytes = 0
			}
		}
		res.AckedBytes += p.wireBytes
		res.AckedPkts++
	}

	if len(blocks) == 0 {
		ackOne(largestAcked)
	} else {
		cursor := int64(largestAcked) + 1
		for _, blk := range blocks {
			end := cursor - 1 - int64(blk.Gap)
			if end < 1 {
				break
			}
			start := end - int64(blk.Len) + 1
			if start < 1 {
				start = 1
			}
			for pn := uint64(end); pn >= uint64(start); pn-- {
				ackOne(pn)
				if pn == 1 {
					break
				}
			}
			cursor = start
		}
	}

	// Detect RACK time threshold & >=3 packet threshold losses among remaining in-flight packets.
	minRTT := lt.srtt
	pPeriod := now.UnixNano() / int64(minRTTWindowDur)
	cutoff := pPeriod - 2
	for i := range lt.minRTTBuckets {
		if lt.minRTTBuckets[i].period >= cutoff && lt.minRTTBuckets[i].minVal > 0 {
			if lt.minRTTBuckets[i].minVal < minRTT {
				minRTT = lt.minRTTBuckets[i].minVal
			}
		}
	}
	rackThresh := (lt.srtt * 5) / 4
	if minAlt := minRTT + 15*time.Millisecond; minAlt > rackThresh {
		rackThresh = minAlt
	}

	originAgeLimit := lt.srtt
	if originAgeLimit < 500*time.Millisecond {
		originAgeLimit = 500 * time.Millisecond
	}
	originAgeLimit *= 2

	var lostCount uint32
	for pn, p := range lt.sent {
		if p.retired {
			if now.Sub(p.retiredAt) >= originAgeLimit {
				delete(lt.sent, pn)
			}
			continue
		}
		if pn >= lt.largestAcked {
			continue
		}
		pktThreshold := pn+8 <= lt.largestAcked
		timeThreshold := now.Sub(p.sentAt) >= rackThresh
		if pktThreshold || timeThreshold {
			delete(lt.sent, pn)
			lt.inFlightBytes -= p.wireBytes
			if lt.inFlightBytes < 0 {
				lt.inFlightBytes = 0
			}
			lostCount++
			for _, f := range p.frames {
				if f.OriginPN == 0 {
					f.OriginPN = pn
				}
				res.LostFrames = append(res.LostFrames, f)
			}
		}
	}

	lt.recordOutcomeLocked(now, uint32(res.AckedPkts), lostCount)
	res.SRTT = lt.srtt
	res.MinRTT = minRTT
	res.LossRate = lt.cachedLossRate
	return res
}

// PollTimeouts inspects in-flight packets for RACK/RTO expiration and returns reliable frames
// requiring immediate retransmission under fresh PacketNumbers.
func (lt *LossTracker) PollTimeouts(now time.Time) (lostFrames []ReliableFrame, ptoCount int, lossRate float64, srtt, minRTT time.Duration) {
	lt.mu.Lock()
	defer lt.mu.Unlock()

	minRTT = lt.srtt
	pPeriod := now.UnixNano() / int64(minRTTWindowDur)
	cutoff := pPeriod - 2
	for i := range lt.minRTTBuckets {
		if lt.minRTTBuckets[i].period >= cutoff && lt.minRTTBuckets[i].minVal > 0 {
			if lt.minRTTBuckets[i].minVal < minRTT {
				minRTT = lt.minRTTBuckets[i].minVal
			}
		}
	}

	rackThresh := (lt.srtt * 5) / 4
	if minAlt := minRTT + 15*time.Millisecond; minAlt > rackThresh {
		rackThresh = minAlt
	}

	varVar := 4 * lt.rttVar
	if varVar < 20*time.Millisecond {
		varVar = 20 * time.Millisecond
	}
	baseRTO := lt.srtt + varVar
	if !lt.hasAck {
		if baseRTO < 500*time.Millisecond {
			baseRTO = 500 * time.Millisecond
		}
	} else if baseRTO < 180*time.Millisecond {
		baseRTO = 180 * time.Millisecond
	}
	if baseRTO > 2*time.Second {
		baseRTO = 2 * time.Second
	}
	shift := lt.ptoBackoff
	if shift > 3 {
		shift = 3
	}
	rto := baseRTO << shift
	if rto > 4*time.Second {
		rto = 4 * time.Second
	}

	originAgeLimit := lt.srtt
	if originAgeLimit < 500*time.Millisecond {
		originAgeLimit = 500 * time.Millisecond
	}
	originAgeLimit *= 2

	var lostCount uint32
	var hitPTO bool
	for pn, p := range lt.sent {
		elapsed := now.Sub(p.sentAt)
		if p.retired {
			if now.Sub(p.retiredAt) >= originAgeLimit {
				delete(lt.sent, pn)
				lostCount++
			}
			continue
		}
		rackExpired := pn < lt.largestAcked && elapsed >= rackThresh
		rtoExpired := elapsed >= rto
		if rackExpired {
			delete(lt.sent, pn)
			lt.inFlightBytes -= p.wireBytes
			if lt.inFlightBytes < 0 {
				lt.inFlightBytes = 0
			}
			lostCount++
			for _, f := range p.frames {
				if f.OriginPN == 0 {
					f.OriginPN = pn
				}
				lostFrames = append(lostFrames, f)
			}
		} else if rtoExpired {
			// Retire in-flight credit and transfer frames once; keep pn briefly for late SACK RTT
			// calibration or until retransmitted packet SACKs resolve OriginPN / age exceeds 2*max(SRTT,500ms).
			p.retired = true
			p.retiredAt = now
			lt.inFlightBytes -= p.wireBytes
			if lt.inFlightBytes < 0 {
				lt.inFlightBytes = 0
			}
			hitPTO = true
			if len(p.frames) > 0 {
				pending := 0
				for _, f := range p.frames {
					if f.OriginPN == 0 {
						f.OriginPN = pn
						pending++
					}
					lostFrames = append(lostFrames, f)
				}
				p.pendingOrig = pending
				p.frames = nil
			}
		}
	}

	if hitPTO && now.Sub(lt.lastPTOAt) >= rto/2 {
		lt.ptoBackoff++
		lt.lastPTOAt = now
	}
	if lostCount > 0 && (lt.hasAck || lt.ptoBackoff >= 2) {
		lt.recordOutcomeLocked(now, 0, lostCount)
	}
	return lostFrames, lt.ptoBackoff, lt.cachedLossRate, lt.srtt, minRTT
}
