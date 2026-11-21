package gftrtc

import (
	mrand "math/rand/v2"
	"sync"
	"time"
)

const (
	ccInitialAutoBps   = 12_000_000.0 / 8.0  // 12 Mbps initial Auto-Probe floor (ramps fast over 170ms links)
	ccMinRateBps       = 256_000.0 / 8.0     // 256 Kbps absolute floor
	ccClientMaxAutoBps = 60_000_000.0 / 8.0  // 60 Mbps client Auto-Probe uplink cap (prevents broadband policing amplification)
	ccMaxAutoBps       = 600_000_000.0 / 8.0 // 600 Mbps server downlink Auto-Probe sanity cap
	ccPolicingLossWall = 0.10                // >10% loss under Auto-Probe signals physical uplink/policing ceiling
)

type ccState uint8

const (
	ccSlowStart ccState = iota
	ccCruise
	ccProbeUp
	ccDrain
)

// SmartBrutalCC implements latency-gradient dual-zone Smart-Brutal congestion control
// paired with a 60fps jittered video-frame micro-burst pacer.
type SmartBrutalCC struct {
	mu sync.Mutex

	isClient  bool
	targetBps float64 // >0 if user/node configured explicit Mbps target; 0 = Auto-Probe
	state     ccState
	baseRate  float64 // current uncompensated base bytes/sec
	bEst      float64 // estimated physical bottleneck bytes/sec

	lastRho       float64
	lastLossRate  float64
	lastRoundAt   time.Time
	lastBackoffAt time.Time
	rttRounds     int

	roundBytes   int64
	roundStart   time.Time
	peakDelivery float64

	// 60fps micro-burst pacer state
	sliceDur      time.Duration
	sliceNextAt   time.Time
	tokenBudget   float64
	maxBurstCap   float64
	frameOuterCap int
}

// NewSmartBrutalCC creates a Smart-Brutal controller. targetMbps == 0 enables Auto-Probe.
func NewSmartBrutalCC(targetMbps int) *SmartBrutalCC {
	return NewSmartBrutalCCForRole(targetMbps, false)
}

// NewSmartBrutalCCForRole creates a Smart-Brutal controller tailored for client uplink or server downlink.
func NewSmartBrutalCCForRole(targetMbps int, isClient bool) *SmartBrutalCC {
	now := time.Now()
	c := &SmartBrutalCC{
		isClient:    isClient,
		state:       ccSlowStart,
		baseRate:    ccInitialAutoBps,
		bEst:        ccInitialAutoBps,
		lastRho:     1.0,
		lastRoundAt: now,
		roundStart:  now,
		sliceDur:    randomFrameSlice(),
		sliceNextAt: now,
	}
	c.SetTargetMbps(targetMbps)
	c.refillFrameSliceLocked(now)
	return c
}

// SetClientMode configures whether Auto-Probe enforces client uplink safety limits.
func (c *SmartBrutalCC) SetClientMode(isClient bool) {
	c.mu.Lock()
	c.isClient = isClient
	if c.targetBps == 0 {
		capBps := c.maxAutoBpsLocked()
		if c.baseRate > capBps {
			c.baseRate = capBps
		}
		if c.bEst > capBps {
			c.bEst = capBps
		}
	}
	c.mu.Unlock()
}

func (c *SmartBrutalCC) maxAutoBpsLocked() float64 {
	if c.isClient {
		return ccClientMaxAutoBps
	}
	return ccMaxAutoBps
}

func randomFrameSlice() time.Duration {
	return time.Duration(12+mrand.IntN(5)) * time.Millisecond // 12ms..16ms (~60-83fps)
}

// SetTargetMbps dynamically updates the target pacing bandwidth (0 = Auto-Probe).
func (c *SmartBrutalCC) SetTargetMbps(mbps int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if mbps <= 0 {
		c.targetBps = 0
		if c.baseRate < ccInitialAutoBps {
			c.baseRate = ccInitialAutoBps
		}
		return
	}
	c.targetBps = float64(mbps) * 1_000_000.0 / 8.0
	c.baseRate = c.targetBps
	c.bEst = c.targetBps
	c.state = ccCruise
}

// TargetMbps returns the configured target Mbps (0 if Auto-Probe).
func (c *SmartBrutalCC) TargetMbps() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.targetBps <= 0 {
		return 0
	}
	return int((c.targetBps*8.0)/1_000_000.0 + 0.5)
}

// OnFeedback updates latency gradient rho = SRTT / minRTT, delivery rate, and Zone A/B decisions.
func (c *SmartBrutalCC) OnFeedback(ackedBytes int, lossRate float64, srtt, minRTT time.Duration, ptoCount int, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.lastLossRate = lossRate
	if minRTT <= 0 {
		minRTT = srtt
	}
	if minRTT <= 0 {
		minRTT = 20 * time.Millisecond
	}
	rho := float64(srtt) / float64(minRTT)
	if rho < 1.0 {
		rho = 1.0
	}
	c.lastRho = rho

	if ackedBytes > 0 {
		c.roundBytes += int64(ackedBytes)
	}

	roundDur := srtt
	if roundDur < 25*time.Millisecond {
		roundDur = 25 * time.Millisecond
	}

	// Zone B: Real physical queue congestion (rho > 1.65 with >=25ms queuing delta, or >=3 consecutive PTOs) -> smooth 0.80 backoff
	queueDelta := srtt - minRTT
	if (rho > 1.65 && queueDelta >= 25*time.Millisecond) || ptoCount >= 3 {
		if now.Sub(c.lastBackoffAt) >= roundDur {
			c.state = ccDrain
			c.baseRate *= 0.80
			if c.baseRate < ccMinRateBps {
				c.baseRate = ccMinRateBps
			}
			if c.targetBps == 0 && c.bEst > c.baseRate*1.25 {
				c.bEst = c.baseRate * 1.15
			}
			c.lastBackoffAt = now
		}
		return
	}

	// Recover out of Drain once queue clears cleanly (rho < 1.25 or queueDelta < 12ms)
	if c.state == ccDrain {
		if rho < 1.25 || queueDelta < 12*time.Millisecond {
			c.state = ccCruise
			if c.targetBps > 0 {
				c.baseRate = c.targetBps * 0.90
			} else {
				c.baseRate = c.bEst * 0.95
			}
			c.lastRoundAt = now
			c.roundStart = now
			c.roundBytes = 0
		}
		return
	}

	// Explicit target mode: hold baseRate near targetBps when not physically congested
	if c.targetBps > 0 {
		if (rho <= 1.35 || queueDelta < 15*time.Millisecond) && c.baseRate < c.targetBps {
			c.baseRate = c.targetBps
		}
		return
	}

	// Auto-Probe mode (targetBps == 0): advance RTT pacing state once per round
	if now.Sub(c.lastRoundAt) < roundDur {
		return
	}
	elapsedSec := now.Sub(c.roundStart).Seconds()
	var deliveryBps float64
	if elapsedSec > 0 && c.roundBytes > 0 {
		if lossRate > ccPolicingLossWall {
			// Above 10% loss in Auto-Probe, measure actual goodput only without 1/(1-loss) amplification.
			deliveryBps = float64(c.roundBytes) / elapsedSec
		} else {
			// Reconstruct pre-loss send capacity smoothly up to 10% loss.
			deliveryBps = (float64(c.roundBytes) / elapsedSec) / (1.0 - lossRate)
		}
		if deliveryBps > c.peakDelivery {
			c.peakDelivery = deliveryBps
		}
	}
	c.lastRoundAt = now
	c.roundStart = now
	c.roundBytes = 0

	maxAuto := c.maxAutoBpsLocked()

	// Tail drops >10% during Auto-Probe indicate physical uplink/policing pressure -> exit SlowStart & back off 0.75x.
	if lossRate > ccPolicingLossWall {
		inSlowOrProbe := c.state == ccSlowStart || c.state == ccProbeUp
		severePolicing := lossRate > 0.25
		shouldBackoff := inSlowOrProbe || (severePolicing && now.Sub(c.lastBackoffAt) >= roundDur*4)
		c.state = ccCruise
		c.rttRounds = 0
		if shouldBackoff {
			c.bEst *= 0.75
			if c.bEst < ccMinRateBps {
				c.bEst = ccMinRateBps
			}
			c.baseRate = c.bEst
			c.lastBackoffAt = now
		} else {
			if deliveryBps > c.bEst {
				if deliveryBps > maxAuto {
					deliveryBps = maxAuto
				}
				c.bEst = deliveryBps
			}
			c.baseRate = 0.95 * c.bEst
			if c.baseRate < ccMinRateBps {
				c.baseRate = ccMinRateBps
			}
		}
		return
	}

	switch c.state {
	case ccSlowStart:
		if rho > 1.30 && queueDelta >= 12*time.Millisecond {
			est := deliveryBps
			if est < c.baseRate*0.85 {
				est = c.baseRate * 0.85
			}
			if est > maxAuto {
				est = maxAuto
			}
			c.bEst = est
			c.baseRate = 0.95 * c.bEst
			c.state = ccCruise
			c.rttRounds = 0
		} else {
			// Only ramp +35% when actual delivery approached at least 25% of baseRate (avoid idle runaway)
			if deliveryBps >= c.baseRate*0.25 || (deliveryBps == 0 && c.baseRate <= ccInitialAutoBps*1.4) {
				c.baseRate *= 1.35
				if c.baseRate > maxAuto {
					c.baseRate = maxAuto
				}
				if c.baseRate > c.bEst {
					c.bEst = c.baseRate
				}
			}
		}

	case ccCruise:
		c.rttRounds++
		if rho > 1.35 && queueDelta >= 15*time.Millisecond {
			// Plateau zone: genuine queue buildup -> hold steady
			return
		}
		if deliveryBps > c.bEst {
			if deliveryBps > maxAuto {
				deliveryBps = maxAuto
			}
			c.bEst = deliveryBps
		}
		c.baseRate = 0.95 * c.bEst
		if c.rttRounds >= 8 {
			c.rttRounds = 0
			c.state = ccProbeUp
			c.baseRate = 1.15 * c.bEst
			if c.baseRate > maxAuto {
				c.baseRate = maxAuto
			}
		}

	case ccProbeUp:
		if (rho <= 1.35 || queueDelta < 15*time.Millisecond) && deliveryBps > c.bEst {
			if deliveryBps > maxAuto {
				deliveryBps = maxAuto
			}
			c.bEst = deliveryBps
		}
		c.baseRate = 0.95 * c.bEst
		c.state = ccCruise
	}
}

func (c *SmartBrutalCC) effectiveRateLocked() float64 {
	rate := c.baseRate
	if rate < ccMinRateBps {
		rate = ccMinRateBps
	}
	// Never apply 1/(1-loss) upward acceleration when Auto-Probe exceeds the 10% physical policing threshold.
	if c.lastRho <= 1.35 && !(c.targetBps == 0 && c.lastLossRate > ccPolicingLossWall) {
		lossCap := c.lastLossRate
		if lossCap > 0.45 {
			lossCap = 0.45
		}
		if lossCap > 0 {
			rate = rate / (1.0 - lossCap)
			maxComp := c.baseRate * 1.8
			if rate > maxComp {
				rate = maxComp
			}
		}
	}
	return rate
}

func (c *SmartBrutalCC) refillFrameSliceLocked(now time.Time) {
	rate := c.effectiveRateLocked()
	slice := randomFrameSlice()
	c.sliceDur = slice
	c.sliceNextAt = now.Add(slice)
	c.frameOuterCap = MinUDPPayloadJitter + mrand.IntN(MaxUDPPayload-MinUDPPayloadJitter+1)
	grant := rate * slice.Seconds()
	if grant < float64(MaxUDPPayload*2) {
		grant = float64(MaxUDPPayload * 2)
	}
	c.maxBurstCap = grant * 2.0
	c.tokenBudget += grant
	if c.tokenBudget > c.maxBurstCap {
		c.tokenBudget = c.maxBurstCap
	}
}

// FrameBudget returns the randomized inner frame payload ceiling (derived from 1160..1360B outer cap)
// for the current 60fps micro-burst slice to eliminate static 1360B packet-size histogram spikes.
func (c *SmartBrutalCC) FrameBudget(fecEnabled bool) int {
	c.mu.Lock()
	outerCap := c.frameOuterCap
	c.mu.Unlock()
	if outerCap < MinUDPPayloadJitter || outerCap > MaxUDPPayload {
		outerCap = MaxUDPPayload
	}
	budget := outerCap - RTPOverhead - FECHeaderLen
	if fecEnabled {
		budget -= 2
	}
	if budget < 1116 {
		budget = 1116
	}
	return budget
}

// ResetOnWake clears stale congestion & delay-gradient state after system sleep/standby or link handoff.
func (c *SmartBrutalCC) ResetOnWake(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastRho = 1.0
	c.lastLossRate = 0
	c.rttRounds = 0
	c.roundBytes = 0
	c.roundStart = now
	c.lastRoundAt = now
	c.lastBackoffAt = time.Time{}
	c.peakDelivery = 0
	if c.targetBps > 0 {
		c.state = ccCruise
		c.baseRate = c.targetBps
	} else {
		c.state = ccSlowStart
		if c.baseRate < ccInitialAutoBps {
			c.baseRate = ccInitialAutoBps
		}
		if c.bEst < ccInitialAutoBps {
			c.bEst = ccInitialAutoBps
		}
	}
	c.tokenBudget = 0
	c.refillFrameSliceLocked(now)
}

// PacingMbps returns the current loss-compensated pacing rate in Mbps.
func (c *SmartBrutalCC) PacingMbps() float64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return (c.effectiveRateLocked() * 8.0) / 1_000_000.0
}

// DelayInflation returns the latest SRTT / minRTT ratio rho.
func (c *SmartBrutalCC) DelayInflation() float64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastRho
}

// MaxInFlightBytes computes the BDP-safe unacknowledged byte ceiling.
func (c *SmartBrutalCC) MaxInFlightBytes(srtt time.Duration) int {
	c.mu.Lock()
	rate := c.effectiveRateLocked()
	c.mu.Unlock()
	if srtt < 150*time.Millisecond {
		srtt = 150 * time.Millisecond
	}
	lim := int(rate * srtt.Seconds() * 2.5)
	if lim < 512*1024 {
		lim = 512 * 1024
	}
	return lim
}

// CanSend checks 60fps slice budget & BDP in-flight ceiling without deducting bytes yet.
func (c *SmartBrutalCC) CanSend(inFlightBytes int, srtt time.Duration, now time.Time) (allowed bool, waitDur time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if now.After(c.sliceNextAt) || now.Equal(c.sliceNextAt) {
		c.refillFrameSliceLocked(now)
	}
	rate := c.effectiveRateLocked()
	minRTTWin := srtt
	if minRTTWin < 150*time.Millisecond {
		minRTTWin = 150 * time.Millisecond
	}
	maxInFlight := int(rate * minRTTWin.Seconds() * 2.5)
	if maxInFlight < 512*1024 {
		maxInFlight = 512 * 1024
	}
	if inFlightBytes > maxInFlight {
		return false, 4 * time.Millisecond
	}
	if c.tokenBudget >= float64(MaxUDPPayload) || c.tokenBudget > 0 {
		return true, 0
	}
	w := c.sliceNextAt.Sub(now)
	if w < time.Millisecond {
		w = time.Millisecond
	}
	return false, w
}

// ConsumeBytes deducts actual sealed packet bytes and returns whether the current frame slice ended (RTP M=1).
func (c *SmartBrutalCC) ConsumeBytes(pktBytes int) (sliceEndMarker bool) {
	c.mu.Lock()
	c.tokenBudget -= float64(pktBytes)
	sliceEndMarker = c.tokenBudget < float64(MaxUDPPayload)
	c.mu.Unlock()
	return sliceEndMarker
}

// AcquireSendSlot checks 60fps micro-burst budget and in-flight cap for a packet of size pktBytes.
// When allowed is true, sliceEndMarker indicates whether this packet finishes the current frame slice (RTP M=1).
func (c *SmartBrutalCC) AcquireSendSlot(inFlightBytes, pktBytes int, srtt time.Duration, now time.Time) (allowed bool, sliceEndMarker bool, waitDur time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if now.After(c.sliceNextAt) || now.Equal(c.sliceNextAt) {
		c.refillFrameSliceLocked(now)
	}

	rate := c.effectiveRateLocked()
	minRTTWin := srtt
	if minRTTWin < 150*time.Millisecond {
		minRTTWin = 150 * time.Millisecond
	}
	maxInFlight := int(rate * minRTTWin.Seconds() * 2.5)
	if maxInFlight < 512*1024 {
		maxInFlight = 512 * 1024
	}
	if inFlightBytes > maxInFlight {
		return false, false, 4 * time.Millisecond
	}

	need := float64(pktBytes)
	if c.tokenBudget >= need {
		c.tokenBudget -= need
		return true, c.tokenBudget < float64(MaxUDPPayload), 0
	}

	w := c.sliceNextAt.Sub(now)
	if w < time.Millisecond {
		w = time.Millisecond
	}
	return false, false, w
}
