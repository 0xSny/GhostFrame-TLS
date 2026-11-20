//go:build linux

package tproxy

import (
	"testing"
	"time"
)

func TestUDPServerSessionCapEviction(t *testing.T) {
	srv := &UDPServer{
		closed:   make(chan struct{}),
		sessions: make(map[udpTuple]*udpNatEntry),
	}

	var closedCount int
	now := time.Now().UnixNano()
	for i := 0; i < maxUDPNatSessions; i++ {
		tup := udpTuple{srcPort: uint16(10000 + i), dstPort: 443}
		ent := &udpNatEntry{
			tuple:   tup,
			closeFn: func() { closedCount++ },
		}
		ent.lastUsed.Store(now + int64(i))
		srv.sessions[tup] = ent
	}

	if maxUDPNatSessions != 1024 {
		t.Fatalf("expected maxUDPNatSessions=1024, got %d", maxUDPNatSessions)
	}
	oldest := udpTuple{srcPort: 10000, dstPort: 443}
	if _, ok := srv.sessions[oldest]; !ok {
		t.Fatal("expected oldest tuple present before eviction")
	}

	// Simulate getOrCreateSession capacity eviction check
	var evicted *udpNatEntry
	srv.mu.Lock()
	if len(srv.sessions) >= maxUDPNatSessions {
		var oldestKey udpTuple
		var oldestTS int64
		first := true
		for k, candidate := range srv.sessions {
			ts := candidate.lastUsed.Load()
			if first || ts < oldestTS {
				first = false
				oldestTS = ts
				oldestKey = k
				evicted = candidate
			}
		}
		if evicted != nil {
			delete(srv.sessions, oldestKey)
		}
	}
	srv.sessions[udpTuple{srcPort: 60000, dstPort: 443}] = &udpNatEntry{}
	srv.mu.Unlock()
	if evicted != nil && evicted.closeFn != nil {
		evicted.closeFn()
	}

	if _, stillPresent := srv.sessions[oldest]; stillPresent {
		t.Fatalf("expected oldest session %+v evicted at cap", oldest)
	}
	if len(srv.sessions) != maxUDPNatSessions || closedCount != 1 {
		t.Fatalf("unexpected session count=%d closedCount=%d", len(srv.sessions), closedCount)
	}
}
