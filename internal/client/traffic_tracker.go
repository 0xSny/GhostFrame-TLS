package client

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"

	"ghostframe/internal/gft"
)

const (
	maxTrackedTrafficTargets  = 2048
	highUploadAlertThreshold  = uint64(20 * 1024 * 1024) // 20 MB in 10s
	highUploadAlertCooldown   = 10 * time.Second
	highUploadAlertWindowSecs = 10
)

// TargetTrafficStat holds cumulative and 10s sliding-window upload/download stats for a destination.
type TargetTrafficStat struct {
	Target      string    `json:"target"`
	UpBytes     uint64    `json:"total_up"`
	DownBytes   uint64    `json:"total_down"`
	Window10sUp uint64    `json:"window_10s_up"`
	HighUpload  bool      `json:"high_upload"`
	LastSeen    time.Time `json:"last_seen"`
}

type uploadSecBucket struct {
	sec   int64
	bytes uint64
}

type targetTrafficEntry struct {
	target      string
	upBytes     uint64
	downBytes   uint64
	lastSeen    time.Time
	win         [highUploadAlertWindowSecs]uploadSecBucket
	lastAlertAt time.Time
}

type targetTrafficTracker struct {
	mu      sync.Mutex
	entries map[string]*targetTrafficEntry
	nowFn   func() time.Time
}

func newTargetTrafficTracker() *targetTrafficTracker {
	return &targetTrafficTracker{
		entries: make(map[string]*targetTrafficEntry, 128),
		nowFn:   time.Now,
	}
}

func windowUploadLocked(ent *targetTrafficEntry, nowSec int64) uint64 {
	var winUp uint64
	for i := range ent.win {
		b := ent.win[i]
		if nowSec-b.sec >= 0 && nowSec-b.sec < highUploadAlertWindowSecs {
			winUp += b.bytes
		}
	}
	return winUp
}

func (t *targetTrafficTracker) Record(target string, upBytes, downBytes uint64) (alertMsg string) {
	if upBytes == 0 && downBytes == 0 {
		return ""
	}
	clean := strings.TrimSpace(target)
	if clean == "" {
		return ""
	}
	now := t.nowFn()
	nowSec := now.Unix()

	t.mu.Lock()
	ent, ok := t.entries[clean]
	if !ok {
		if len(t.entries) >= maxTrackedTrafficTargets {
			var oldestKey string
			var oldestAt time.Time
			for k, v := range t.entries {
				if oldestKey == "" || v.lastSeen.Before(oldestAt) {
					oldestKey = k
					oldestAt = v.lastSeen
				}
			}
			if oldestKey != "" {
				delete(t.entries, oldestKey)
			}
		}
		ent = &targetTrafficEntry{target: clean}
		t.entries[clean] = ent
	}
	ent.upBytes += upBytes
	ent.downBytes += downBytes
	ent.lastSeen = now

	if upBytes > 0 {
		slot := int(nowSec % highUploadAlertWindowSecs)
		if slot < 0 {
			slot += highUploadAlertWindowSecs
		}
		if ent.win[slot].sec != nowSec {
			ent.win[slot] = uploadSecBucket{sec: nowSec, bytes: upBytes}
		} else {
			ent.win[slot].bytes += upBytes
		}
		winUp := windowUploadLocked(ent, nowSec)
		if winUp > highUploadAlertThreshold && (ent.lastAlertAt.IsZero() || now.Sub(ent.lastAlertAt) >= highUploadAlertCooldown) {
			ent.lastAlertAt = now
			alertMsg = fmt.Sprintf("[TrafficAlert] High upload: %s (↑%.1f MB in 10s)", clean, float64(winUp)/(1024*1024))
		}
	}
	t.mu.Unlock()
	return alertMsg
}

func (t *targetTrafficTracker) TopUpload(limit int) []TargetTrafficStat {
	if limit <= 0 {
		limit = 10
	}
	nowSec := t.nowFn().Unix()
	t.mu.Lock()
	out := make([]TargetTrafficStat, 0, len(t.entries))
	for _, ent := range t.entries {
		winUp := windowUploadLocked(ent, nowSec)
		out = append(out, TargetTrafficStat{
			Target:      ent.target,
			UpBytes:     ent.upBytes,
			DownBytes:   ent.downBytes,
			Window10sUp: winUp,
			HighUpload:  winUp >= highUploadAlertThreshold,
			LastSeen:    ent.lastSeen,
		})
	}
	t.mu.Unlock()

	sort.Slice(out, func(i, j int) bool {
		if out[i].UpBytes != out[j].UpBytes {
			return out[i].UpBytes > out[j].UpBytes
		}
		if out[i].DownBytes != out[j].DownBytes {
			return out[i].DownBytes > out[j].DownBytes
		}
		return out[i].Target < out[j].Target
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

// trackedDataStream wraps gft.DataStream to record per-target upload and download byte counts.
type trackedDataStream struct {
	gft.DataStream
	eng    *Engine
	target string
}

func (s *trackedDataStream) Read(p []byte) (int, error) {
	n, err := s.DataStream.Read(p)
	if n > 0 && s.eng != nil {
		s.eng.RecordTargetTraffic(s.target, 0, uint64(n))
	}
	return n, err
}

func (s *trackedDataStream) Write(p []byte) (int, error) {
	n, err := s.DataStream.Write(p)
	if n > 0 && s.eng != nil {
		s.eng.RecordTargetTraffic(s.target, uint64(n), 0)
	}
	return n, err
}

var _ io.ReadWriteCloser = (*trackedDataStream)(nil)
