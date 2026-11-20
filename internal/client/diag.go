package client

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
)

const defaultLogRingCap = 1000

// LogRingBuffer stores up to maxCap recent LogEntry items in a fixed ring without unbounded growth.
type LogRingBuffer struct {
	mu     sync.Mutex
	buf    []LogEntry
	head   int
	count  int
	maxCap int
}

// NewLogRingBuffer constructs a fixed-capacity ring log buffer.
func NewLogRingBuffer(maxCap int) *LogRingBuffer {
	if maxCap <= 0 {
		maxCap = defaultLogRingCap
	}
	return &LogRingBuffer{
		buf:    make([]LogEntry, maxCap),
		maxCap: maxCap,
	}
}

// Push appends entry to the ring, overwriting the oldest item when full.
func (r *LogRingBuffer) Push(entry LogEntry) {
	r.mu.Lock()
	if r.count < r.maxCap {
		idx := (r.head + r.count) % r.maxCap
		r.buf[idx] = entry
		r.count++
	} else {
		r.buf[r.head] = entry
		r.head = (r.head + 1) % r.maxCap
	}
	r.mu.Unlock()
}

// Entries returns a chronological copy of all stored log entries.
func (r *LogRingBuffer) Entries() []LogEntry {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]LogEntry, r.count)
	for i := 0; i < r.count; i++ {
		out[i] = r.buf[(r.head+i)%r.maxCap]
	}
	return out
}

// Clear resets the ring buffer.
func (r *LogRingBuffer) Clear() {
	r.mu.Lock()
	clear(r.buf)
	r.head = 0
	r.count = 0
	r.mu.Unlock()
}

// Len returns current stored entry count.
func (r *LogRingBuffer) Len() int {
	r.mu.Lock()
	n := r.count
	r.mu.Unlock()
	return n
}

var (
	reGFTLink = regexp.MustCompile(`(?i)gft3://[^\s"'<>]+`)
	reIPv4    = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b`)
	rePSKJson = regexp.MustCompile(`(?i)("?(?:psk|password|secret|token|pin)"?\s*[:=]\s*"?)([A-Za-z0-9+/=_-]{8,})("?)`)
)

// MaskSensitiveText redacts URIs, public IPs, PSKs, passwords, and caller-supplied secrets
// so exported diagnostic snapshots can be shared safely without credential leakage.
func MaskSensitiveText(in string, extraSecrets ...string) string {
	out := reGFTLink.ReplaceAllString(in, "gft3://***")
	for _, sec := range extraSecrets {
		sec = strings.TrimSpace(sec)
		if sec != "" && sec != "127.0.0.1" && strings.ToLower(sec) != "localhost" {
			out = strings.ReplaceAll(out, sec, "***")
		}
	}
	out = rePSKJson.ReplaceAllString(out, `${1}***${3}`)
	out = reIPv4.ReplaceAllStringFunc(out, func(ip string) string {
		if ip == "127.0.0.1" || strings.HasPrefix(ip, "127.") || ip == "0.0.0.0" {
			return ip
		}
		return "***"
	})
	return out
}

// BuildDiagnosticSnapshot compiles a redacted health, tunnel, routing, and ring-log report.
func (e *Engine) BuildDiagnosticSnapshot() string {
	st := e.Status()
	logs := e.Logs()

	e.mu.RLock()
	l := e.activeLinkLocked()
	var secrets []string
	if l != nil {
		if l.Host != "" {
			secrets = append(secrets, l.Host)
		}
		if l.SNI != "" {
			secrets = append(secrets, l.SNI)
		}
		if l.PSK != "" {
			secrets = append(secrets, l.PSK)
		}
		if l.Pin != "" {
			secrets = append(secrets, l.Pin)
		}
		if enc := l.Encode(); enc != "" {
			secrets = append(secrets, enc)
		}
	}
	e.mu.RUnlock()

	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)

	var sb strings.Builder
	sb.WriteString("=== GhostFrame-Pro Diagnostic Snapshot (Sanitized) ===\n")
	fmt.Fprintf(&sb, "Version: v4.0.0-LTS (%s/%s, %s)\n", runtime.GOOS, runtime.GOARCH, runtime.Version())
	fmt.Fprintf(&sb, "State: %v | ActiveTransport: %v | Pref: %v | RouteMode: %v\n",
		st["state"], st["active_transport"], st["transport_pref"], st["route_mode"])
	fmt.Fprintf(&sb, "RTT: %vms (SRTT=%vms, MinRTT=%vms) | Loss: %.2f%% | Pacing: %.1f Mbps | FEC Recovered: %v\n",
		st["ping_ms"], st["srtt_ms"], st["min_rtt_ms"], st["loss_pct"], st["pacing_mbps"], st["fec_recovered"])
	fmt.Fprintf(&sb, "RTC Channels: %v | HopRange: %v | HopState: %v | HopCount: %v | RekeyCount: %v\n",
		st["rtc_ports"], "***", st["hop_state"], st["hop_count"], st["rekey_count"])
	fmt.Fprintf(&sb, "ActiveConns: %v | ActiveStreams: %v | Up: %v B | Down: %v B\n",
		st["active_conns"], st["active_streams"], st["total_up"], st["total_down"])
	fmt.Fprintf(&sb, "Proxy: SOCKS5=%v HTTP=%v SysProxy=%v Drifted=%v\n",
		st["socks_addr"], st["http_addr"], st["sys_proxy"], st["proxy_drifted"])
	fmt.Fprintf(&sb, "Runtime: Goroutines=%d HeapAlloc=%.2fMB HeapInuse=%.2fMB Sys=%.2fMB\n",
		runtime.NumGoroutine(), float64(ms.HeapAlloc)/(1<<20), float64(ms.HeapInuse)/(1<<20), float64(ms.Sys)/(1<<20))
	sb.WriteString("\n--- Recent Kernel Logs (Masked, up to 1000 entries) ---\n")
	for _, entry := range logs {
		fmt.Fprintf(&sb, "%s %s\n", entry.Time, entry.Message)
	}
	return MaskSensitiveText(sb.String(), secrets...)
}

// ExportDiagnosticSnapshot builds a sanitized snapshot, saves it to ~/.gft/diag_snapshot.txt,
// and copies it to the system clipboard on desktop platforms when possible.
func (e *Engine) ExportDiagnosticSnapshot(hwnd uintptr) (outPath string, copied bool, text string, err error) {
	text = e.BuildDiagnosticSnapshot()
	dir := ""
	if e.cfgPath != "" {
		dir = filepath.Dir(e.cfgPath)
	}
	if dir == "" {
		if home, herr := os.UserHomeDir(); herr == nil && home != "" {
			dir = filepath.Join(home, ".gft")
		}
	}
	if dir != "" {
		_ = os.MkdirAll(dir, 0o755)
		outPath = filepath.Join(dir, "diag_snapshot.txt")
		err = os.WriteFile(outPath, []byte(text), 0o600)
	}
	copied = copyTextClipboardNative(hwnd, text)
	return outPath, copied, text, err
}
