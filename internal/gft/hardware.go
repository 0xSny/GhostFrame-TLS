package gft

import (
	"crypto/tls"
	"net"
	"runtime"
	"sync/atomic"

	"ghostframe/internal/gftrtc"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/sys/cpu"
)

var lowMemMode atomic.Bool

// SetLowMemMode toggles low-memory mode (designed for Phicomm N1 / S905D routers):
// converges max per-stream window from 16MB -> 4MB and shrinks buffer pools.
func SetLowMemMode(on bool) {
	lowMemMode.Store(on)
	gftrtc.SetLowMemMode(on)
}

// IsLowMemMode reports whether low-memory mode is enabled.
func IsLowMemMode() bool {
	return lowMemMode.Load()
}

// EffectiveInitStreamWindow returns 1MB in low-memory mode or 4MB by default.
func EffectiveInitStreamWindow() int {
	if lowMemMode.Load() {
		return 1024 * 1024
	}
	return streamWindow
}

// EffectiveMaxStreamWindow returns 4MB in low-memory mode or 16MB by default.
func EffectiveMaxStreamWindow() int {
	if lowMemMode.Load() {
		return 4 * 1024 * 1024
	}
	return maxStreamWindow
}

// EffectivePoolSize returns 4 TCP-uTLS sessions in low-memory mode or 6 by default
// for multi-flow TCP-uTLS striping without single-socket loss bottlenecks.
func EffectivePoolSize() int {
	if lowMemMode.Load() {
		return DefaultPoolSize
	}
	return 6
}

// EffectiveUDPSocketBuffer returns the OS UDP socket receive/send buffer target
// (512KB in low-memory mode or 8MB by default).
func EffectiveUDPSocketBuffer() int {
	if lowMemMode.Load() {
		return 512 * 1024
	}
	return 8 * 1024 * 1024
}

// TuneUDPSocketBuffers enlarges OS read/write buffers on UDP sockets to prevent
// kernel buffer truncation on high-BDP links.
func TuneUDPSocketBuffers(pc net.PacketConn) {
	gftrtc.TuneUDPSocketBuffers(pc)
}

// PrioritizeChaCha20 returns true on ARM64 SoCs without ARMv8 Crypto/AES instructions
// (e.g., Amlogic S905D on Phicomm N1), where ChaCha20-Poly1305 delivers ~2x throughput.
func PrioritizeChaCha20() bool {
	return runtime.GOARCH == "arm64" && !cpu.ARM64.HasAES
}

// OptimizeTLSConfigForHardware tunes tls.Config cipher preferences for host CPU capabilities.
func OptimizeTLSConfigForHardware(cfg *tls.Config) {
	if cfg == nil {
		return
	}
	if PrioritizeChaCha20() {
		cfg.CipherSuites = []uint16{
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		}
	}
}

// newUClientWithHardware builds a uTLS client prioritizing ChaCha20-Poly1305 on
// AES-less ARM64 boards while preserving browser fingerprint extensions elsewhere.
func newUClientWithHardware(conn net.Conn, ucfg *utls.Config, id utls.ClientHelloID) *utls.UConn {
	if PrioritizeChaCha20() {
		if spec, err := utls.UTLSIdToSpec(id); err == nil && len(spec.CipherSuites) > 0 {
			prioritizeSpecChaCha20(&spec)
			uc := utls.UClient(conn, ucfg, utls.HelloCustom)
			if uc.ApplyPreset(&spec) == nil {
				return uc
			}
		}
	}
	return utls.UClient(conn, ucfg, id)
}

func prioritizeSpecChaCha20(spec *utls.ClientHelloSpec) {
	const chacha = utls.TLS_CHACHA20_POLY1305_SHA256
	idx := -1
	for i, cs := range spec.CipherSuites {
		if cs == chacha {
			idx = i
			break
		}
	}
	if idx <= 0 {
		return
	}
	// Keep leading GREASE value at index 0 if present, place ChaCha20 first among real ciphers.
	insertAt := 0
	if spec.CipherSuites[0]&0x0f0f == 0x0a0a {
		insertAt = 1
	}
	if idx <= insertAt {
		return
	}
	copy(spec.CipherSuites[insertAt+1:idx+1], spec.CipherSuites[insertAt:idx])
	spec.CipherSuites[insertAt] = chacha
}
