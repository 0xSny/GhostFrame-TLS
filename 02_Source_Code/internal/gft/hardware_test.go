package gft

import (
	"testing"

	utls "github.com/refraction-networking/utls"
)

func TestLowMemModeAndHardwareCipherOrder(t *testing.T) {
	prev := IsLowMemMode()
	defer SetLowMemMode(prev)

	SetLowMemMode(false)
	if EffectiveMaxStreamWindow() != maxStreamWindow {
		t.Fatalf("expected default 16MB window, got %d", EffectiveMaxStreamWindow())
	}
	if QUICConfig().MaxStreamReceiveWindow != 16*1024*1024 {
		t.Fatalf("expected 16MB QUIC stream window, got %d", QUICConfig().MaxStreamReceiveWindow)
	}

	SetLowMemMode(true)
	if EffectiveMaxStreamWindow() != 4*1024*1024 {
		t.Fatalf("expected 4MB window in LowMemMode, got %d", EffectiveMaxStreamWindow())
	}
	if QUICConfig().MaxStreamReceiveWindow != 4*1024*1024 {
		t.Fatalf("expected 4MB QUIC stream window in LowMemMode, got %d", QUICConfig().MaxStreamReceiveWindow)
	}
	bp := GetBuf()
	PutBuf(bp)

	spec := utls.ClientHelloSpec{
		CipherSuites: []uint16{
			utls.GREASE_PLACEHOLDER,
			utls.TLS_AES_128_GCM_SHA256,
			utls.TLS_AES_256_GCM_SHA384,
			utls.TLS_CHACHA20_POLY1305_SHA256,
		},
	}
	prioritizeSpecChaCha20(&spec)
	if spec.CipherSuites[0] != utls.GREASE_PLACEHOLDER || spec.CipherSuites[1] != utls.TLS_CHACHA20_POLY1305_SHA256 {
		t.Fatalf("expected ChaCha20 right after GREASE, got %x", spec.CipherSuites)
	}
}
