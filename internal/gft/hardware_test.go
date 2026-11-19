package gft

import (
	"net"
	"testing"

	utls "github.com/refraction-networking/utls"
)

func TestLowMemModeAndHardwareCipherOrder(t *testing.T) {
	prev := IsLowMemMode()
	defer SetLowMemMode(prev)

	SetLowMemMode(false)
	if EffectiveInitStreamWindow() != 4*1024*1024 {
		t.Fatalf("expected default 4MB init window, got %d", EffectiveInitStreamWindow())
	}
	if EffectiveMaxStreamWindow() != maxStreamWindow {
		t.Fatalf("expected default 16MB window, got %d", EffectiveMaxStreamWindow())
	}
	if QUICConfig().InitialStreamReceiveWindow != 4*1024*1024 || QUICConfig().InitialConnectionReceiveWindow != 8*1024*1024 {
		t.Fatalf("unexpected default QUIC init windows: stream=%d conn=%d", QUICConfig().InitialStreamReceiveWindow, QUICConfig().InitialConnectionReceiveWindow)
	}
	if QUICConfig().MaxStreamReceiveWindow != 16*1024*1024 {
		t.Fatalf("expected 16MB QUIC stream window, got %d", QUICConfig().MaxStreamReceiveWindow)
	}
	if EffectiveUDPSocketBuffer() != 8*1024*1024 {
		t.Fatalf("expected 8MB UDP socket buffer, got %d", EffectiveUDPSocketBuffer())
	}

	SetLowMemMode(true)
	if EffectiveInitStreamWindow() != 1024*1024 {
		t.Fatalf("expected 1MB init window in LowMemMode, got %d", EffectiveInitStreamWindow())
	}
	if EffectiveMaxStreamWindow() != 4*1024*1024 {
		t.Fatalf("expected 4MB window in LowMemMode, got %d", EffectiveMaxStreamWindow())
	}
	if QUICConfig().MaxStreamReceiveWindow != 4*1024*1024 {
		t.Fatalf("expected 4MB QUIC stream window in LowMemMode, got %d", QUICConfig().MaxStreamReceiveWindow)
	}
	if EffectiveUDPSocketBuffer() != 1024*1024 {
		t.Fatalf("expected 1MB UDP socket buffer in LowMemMode, got %d", EffectiveUDPSocketBuffer())
	}

	// Verify AuthPacketConn forwards SetReadBuffer / SetWriteBuffer to underlying UDPConn
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	authPC := NewAuthPacketConn(pc, nil)
	if err := authPC.SetReadBuffer(2 * 1024 * 1024); err != nil {
		t.Fatalf("AuthPacketConn.SetReadBuffer failed: %v", err)
	}
	if err := authPC.SetWriteBuffer(2 * 1024 * 1024); err != nil {
		t.Fatalf("AuthPacketConn.SetWriteBuffer failed: %v", err)
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
