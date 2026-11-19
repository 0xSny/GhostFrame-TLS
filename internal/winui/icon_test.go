//go:build windows

package winui

import (
	"testing"

	"ghostframe/internal/client"
)

func TestCreateVectorIconAllStates(t *testing.T) {
	states := []client.ConnState{
		client.StateDisconnected,
		client.StateConnecting,
		client.StateConnected,
		client.StateError,
	}
	for _, st := range states {
		h := CreateVectorIcon(st)
		if h == 0 {
			t.Fatalf("CreateVectorIcon(%s) returned 0", st)
		}
		_, _, _ = pDestroyIcon.Call(h)
	}
}

func TestBackBufferClipBoundsAndResizeHook(t *testing.T) {
	var b backBuffer
	defer b.release()

	releasedCalls := 0
	ok, rec := b.ensure(0, 320, 240, func() { releasedCalls++ })
	if !ok || !rec || releasedCalls != 1 {
		t.Fatalf("initial ensure failed: ok=%v rec=%v released=%d", ok, rec, releasedCalls)
	}

	// Same size must reuse buffer without calling onBeforeRelease
	ok, rec = b.ensure(0, 320, 240, func() { releasedCalls++ })
	if !ok || rec || releasedCalls != 1 {
		t.Fatalf("same-size reuse failed: ok=%v rec=%v released=%d", ok, rec, releasedCalls)
	}

	// Resize triggers onBeforeRelease BEFORE releasing old DC/BMP
	ok, rec = b.ensure(0, 640, 480, func() { releasedCalls++ })
	if !ok || !rec || releasedCalls != 2 {
		t.Fatalf("resize recreate failed: ok=%v rec=%v released=%d", ok, rec, releasedCalls)
	}

	// Out-of-bounds / oversized clips must clamp safely with zero panics
	oversized := rect{-50, -50, 9999, 9999}
	b.clear(0xFF070B12)
	b.drawLineAA(-30, -30, 800, 600, 3, 0xFF10B981, oversized)
	b.fillCurveArea([]float32{-10, 200, 700}, []float32{-5, 100, 500}, 490, 0x4410B981, 0x0510B981, oversized)

	// Degenerate / negative-area clip returns safely
	b.drawLineAA(0, 0, 100, 100, 2, 0xFFFFFFFF, rect{500, 500, 400, 400})
}
