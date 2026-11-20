package main

import (
	"bytes"
	"image/png"
	"testing"
)

func TestRenderIconOpaqueRGB1024(t *testing.T) {
	data, err := renderIconPNG(1024)
	if err != nil {
		t.Fatalf("renderIconPNG failed: %v", err)
	}
	if len(data) < 30 {
		t.Fatalf("PNG output unexpectedly small: %d", len(data))
	}
	// PNG IHDR ColorType sits at byte offset 25 (8B sig + 4B len + 4B "IHDR" + 4B W + 4B H + 1B depth).
	// ColorType == 2 strictly guarantees pure RGB with NO alpha channel.
	if data[25] != 2 {
		t.Fatalf("expected PNG ColorType=2 (opaque RGB without alpha), got %d", data[25])
	}
	cfg, err := png.DecodeConfig(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("png.DecodeConfig failed: %v", err)
	}
	if cfg.Width != 1024 || cfg.Height != 1024 {
		t.Fatalf("expected 1024x1024 icon, got %dx%d", cfg.Width, cfg.Height)
	}
}
