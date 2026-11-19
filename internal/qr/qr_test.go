package qr

import (
	"strings"
	"testing"
)

func TestQRVersions16To20AndLongGFT3SVG(t *testing.T) {
	for _, n := range []int{40, 220, 545, 620, 820} {
		payload := "gft3://" + strings.Repeat("A", n-7)
		svg, err := RenderSVG(payload)
		if err != nil {
			t.Fatalf("RenderSVG(len=%d) failed: %v", n, err)
		}
		if !strings.HasPrefix(svg, "<svg ") || !strings.HasSuffix(svg, "</svg>") {
			t.Fatalf("unexpected SVG wrapper for len=%d", n)
		}
	}
}
