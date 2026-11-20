package main

import (
	"bytes"
	"flag"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"math"
	"os"
	"path/filepath"
)

const defaultOutPath = "ios/Shared/Assets.xcassets/AppIcon.appiconset/AppIcon-1024.png"

// opaqueRGB is an image.Image whose Opaque() returns true so Go's image/png writes
// ColorType=2 (24-bit RGB without alpha channel), matching Apple AppIcon requirements.
type opaqueRGB struct {
	rect image.Rectangle
	pix  []uint8
}

func newOpaqueRGB(w, h int) *opaqueRGB {
	return &opaqueRGB{
		rect: image.Rect(0, 0, w, h),
		pix:  make([]uint8, w*h*4),
	}
}

func (o *opaqueRGB) ColorModel() color.Model { return color.RGBAModel }
func (o *opaqueRGB) Bounds() image.Rectangle { return o.rect }
func (o *opaqueRGB) Opaque() bool            { return true }
func (o *opaqueRGB) At(x, y int) color.Color { return o.RGBAAt(x, y) }
func (o *opaqueRGB) RGBAAt(x, y int) color.RGBA {
	if !image.Pt(x, y).In(o.rect) {
		return color.RGBA{}
	}
	i := (y*o.rect.Dx() + x) * 4
	return color.RGBA{R: o.pix[i], G: o.pix[i+1], B: o.pix[i+2], A: 255}
}
func (o *opaqueRGB) SetRGB(x, y int, r, g, b uint8) {
	i := (y*o.rect.Dx() + x) * 4
	o.pix[i] = r
	o.pix[i+1] = g
	o.pix[i+2] = b
	o.pix[i+3] = 255
}

func renderIconPNG(size int) ([]byte, error) {
	img := newOpaqueRGB(size, size)
	cx := float64(size) * 0.5
	cy := float64(size) * 0.5
	inv := 1.0 / float64(size)

	// Layer 1: Deep obsidian backdrop + subtle cyan/indigo radial nebula glow
	for y := 0; y < size; y++ {
		ny := float64(y) * inv
		for x := 0; x < size; x++ {
			nx := float64(x) * inv

			// Base diagonal dark obsidian gradient (#040812 -> #0C152B)
			t := clamp01(0.65*ny + 0.35*nx)
			r := lerp(4.0, 12.0, t)
			g := lerp(8.0, 21.0, t)
			b := lerp(18.0, 43.0, t)

			// Subtle cyan aura centered behind emblem
			dCenter := math.Hypot((float64(x)-cx)*inv, (float64(y)-cy)*inv)
			aura := math.Exp(-dCenter * dCenter * 9.5)
			r += 10.0 * aura
			g += 58.0 * aura
			b += 86.0 * aura

			// Secondary top-right indigo ambient sheen
			dIndigo := math.Hypot(nx-0.78, ny-0.22)
			indigoAura := math.Exp(-dIndigo * dIndigo * 6.5)
			r += 24.0 * indigoAura
			g += 18.0 * indigoAura
			b += 68.0 * indigoAura

			// Subtle concentric cyber radar rings
			ringDist := math.Abs(dCenter - 0.37)
			if ringDist < 0.0045 {
				alpha := smoothstep(0.0045, 0.0, ringDist) * 0.22
				r = lerp(r, 56.0, alpha)
				g = lerp(g, 189.0, alpha)
				b = lerp(b, 248.0, alpha)
			}

			// Layer 2: Outer neon GhostFrame shield SDF (super-sampled AA via smoothstep)
			sdShield := shieldSDF(nx-0.5, ny-0.5)
			if sdShield < 0.014 {
				// Outer cyan glow halo
				halo := smoothstep(0.014, 0.0, sdShield) * 0.48
				r = lerp(r, 34.0, halo)
				g = lerp(g, 211.0, halo)
				b = lerp(b, 238.0, halo)
			}
			if sdShield < 0.002 {
				fillMask := smoothstep(0.002, -0.002, sdShield)
				// Dark glass shield interior (#0A162D -> #112447)
				inR := lerp(10.0, 18.0, ny)
				inG := lerp(22.0, 40.0, ny)
				inB := lerp(45.0, 74.0, ny)
				// Bright neon cyan-indigo edge rim
				rimWidth := 0.016
				if sdShield > -rimWidth {
					rim := smoothstep(-rimWidth, -0.002, sdShield)
					grad := clamp01((nx-0.25)*1.4 + (ny-0.2)*0.4)
					rimR := lerp(34.0, 99.0, grad)
					rimG := lerp(238.0, 130.0, grad)
					rimB := lerp(246.0, 246.0, grad)
					inR = lerp(inR, rimR, rim)
					inG = lerp(inG, rimG, rim)
					inB = lerp(inB, rimB, rim)
				}
				r = lerp(r, inR, fillMask)
				g = lerp(g, inG, fillMask)
				b = lerp(b, inB, fillMask)
			}

			// Layer 3: Inner Ghost Prism / Phantom V-Chevron core
			sdPrism := prismSDF(nx-0.5, ny-0.5)
			if sdPrism < 0.002 {
				pMask := smoothstep(0.002, -0.002, sdPrism)
				gt := clamp01((ny - 0.30) / 0.40)
				prR := lerp(165.0, 34.0, gt)
				prG := lerp(248.0, 211.0, gt)
				prB := lerp(255.0, 238.0, gt)
				// Faceted left/right prism highlight
				if nx > 0.5 {
					prR *= 0.80
					prG *= 0.90
				}
				r = lerp(r, prR, pMask)
				g = lerp(g, prG, pMask)
				b = lerp(b, prB, pMask)
			}

			// Core diamond eye highlight
			dCore := math.Abs(nx-0.5) + math.Abs(ny-0.46)
			if dCore < 0.045 {
				cMask := smoothstep(0.045, 0.039, dCore)
				r = lerp(r, 240.0, cMask)
				g = lerp(g, 253.0, cMask)
				b = lerp(b, 255.0, cMask)
			}

			img.SetRGB(x, y, clampByte(r), clampByte(g), clampByte(b))
		}
	}

	var buf bytes.Buffer
	enc := png.Encoder{CompressionLevel: png.BestCompression}
	if err := enc.Encode(&buf, img); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// shieldSDF returns signed distance in normalized [-0.5, 0.5] coordinates.
func shieldSDF(dx, dy float64) float64 {
	ax := math.Abs(dx)
	// Shield spans roughly dy in [-0.29, +0.30], max half-width 0.24
	top := -0.27 + 0.08*ax
	halfW := 0.235
	if dy > 0.02 {
		t := clamp01((dy - 0.02) / 0.28)
		halfW = 0.235 * (1.0 - 0.92*math.Pow(t, 1.45))
	}
	dTop := top - dy
	dBot := dy - 0.29
	dSide := ax - halfW
	outside := math.Hypot(math.Max(dSide, 0), math.Max(math.Max(dTop, dBot), 0))
	inside := math.Min(math.Max(dSide, math.Max(dTop, dBot)), 0)
	return outside + inside
}

// prismSDF renders the geometric GhostFrame phantom chevron inside the shield.
func prismSDF(dx, dy float64) float64 {
	ax := math.Abs(dx)
	// Symmetric diamond-hooded chevron
	top := -0.15 + 0.68*ax
	bot := 0.16 - 0.55*ax
	if ax > 0.03 {
		// Cutout inner chevron notch at bottom
		notch := 0.075 - 0.25*ax
		if dy > notch && ax < 0.085 {
			bot = notch
		}
	}
	dSide := ax - 0.135
	dTop := top - dy
	dBot := dy - bot
	outside := math.Hypot(math.Max(dSide, 0), math.Max(math.Max(dTop, dBot), 0))
	inside := math.Min(math.Max(dSide, math.Max(dTop, dBot)), 0)
	return outside + inside
}

func lerp(a, b, t float64) float64 { return a + (b-a)*t }
func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}
func smoothstep(e0, e1, x float64) float64 {
	t := clamp01((x - e0) / (e1 - e0))
	return t * t * (3.0 - 2.0*t)
}
func clampByte(v float64) uint8 {
	if v <= 0 {
		return 0
	}
	if v >= 255 {
		return 255
	}
	return uint8(math.Round(v))
}

func main() {
	out := flag.String("out", defaultOutPath, "output path for 1024x1024 opaque RGB AppIcon PNG")
	flag.Parse()

	data, err := renderIconPNG(1024)
	if err != nil {
		fmt.Fprintf(os.Stderr, "render icon failed: %v\n", err)
		os.Exit(1)
	}
	if err := os.MkdirAll(filepath.Dir(*out), 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "mkdir failed: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(*out, data, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write icon failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Generated 1024x1024 opaque RGB AppIcon (%d bytes) -> %s\n", len(data), *out)
}
