package tui

import (
	"strings"

	"ghostframe/internal/qr"
)

// EncodeQR builds a square boolean QR code matrix (true = dark module) for payload.
func EncodeQR(payload string) ([][]bool, error) {
	return qr.Encode(payload)
}

// RenderTerminalQR renders payload as a compact UTF-8 half-block QR code (2 rows per line)
// with white-module quiet zone so smartphone cameras scan reliably even on dark terminals.
func RenderTerminalQR(payload string, utf8 bool) (string, error) {
	mat, err := EncodeQR(payload)
	if err != nil {
		return "", err
	}
	const quiet = 1
	n := len(mat)
	total := n + quiet*2
	isLight := func(r, c int) bool {
		mr, mc := r-quiet, c-quiet
		if mr < 0 || mr >= n || mc < 0 || mc >= n {
			return true // quiet zone is light background
		}
		return !mat[mr][mc]
	}

	var b strings.Builder
	if !utf8 {
		for r := 0; r < total; r++ {
			for c := 0; c < total; c++ {
				if isLight(r, c) {
					b.WriteString("##")
				} else {
					b.WriteString("  ")
				}
			}
			b.WriteByte('\n')
		}
		return b.String(), nil
	}

	for r := 0; r < total; r += 2 {
		for c := 0; c < total; c++ {
			top := isLight(r, c)
			bot := true
			if r+1 < total {
				bot = isLight(r+1, c)
			}
			switch {
			case top && bot:
				b.WriteRune('█')
			case top && !bot:
				b.WriteRune('▀')
			case !top && bot:
				b.WriteRune('▄')
			default:
				b.WriteRune(' ')
			}
		}
		b.WriteByte('\n')
	}
	return b.String(), nil
}
