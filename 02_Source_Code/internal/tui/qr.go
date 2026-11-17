package tui

import (
	"errors"
	"strings"
)

// Pure-Go ISO 18004 Byte-mode QR Code matrix generator (Versions 1..15, ECC Level L)
// for zero-dependency terminal QR rendering of gft3:// URIs.

type qrSpec struct {
	ver        int
	dataBytes  int
	eccPerBlk  int
	g1Blocks   int
	g1Data     int
	g2Blocks   int
	g2Data     int
	alignments []int
}

// Level L specifications covering byte payloads up to 520+ chars (gft3:// links are ~240-360 chars).
var qrSpecs = []qrSpec{
	{1, 19, 7, 1, 19, 0, 0, nil},
	{2, 34, 10, 1, 34, 0, 0, []int{6, 18}},
	{3, 55, 15, 1, 55, 0, 0, []int{6, 22}},
	{4, 80, 20, 1, 80, 0, 0, []int{6, 26}},
	{5, 108, 26, 1, 108, 0, 0, []int{6, 30}},
	{6, 136, 18, 2, 68, 0, 0, []int{6, 34}},
	{7, 156, 20, 2, 78, 0, 0, []int{6, 22, 38}},
	{8, 194, 24, 2, 97, 0, 0, []int{6, 24, 42}},
	{9, 232, 30, 2, 116, 0, 0, []int{6, 26, 46}},
	{10, 274, 18, 2, 68, 2, 69, []int{6, 28, 50}},
	{11, 324, 20, 4, 81, 0, 0, []int{6, 30, 54}},
	{12, 370, 24, 2, 92, 2, 93, []int{6, 32, 58}},
	{13, 428, 26, 4, 107, 0, 0, []int{6, 34, 62}},
	{14, 461, 30, 3, 115, 1, 116, []int{6, 26, 46, 66}},
	{15, 523, 22, 5, 87, 1, 88, []int{6, 26, 48, 70}},
}

var gfExp [512]byte
var gfLog [256]byte

func init() {
	x := 1
	for i := 0; i < 255; i++ {
		gfExp[i] = byte(x)
		gfLog[x] = byte(i)
		x <<= 1
		if x&0x100 != 0 {
			x ^= 0x11D
		}
	}
	for i := 255; i < 512; i++ {
		gfExp[i] = gfExp[i-255]
	}
}

func gfMul(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	return gfExp[int(gfLog[a])+int(gfLog[b])]
}

func rsGenerator(deg int) []byte {
	g := []byte{1}
	for i := 0; i < deg; i++ {
		root := gfExp[i]
		next := make([]byte, len(g)+1)
		for j := 0; j < len(g); j++ {
			next[j] ^= g[j]
			next[j+1] ^= gfMul(g[j], root)
		}
		g = next
	}
	return g
}

func rsComputeECC(data []byte, eccLen int) []byte {
	gen := rsGenerator(eccLen)
	buf := make([]byte, len(data)+eccLen)
	copy(buf, data)
	for i := 0; i < len(data); i++ {
		coef := buf[i]
		if coef == 0 {
			continue
		}
		for j := 0; j < len(gen); j++ {
			buf[i+j] ^= gfMul(gen[j], coef)
		}
	}
	return buf[len(data):]
}

// EncodeQR builds a square boolean QR code matrix (true = dark module) for payload.
func EncodeQR(payload string) ([][]bool, error) {
	raw := []byte(payload)
	var sp *qrSpec
	for i := range qrSpecs {
		cand := &qrSpecs[i]
		cntBits := 8
		if cand.ver >= 10 {
			cntBits = 16
		}
		neededBits := 4 + cntBits + len(raw)*8
		if neededBits <= cand.dataBytes*8 {
			sp = cand
			break
		}
	}
	if sp == nil {
		return nil, errors.New("payload exceeds max QR length (~515 bytes)")
	}

	// Build bit stream
	bits := make([]byte, 0, sp.dataBytes*8)
	appendBits := func(val, n int) {
		for i := n - 1; i >= 0; i-- {
			bits = append(bits, byte((val>>i)&1))
		}
	}
	appendBits(0b0100, 4) // Byte mode
	cntBits := 8
	if sp.ver >= 10 {
		cntBits = 16
	}
	appendBits(len(raw), cntBits)
	for _, b := range raw {
		appendBits(int(b), 8)
	}
	capBits := sp.dataBytes * 8
	term := 4
	if capBits-len(bits) < term {
		term = capBits - len(bits)
	}
	appendBits(0, term)
	for len(bits)%8 != 0 {
		bits = append(bits, 0)
	}
	codewords := make([]byte, 0, sp.dataBytes)
	for i := 0; i < len(bits); i += 8 {
		var v byte
		for j := 0; j < 8; j++ {
			v = (v << 1) | bits[i+j]
		}
		codewords = append(codewords, v)
	}
	padSeq := [2]byte{0xEC, 0x11}
	for p := 0; len(codewords) < sp.dataBytes; p++ {
		codewords = append(codewords, padSeq[p&1])
	}

	// Split blocks & compute ECC
	var dataBlocks [][]byte
	var eccBlocks [][]byte
	off := 0
	for i := 0; i < sp.g1Blocks; i++ {
		blk := codewords[off : off+sp.g1Data]
		off += sp.g1Data
		dataBlocks = append(dataBlocks, blk)
		eccBlocks = append(eccBlocks, rsComputeECC(blk, sp.eccPerBlk))
	}
	for i := 0; i < sp.g2Blocks; i++ {
		blk := codewords[off : off+sp.g2Data]
		off += sp.g2Data
		dataBlocks = append(dataBlocks, blk)
		eccBlocks = append(eccBlocks, rsComputeECC(blk, sp.eccPerBlk))
	}

	var finalBytes []byte
	maxD := sp.g1Data
	if sp.g2Data > maxD {
		maxD = sp.g2Data
	}
	for col := 0; col < maxD; col++ {
		for _, blk := range dataBlocks {
			if col < len(blk) {
				finalBytes = append(finalBytes, blk[col])
			}
		}
	}
	for col := 0; col < sp.eccPerBlk; col++ {
		for _, blk := range eccBlocks {
			finalBytes = append(finalBytes, blk[col])
		}
	}

	n := sp.ver*4 + 17
	mat := make([][]bool, n)
	fn := make([][]bool, n)
	for r := 0; r < n; r++ {
		mat[r] = make([]bool, n)
		fn[r] = make([]bool, n)
	}

	setMod := func(r, c int, dark, isFunc bool) {
		if r >= 0 && r < n && c >= 0 && c < n {
			mat[r][c] = dark
			if isFunc {
				fn[r][c] = true
			}
		}
	}
	drawFinder := func(r0, c0 int) {
		for dr := -1; dr <= 7; dr++ {
			for dc := -1; dc <= 7; dc++ {
				r, c := r0+dr, c0+dc
				if r < 0 || r >= n || c < 0 || c >= n {
					continue
				}
				dark := dr >= 0 && dr <= 6 && dc >= 0 && dc <= 6 &&
					(dr == 0 || dr == 6 || dc == 0 || dc == 6 || (dr >= 2 && dr <= 4 && dc >= 2 && dc <= 4))
				setMod(r, c, dark, true)
			}
		}
	}
	drawFinder(0, 0)
	drawFinder(0, n-7)
	drawFinder(n-7, 0)

	// Alignment patterns
	for _, ar := range sp.alignments {
		for _, ac := range sp.alignments {
			if fn[ar][ac] {
				continue
			}
			for dr := -2; dr <= 2; dr++ {
				for dc := -2; dc <= 2; dc++ {
					dark := dr == -2 || dr == 2 || dc == -2 || dc == 2 || (dr == 0 && dc == 0)
					setMod(ar+dr, ac+dc, dark, true)
				}
			}
		}
	}

	// Timing patterns
	for i := 8; i < n-8; i++ {
		if !fn[6][i] {
			setMod(6, i, i%2 == 0, true)
		}
		if !fn[i][6] {
			setMod(i, 6, i%2 == 0, true)
		}
	}
	setMod(n-8, 8, true, true) // Dark module

	// Reserve format info areas
	for i := 0; i <= 8; i++ {
		if !fn[8][i] {
			setMod(8, i, false, true)
		}
		if !fn[i][8] {
			setMod(i, 8, false, true)
		}
	}
	for i := n - 8; i < n; i++ {
		setMod(8, i, false, true)
	}
	for i := n - 7; i < n; i++ {
		setMod(i, 8, false, true)
	}

	// Reserve version info (>=7)
	if sp.ver >= 7 {
		vBits := calcVersionInfo(sp.ver)
		for i := 0; i < 18; i++ {
			dark := ((vBits >> i) & 1) == 1
			r := i / 3
			c := n - 11 + (i % 3)
			setMod(r, c, dark, true)
			setMod(c, r, dark, true)
		}
	}

	// Place data bits in zig-zag columns using Mask 0 ((r+c)%2 == 0) directly after placement
	bitIdx := 0
	totalDataBits := len(finalBytes) * 8
	up := true
	for col := n - 1; col >= 1; col -= 2 {
		if col == 6 {
			col--
		}
		for i := 0; i < n; i++ {
			r := i
			if up {
				r = n - 1 - i
			}
			for dc := 0; dc < 2; dc++ {
				c := col - dc
				if fn[r][c] {
					continue
				}
				var bit bool
				if bitIdx < totalDataBits {
					b := finalBytes[bitIdx/8]
					bit = ((b >> (7 - (bitIdx % 8))) & 1) == 1
					bitIdx++
				}
				mat[r][c] = bit
			}
		}
		up = !up
	}

	// Select best mask (0..7) minimizing penalty
	bestMask := 0
	bestScore := int(1e9)
	for m := 0; m < 8; m++ {
		applyMask(mat, fn, m)
		writeFormatBits(mat, m)
		sc := qrPenalty(mat)
		if sc < bestScore {
			bestScore = sc
			bestMask = m
		}
		applyMask(mat, fn, m) // revert mask
	}
	applyMask(mat, fn, bestMask)
	writeFormatBits(mat, bestMask)
	return mat, nil
}

func maskBit(mask, r, c int) bool {
	switch mask {
	case 0:
		return (r+c)%2 == 0
	case 1:
		return r%2 == 0
	case 2:
		return c%3 == 0
	case 3:
		return (r+c)%3 == 0
	case 4:
		return (r/2+c/3)%2 == 0
	case 5:
		return (r*c)%2+(r*c)%3 == 0
	case 6:
		return ((r*c)%2+(r*c)%3)%2 == 0
	default:
		return ((r+c)%2+(r*c)%3)%2 == 0
	}
}

func applyMask(mat, fn [][]bool, mask int) {
	n := len(mat)
	for r := 0; r < n; r++ {
		for c := 0; c < n; c++ {
			if !fn[r][c] && maskBit(mask, r, c) {
				mat[r][c] = !mat[r][c]
			}
		}
	}
}

func writeFormatBits(mat [][]bool, mask int) {
	// Level L (01) + 3-bit mask => 5-bit data; BCH(15,5) + XOR 0x5412
	data := (0b01 << 3) | mask
	rem := data << 10
	for i := 4; i >= 0; i-- {
		if (rem>>(i+10))&1 != 0 {
			rem ^= 0x537 << i
		}
	}
	bits := ((data << 10) | rem) ^ 0x5412
	n := len(mat)
	for i := 0; i <= 5; i++ {
		mat[8][i] = ((bits >> (14 - i)) & 1) == 1
	}
	mat[8][7] = ((bits >> 8) & 1) == 1
	mat[8][8] = ((bits >> 7) & 1) == 1
	mat[7][8] = ((bits >> 6) & 1) == 1
	for i := 9; i < 15; i++ {
		mat[14-i][8] = ((bits >> (14 - i)) & 1) == 1
	}
	for i := 0; i < 7; i++ {
		mat[n-1-i][8] = ((bits >> i) & 1) == 1
	}
	for i := 7; i < 15; i++ {
		mat[8][n-15+i] = ((bits >> i) & 1) == 1
	}
}

func calcVersionInfo(ver int) int {
	rem := ver << 12
	for i := 5; i >= 0; i-- {
		if (rem>>(i+12))&1 != 0 {
			rem ^= 0x1F25 << i
		}
	}
	return (ver << 12) | rem
}

func qrPenalty(mat [][]bool) int {
	n := len(mat)
	pen := 0
	for r := 0; r < n; r++ {
		run := 1
		for c := 1; c < n; c++ {
			if mat[r][c] == mat[r][c-1] {
				run++
				if run == 5 {
					pen += 3
				} else if run > 5 {
					pen++
				}
			} else {
				run = 1
			}
		}
	}
	for c := 0; c < n; c++ {
		run := 1
		for r := 1; r < n; r++ {
			if mat[r][c] == mat[r-1][c] {
				run++
				if run == 5 {
					pen += 3
				} else if run > 5 {
					pen++
				}
			} else {
				run = 1
			}
		}
	}
	return pen
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
