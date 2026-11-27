//go:build ignore

// Generates cmd/gft-client-gui/kestrel.ico and cmd/gft-client-gui/rsrc_windows_amd64.syso
// containing multi-resolution Kestrel Pro icons (RT_ICON + RT_GROUP_ICON ID 1) and
// a PerMonitorV2 DPI-aware + CommonControls v6 application manifest (RT_MANIFEST ID 1).
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"math"
	"os"
	"path/filepath"
	"sort"
)

func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

func lerp(a, b, t float64) float64 {
	return a*(1-t) + b*t
}

func lerpCol(c0, c1 color.NRGBA, t float64) color.NRGBA {
	t = clamp01(t)
	return color.NRGBA{
		R: uint8(math.Round(lerp(float64(c0.R), float64(c1.R), t))),
		G: uint8(math.Round(lerp(float64(c0.G), float64(c1.G), t))),
		B: uint8(math.Round(lerp(float64(c0.B), float64(c1.B), t))),
		A: uint8(math.Round(lerp(float64(c0.A), float64(c1.A), t))),
	}
}

func distPointToSegment(px, py, ax, ay, bx, by float64) float64 {
	vx, vy := bx-ax, by-ay
	wx, wy := px-ax, py-ay
	c1 := vx*wx + vy*wy
	if c1 <= 0 {
		return math.Hypot(px-ax, py-ay)
	}
	c2 := vx*vx + vy*vy
	if c2 <= c1 {
		return math.Hypot(px-bx, py-by)
	}
	b := c1 / c2
	return math.Hypot(px-(ax+b*vx), py-(ay+b*vy))
}

func sdRoundedBox(px, py, halfW, halfH, r float64) float64 {
	qx := math.Abs(px) - (halfW - r)
	qy := math.Abs(py) - (halfH - r)
	ox := math.Max(qx, 0)
	oy := math.Max(qy, 0)
	return math.Hypot(ox, oy) + math.Min(math.Max(qx, qy), 0) - r
}

// renderKestrelIconFromMaster loads the master 1024x1024 PNG artwork and downsamples it
// with 4x4 supersampled bilinear filtering + clean rounded-square alpha for Windows ICO/EXE.
func renderKestrelIconFromMaster(src image.Image, size int) *image.NRGBA {
	sb := src.Bounds()
	sw, sh := float64(sb.Dx()), float64(sb.Dy())
	dst := image.NewNRGBA(image.Rect(0, 0, size, size))
	const ss = 4
	halfBox := 0.94
	cornerR := 0.24

	sampleBilinear := func(u, v float64) (float64, float64, float64) {
		fx := clamp01(u)*(sw-1) + float64(sb.Min.X)
		fy := clamp01(v)*(sh-1) + float64(sb.Min.Y)
		x0 := int(math.Floor(fx))
		y0 := int(math.Floor(fy))
		x1 := x0 + 1
		y1 := y0 + 1
		if x1 >= sb.Max.X {
			x1 = sb.Max.X - 1
		}
		if y1 >= sb.Max.Y {
			y1 = sb.Max.Y - 1
		}
		tx := fx - float64(x0)
		ty := fy - float64(y0)
		c00 := color.NRGBAModel.Convert(src.At(x0, y0)).(color.NRGBA)
		c10 := color.NRGBAModel.Convert(src.At(x1, y0)).(color.NRGBA)
		c01 := color.NRGBAModel.Convert(src.At(x0, y1)).(color.NRGBA)
		c11 := color.NRGBAModel.Convert(src.At(x1, y1)).(color.NRGBA)
		r := lerp(lerp(float64(c00.R), float64(c10.R), tx), lerp(float64(c01.R), float64(c11.R), tx), ty)
		g := lerp(lerp(float64(c00.G), float64(c10.G), tx), lerp(float64(c01.G), float64(c11.G), tx), ty)
		b := lerp(lerp(float64(c00.B), float64(c10.B), tx), lerp(float64(c01.B), float64(c11.B), tx), ty)
		return r, g, b
	}

	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			var sr, sg, sbAcc, sa float64
			for sy := 0; sy < ss; sy++ {
				for sx := 0; sx < ss; sx++ {
					u := (float64(x) + (float64(sx)+0.5)/ss) / float64(size)
					v := (float64(y) + (float64(sy)+0.5)/ss) / float64(size)
					nx := u*2.0 - 1.0
					ny := v*2.0 - 1.0
					d := sdRoundedBox(nx, ny, halfBox, halfBox, cornerR)
					if d > 0.03 {
						continue
					}
					a := clamp01(0.5 - d*float64(size)*0.48)
					if a <= 0 {
						continue
					}
					// Map inner [-halfBox, halfBox] to [0, 1] of master artwork
					mu := (nx/halfBox + 1.0) * 0.5
					mv := (ny/halfBox + 1.0) * 0.5
					r, g, b := sampleBilinear(mu, mv)
					sr += r * a
					sg += g * a
					sbAcc += b * a
					sa += a
				}
			}
			n := float64(ss * ss)
			if sa > 0 {
				dst.SetNRGBA(x, y, color.NRGBA{
					R: uint8(math.Round(clamp01(sr/sa/255.0) * 255.0)),
					G: uint8(math.Round(clamp01(sg/sa/255.0) * 255.0)),
					B: uint8(math.Round(clamp01(sbAcc/sa/255.0) * 255.0)),
					A: uint8(math.Round(clamp01(sa/n) * 255.0)),
				})
			}
		}
	}
	return dst
}

func loadMasterIconPNG() image.Image {
	p := filepath.Join("ios", "Shared", "Assets.xcassets", "AppIcon.appiconset", "AppIcon-1024.png")
	f, err := os.Open(p)
	if err != nil {
		return nil
	}
	defer f.Close()
	img, err := png.Decode(f)
	if err != nil {
		return nil
	}
	return img
}

// renderKestrelIcon renders a crisp supersampled ARGB Kestrel Pro emblem.
func renderKestrelIcon(size int) *image.NRGBA {
	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	const ss = 4 // 4x4 supersampling for clean anti-aliasing down to 16x16

	bgTop := color.NRGBA{0x0F, 0x17, 0x2A, 0xFF}
	bgBot := color.NRGBA{0x07, 0x0D, 0x19, 0xFF}
	ringStart := color.NRGBA{0x10, 0xB9, 0x81, 0xFF} // emerald
	ringEnd := color.NRGBA{0x06, 0xB6, 0xD4, 0xFF}   // cyan
	white := color.NRGBA{0xF8, 0xFA, 0xFC, 0xFF}
	cyanBright := color.NRGBA{0x38, 0xBD, 0xF8, 0xFF}

	// Normalized coords in [-1, 1]
	halfBox := 0.88
	cornerR := 0.28
	ringInset := 0.13
	ringThickness := 0.055
	strokeR := 0.105

	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			var sr, sg, sb, sa float64
			for sy := 0; sy < ss; sy++ {
				for sx := 0; sx < ss; sx++ {
					fx := (float64(x)+(float64(sx)+0.5)/ss)/float64(size)*2.0 - 1.0
					fy := (float64(y)+(float64(sy)+0.5)/ss)/float64(size)*2.0 - 1.0

					dOuter := sdRoundedBox(fx, fy, halfBox, halfBox, cornerR)
					if dOuter > 0.03 {
						continue
					}
					alpha := clamp01(0.5 - dOuter*float64(size)*0.48)
					if alpha <= 0 {
						continue
					}

					tBg := clamp01((fx + fy + 1.6) / 3.2)
					col := lerpCol(bgTop, bgBot, tBg)

					// Subtle top inner sheen
					sheen := math.Exp(-math.Pow(fx*1.1, 2)-math.Pow((fy+0.52)*2.1, 2)) * 0.22
					col = lerpCol(col, color.NRGBA{0x1E, 0x29, 0x3B, 0xFF}, sheen)

					// Glowing emerald-cyan perimeter ring
					dRing := math.Abs(sdRoundedBox(fx, fy, halfBox-ringInset, halfBox-ringInset, cornerR*0.72))
					ringGrad := lerpCol(ringStart, ringEnd, clamp01((fx+fy+1.5)/3.0))
					ringGlow := math.Exp(-math.Pow(dRing/0.14, 2)) * 0.24
					col = lerpCol(col, ringGrad, ringGlow)
					if dRing < ringThickness {
						ringFill := clamp01((ringThickness - dRing) * float64(size) * 0.55)
						col = lerpCol(col, ringGrad, ringFill)
					}

					// Geometric Kestrel "K" / swept falcon wing emblem
					dStem := distPointToSegment(fx, fy, -0.34, -0.44, -0.34, 0.44)
					dUpperWing := distPointToSegment(fx, fy, -0.26, 0.04, 0.36, -0.44)
					dLowerWing := distPointToSegment(fx, fy, -0.10, -0.06, 0.38, 0.44)

					dMin := math.Min(dStem, math.Min(dUpperWing, dLowerWing))
					if dMin < strokeR*2.0 {
						glow := math.Exp(-math.Pow(dMin/(strokeR*1.4), 2)) * 0.25
						col = lerpCol(col, cyanBright, glow)
					}
					if dMin < strokeR {
						fill := clamp01((strokeR - dMin) * float64(size) * 0.55)
						glyphCol := lerpCol(white, cyanBright, clamp01((fx+0.35)/0.8))
						col = lerpCol(col, glyphCol, fill)
					}

					// Small emerald active jewel accent at wing apex
					dDot := math.Hypot(fx-0.37, fy+0.44)
					if dDot < 0.085 {
						dotMix := clamp01((0.085 - dDot) * float64(size) * 0.6)
						col = lerpCol(col, ringStart, dotMix)
					}

					sr += float64(col.R) * alpha
					sg += float64(col.G) * alpha
					sb += float64(col.B) * alpha
					sa += alpha
				}
			}
			const inv = 1.0 / float64(ss*ss)
			saAvg := sa * inv
			if saAvg <= 0.002 {
				continue
			}
			img.SetNRGBA(x, y, color.NRGBA{
				R: uint8(math.Min(255, math.Round(sr*inv/saAvg))),
				G: uint8(math.Min(255, math.Round(sg*inv/saAvg))),
				B: uint8(math.Min(255, math.Round(sb*inv/saAvg))),
				A: uint8(math.Min(255, math.Round(saAvg*255))),
			})
		}
	}
	return img
}

func encodeIconImage(img *image.NRGBA, usePNG bool) ([]byte, error) {
	if usePNG {
		var buf bytes.Buffer
		if err := png.Encode(&buf, img); err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	}
	w := img.Bounds().Dx()
	h := img.Bounds().Dy()
	andStride := ((w + 31) / 32) * 4
	xorSize := w * h * 4
	andSize := andStride * h

	var buf bytes.Buffer
	// BITMAPINFOHEADER (40 bytes)
	_ = binary.Write(&buf, binary.LittleEndian, uint32(40))
	_ = binary.Write(&buf, binary.LittleEndian, int32(w))
	_ = binary.Write(&buf, binary.LittleEndian, int32(h*2)) // XOR + AND mask height
	_ = binary.Write(&buf, binary.LittleEndian, uint16(1))
	_ = binary.Write(&buf, binary.LittleEndian, uint16(32))
	_ = binary.Write(&buf, binary.LittleEndian, uint32(0)) // BI_RGB
	_ = binary.Write(&buf, binary.LittleEndian, uint32(xorSize+andSize))
	_ = binary.Write(&buf, binary.LittleEndian, int32(0))
	_ = binary.Write(&buf, binary.LittleEndian, int32(0))
	_ = binary.Write(&buf, binary.LittleEndian, uint32(0))
	_ = binary.Write(&buf, binary.LittleEndian, uint32(0))

	// Bottom-up BGRA pixels
	for y := h - 1; y >= 0; y-- {
		for x := 0; x < w; x++ {
			c := img.NRGBAAt(x, y)
			buf.WriteByte(c.B)
			buf.WriteByte(c.G)
			buf.WriteByte(c.R)
			buf.WriteByte(c.A)
		}
	}
	// AND mask (0 = use alpha channel; 1 when fully transparent for legacy renderers)
	andMask := make([]byte, andSize)
	for y := h - 1; y >= 0; y-- {
		rowOff := (h - 1 - y) * andStride
		for x := 0; x < w; x++ {
			if img.NRGBAAt(x, y).A == 0 {
				andMask[rowOff+(x/8)] |= 1 << uint(7-(x%8))
			}
		}
	}
	buf.Write(andMask)
	return buf.Bytes(), nil
}

type iconFrame struct {
	size int
	data []byte
}

func buildICO(frames []iconFrame) []byte {
	var hdr bytes.Buffer
	_ = binary.Write(&hdr, binary.LittleEndian, uint16(0)) // reserved
	_ = binary.Write(&hdr, binary.LittleEndian, uint16(1)) // type = ICO
	_ = binary.Write(&hdr, binary.LittleEndian, uint16(len(frames)))

	offset := uint32(6 + len(frames)*16)
	var body bytes.Buffer
	for _, f := range frames {
		wb := byte(f.size)
		hb := byte(f.size)
		if f.size >= 256 {
			wb, hb = 0, 0
		}
		hdr.WriteByte(wb)
		hdr.WriteByte(hb)
		hdr.WriteByte(0) // color count
		hdr.WriteByte(0) // reserved
		_ = binary.Write(&hdr, binary.LittleEndian, uint16(1))  // planes
		_ = binary.Write(&hdr, binary.LittleEndian, uint16(32)) // bitCount
		_ = binary.Write(&hdr, binary.LittleEndian, uint32(len(f.data)))
		_ = binary.Write(&hdr, binary.LittleEndian, offset)
		offset += uint32(len(f.data))
		body.Write(f.data)
	}
	hdr.Write(body.Bytes())
	return hdr.Bytes()
}

func buildGroupIconData(frames []iconFrame) []byte {
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.LittleEndian, uint16(0)) // reserved
	_ = binary.Write(&buf, binary.LittleEndian, uint16(1)) // type = ICO
	_ = binary.Write(&buf, binary.LittleEndian, uint16(len(frames)))
	for i, f := range frames {
		wb := byte(f.size)
		hb := byte(f.size)
		if f.size >= 256 {
			wb, hb = 0, 0
		}
		buf.WriteByte(wb)
		buf.WriteByte(hb)
		buf.WriteByte(0)
		buf.WriteByte(0)
		_ = binary.Write(&buf, binary.LittleEndian, uint16(1))
		_ = binary.Write(&buf, binary.LittleEndian, uint16(32))
		_ = binary.Write(&buf, binary.LittleEndian, uint32(len(f.data)))
		_ = binary.Write(&buf, binary.LittleEndian, uint16(i+1)) // RT_ICON resource ID (1..N)
	}
	return buf.Bytes()
}

// COFF PE x64 .rsrc section builder (pure Go, zero external dependencies).
type rsrcEntry struct {
	typeID uint32
	id     uint32
	langID uint32
	data   []byte
}

func buildCOFFResourceAMD64(entries []rsrcEntry) ([]byte, error) {
	// Group entries by typeID -> id -> langID sorted ascending.
	typeMap := map[uint32]map[uint32][]rsrcEntry{}
	for _, e := range entries {
		if typeMap[e.typeID] == nil {
			typeMap[e.typeID] = map[uint32][]rsrcEntry{}
		}
		typeMap[e.typeID][e.id] = append(typeMap[e.typeID][e.id], e)
	}

	var typeIDs []uint32
	for k := range typeMap {
		typeIDs = append(typeIDs, k)
	}
	sort.Slice(typeIDs, func(i, j int) bool { return typeIDs[i] < typeIDs[j] })

	// Compute directory table size before data entries & payloads.
	// Root directory: 16 + 8*len(typeIDs)
	dirSize := 16 + 8*len(typeIDs)
	typeDirOffsets := make(map[uint32]uint32)
	idDirOffsets := make(map[[2]uint32]uint32)
	dataEntryOffsets := make(map[[3]uint32]uint32)

	for _, tid := range typeIDs {
		typeDirOffsets[tid] = uint32(dirSize)
		var ids []uint32
		for id := range typeMap[tid] {
			ids = append(ids, id)
		}
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
		dirSize += 16 + 8*len(ids)
	}
	for _, tid := range typeIDs {
		var ids []uint32
		for id := range typeMap[tid] {
			ids = append(ids, id)
		}
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
		for _, id := range ids {
			idDirOffsets[[2]uint32{tid, id}] = uint32(dirSize)
			langs := typeMap[tid][id]
			sort.Slice(langs, func(i, j int) bool { return langs[i].langID < langs[j].langID })
			dirSize += 16 + 8*len(langs)
		}
	}

	dataEntriesStart := uint32(dirSize)
	totalItems := 0
	for _, tid := range typeIDs {
		for _, langs := range typeMap[tid] {
			totalItems += len(langs)
		}
	}
	payloadStart := dataEntriesStart + uint32(totalItems*16)

	var rsrc bytes.Buffer
	writeDirHeader := func(idCount uint16) {
		_ = binary.Write(&rsrc, binary.LittleEndian, uint32(0)) // Characteristics
		_ = binary.Write(&rsrc, binary.LittleEndian, uint32(0)) // TimeDateStamp
		_ = binary.Write(&rsrc, binary.LittleEndian, uint16(0)) // MajorVersion
		_ = binary.Write(&rsrc, binary.LittleEndian, uint16(0)) // MinorVersion
		_ = binary.Write(&rsrc, binary.LittleEndian, uint16(0)) // NumberOfNamedEntries
		_ = binary.Write(&rsrc, binary.LittleEndian, idCount)   // NumberOfIdEntries
	}

	// 1. Root directory
	writeDirHeader(uint16(len(typeIDs)))
	for _, tid := range typeIDs {
		_ = binary.Write(&rsrc, binary.LittleEndian, tid)
		_ = binary.Write(&rsrc, binary.LittleEndian, uint32(0x80000000)|typeDirOffsets[tid])
	}

	// 2. Type directories
	for _, tid := range typeIDs {
		var ids []uint32
		for id := range typeMap[tid] {
			ids = append(ids, id)
		}
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
		writeDirHeader(uint16(len(ids)))
		for _, id := range ids {
			_ = binary.Write(&rsrc, binary.LittleEndian, id)
			_ = binary.Write(&rsrc, binary.LittleEndian, uint32(0x80000000)|idDirOffsets[[2]uint32{tid, id}])
		}
	}

	// 3. Language directories
	itemIdx := uint32(0)
	var ordered []rsrcEntry
	for _, tid := range typeIDs {
		var ids []uint32
		for id := range typeMap[tid] {
			ids = append(ids, id)
		}
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
		for _, id := range ids {
			langs := typeMap[tid][id]
			sort.Slice(langs, func(i, j int) bool { return langs[i].langID < langs[j].langID })
			writeDirHeader(uint16(len(langs)))
			for _, ent := range langs {
				deOff := dataEntriesStart + itemIdx*16
				dataEntryOffsets[[3]uint32{tid, id, ent.langID}] = deOff
				_ = binary.Write(&rsrc, binary.LittleEndian, ent.langID)
				_ = binary.Write(&rsrc, binary.LittleEndian, deOff)
				ordered = append(ordered, ent)
				itemIdx++
			}
		}
	}
	if uint32(rsrc.Len()) != dataEntriesStart {
		return nil, fmt.Errorf("dir layout mismatch: got %d want %d", rsrc.Len(), dataEntriesStart)
	}

	// 4. IMAGE_RESOURCE_DATA_ENTRY records + relocations (IMAGE_REL_AMD64_ADDR32NB = 3)
	type relocRec struct {
		virtualAddr uint32
		symbolIdx   uint32
		relocType   uint16
	}
	var relocs []relocRec
	curPayload := payloadStart
	var payloads bytes.Buffer
	for _, ent := range ordered {
		deOff := uint32(rsrc.Len())
		_ = binary.Write(&rsrc, binary.LittleEndian, curPayload)         // OffsetToData (relocated via ADDR32NB)
		_ = binary.Write(&rsrc, binary.LittleEndian, uint32(len(ent.data))) // Size
		_ = binary.Write(&rsrc, binary.LittleEndian, uint32(0))          // CodePage
		_ = binary.Write(&rsrc, binary.LittleEndian, uint32(0))          // Reserved
		relocs = append(relocs, relocRec{
			virtualAddr: deOff,
			symbolIdx:   0, // .rsrc section symbol
			relocType:   3, // IMAGE_REL_AMD64_ADDR32NB
		})
		payloads.Write(ent.data)
		for payloads.Len()%4 != 0 {
			payloads.WriteByte(0)
		}
		curPayload = payloadStart + uint32(payloads.Len())
	}
	rsrc.Write(payloads.Bytes())
	for rsrc.Len()%4 != 0 {
		rsrc.WriteByte(0)
	}

	// Assemble COFF object:
	// [20B COFF File Header] + [40B .rsrc Section Header] + [.rsrc raw data] + [Relocations] + [18B Symbol Table] + [4B String Table]
	const (
		coffHdrSize    = 20
		secHdrSize     = 40
		machineAMD64   = 0x8664
		secFlagsRsrc   = 0x40000040 // IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ
	)
	rawOff := uint32(coffHdrSize + secHdrSize)
	relocOff := rawOff + uint32(rsrc.Len())
	symOff := relocOff + uint32(len(relocs)*10)

	var out bytes.Buffer
	// COFF Header
	_ = binary.Write(&out, binary.LittleEndian, uint16(machineAMD64))
	_ = binary.Write(&out, binary.LittleEndian, uint16(1))      // NumberOfSections
	_ = binary.Write(&out, binary.LittleEndian, uint32(0))      // TimeDateStamp
	_ = binary.Write(&out, binary.LittleEndian, symOff)         // PointerToSymbolTable
	_ = binary.Write(&out, binary.LittleEndian, uint32(1))      // NumberOfSymbols
	_ = binary.Write(&out, binary.LittleEndian, uint16(0))      // SizeOfOptionalHeader
	_ = binary.Write(&out, binary.LittleEndian, uint16(0x0104)) // IMAGE_FILE_LINE_NUMS_STRIPPED | IMAGE_FILE_32BIT_MACHINE? wait -> 0 is standard for x64 object

	// Fix characteristics cleanly (0 for x64 COFF object)
	out.Truncate(18)
	_ = binary.Write(&out, binary.LittleEndian, uint16(0))

	// Section Header (.rsrc)
	var secName [8]byte
	copy(secName[:], ".rsrc")
	out.Write(secName[:])
	_ = binary.Write(&out, binary.LittleEndian, uint32(0))                 // VirtualSize
	_ = binary.Write(&out, binary.LittleEndian, uint32(0))                 // VirtualAddress
	_ = binary.Write(&out, binary.LittleEndian, uint32(rsrc.Len()))        // SizeOfRawData
	_ = binary.Write(&out, binary.LittleEndian, rawOff)                    // PointerToRawData
	_ = binary.Write(&out, binary.LittleEndian, relocOff)                  // PointerToRelocations
	_ = binary.Write(&out, binary.LittleEndian, uint32(0))                 // PointerToLinenumbers
	_ = binary.Write(&out, binary.LittleEndian, uint16(len(relocs)))       // NumberOfRelocations
	_ = binary.Write(&out, binary.LittleEndian, uint16(0))                 // NumberOfLinenumbers
	_ = binary.Write(&out, binary.LittleEndian, uint32(secFlagsRsrc))      // Characteristics

	out.Write(rsrc.Bytes())
	for _, r := range relocs {
		_ = binary.Write(&out, binary.LittleEndian, r.virtualAddr)
		_ = binary.Write(&out, binary.LittleEndian, r.symbolIdx)
		_ = binary.Write(&out, binary.LittleEndian, r.relocType)
	}

	// Symbol table: 1 section symbol for .rsrc
	out.Write(secName[:])
	_ = binary.Write(&out, binary.LittleEndian, uint32(0)) // Value
	_ = binary.Write(&out, binary.LittleEndian, int16(1))  // SectionNumber = 1 (.rsrc)
	_ = binary.Write(&out, binary.LittleEndian, uint16(0)) // Type
	out.WriteByte(3)                                       // StorageClass = IMAGE_SYM_CLASS_STATIC
	out.WriteByte(0)                                       // NumberOfAuxSymbols

	// String table (empty, size = 4)
	_ = binary.Write(&out, binary.LittleEndian, uint32(4))

	return out.Bytes(), nil
}

const appManifestXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity version="4.2.0.0" processorArchitecture="amd64" name="KestrelPro" type="win32"/>
  <description>Kestrel Pro Desktop Client</description>
  <dependency>
    <dependentAssembly>
      <assemblyIdentity type="win32" name="Microsoft.Windows.Common-Controls" version="6.0.0.0" processorArchitecture="*" publicKeyToken="6595b64144ccf1df" language="*"/>
    </dependentAssembly>
  </dependency>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="asInvoker" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
  <application xmlns="urn:schemas-microsoft-com:asm.v3">
    <windowsSettings>
      <dpiAwareness xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">PerMonitorV2</dpiAwareness>
    </windowsSettings>
  </application>
</assembly>
`

func main() {
	sizes := []int{16, 24, 32, 48, 64, 256}
	var frames []iconFrame
	var entries []rsrcEntry
	const langENUS = 0x0409

	masterIcon := loadMasterIconPNG()
	for i, sz := range sizes {
		var img *image.NRGBA
		if masterIcon != nil {
			img = renderKestrelIconFromMaster(masterIcon, sz)
		} else {
			img = renderKestrelIcon(sz)
		}
		data, err := encodeIconImage(img, sz == 256)
		if err != nil {
			panic(err)
		}
		frames = append(frames, iconFrame{size: sz, data: data})
		entries = append(entries, rsrcEntry{
			typeID: 3, // RT_ICON
			id:     uint32(i + 1),
			langID: langENUS,
			data:   data,
		})
	}
	entries = append(entries,
		rsrcEntry{
			typeID: 14, // RT_GROUP_ICON
			id:     1,
			langID: langENUS,
			data:   buildGroupIconData(frames),
		},
		rsrcEntry{
			typeID: 24, // RT_MANIFEST
			id:     1,
			langID: langENUS,
			data:   []byte(appManifestXML),
		},
	)

	icoBytes := buildICO(frames)
	sysoBytes, err := buildCOFFResourceAMD64(entries)
	if err != nil {
		panic(err)
	}

	outDir := filepath.Join("cmd", "gft-client-gui")
	if err := os.WriteFile(filepath.Join(outDir, "kestrel.ico"), icoBytes, 0o644); err != nil {
		panic(err)
	}
	if err := os.WriteFile(filepath.Join(outDir, "rsrc_windows_amd64.syso"), sysoBytes, 0o644); err != nil {
		panic(err)
	}
	setupDir := filepath.Join("cmd", "kestrel-setup")
	if st, err := os.Stat(setupDir); err == nil && st.IsDir() {
		if err := os.WriteFile(filepath.Join(setupDir, "rsrc_windows_amd64.syso"), sysoBytes, 0o644); err != nil {
			panic(err)
		}
	}
	fmt.Printf("Generated kestrel.ico (%d bytes) and rsrc_windows_amd64.syso (%d bytes)\n", len(icoBytes), len(sysoBytes))
}
