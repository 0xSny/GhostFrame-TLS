//go:build windows

package winui

import (
	"math"
	"os"
	"runtime"
	"syscall"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	windowClassName = "GhostFrameProWndClass"
	singleMutexName = `Local\GhostFrameTLSPro_SingleInstance`

	wmAppWake    = 0x8001 // WM_APP + 1
	wmAppTray    = 0x8002 // WM_APP + 2
	wmAppQuit    = 0x8003 // WM_APP + 3
	wmAppRefresh = 0x8004 // WM_APP + 4

	wmCreate          = 0x0001
	wmDestroy         = 0x0002
	wmSize            = 0x0005
	wmSetFocus        = 0x0007
	wmPaint           = 0x000F
	wmClose           = 0x0010
	wmQueryEndSession = 0x0011
	wmEraseBkgnd      = 0x0014
	wmEndSession      = 0x0016
	wmGetMinMaxInfo   = 0x0024
	wmSetIcon         = 0x0080
	wmKeyDown         = 0x0100
	wmChar            = 0x0102
	wmCommand         = 0x0111
	wmTimer           = 0x0113
	wmMouseMove       = 0x0200
	wmLButtonDown     = 0x0201
	wmLButtonUp       = 0x0202
	wmLButtonDblClk   = 0x0203
	wmRButtonUp       = 0x0205
	wmMouseWheel      = 0x020A
	wmDpiChanged      = 0x02E0
	wmContextMenu     = 0x007B

	swHide    = 0
	swShow    = 5
	swRestore = 9

	wsOverlappedWindow = 0x00CF0000
	wsClipChildren     = 0x02000000
	cwUseDefault       = 0x80000000

	csVRedraw = 0x0001
	csHRedraw = 0x0002
	csDblClks = 0x0008

	idcArrow = 32512
	idcHand  = 32649

	iconSmall = 0
	iconBig   = 1

	swpNoZOrder   = 0x0004
	swpNoActivate = 0x0010

	srcCopy       = 0x00CC0020
	dibRGBColors  = 0
	biRGB         = 0
	cfUnicodeText = 13
	gmemMoveable  = 0x0002

	dwmwaUseImmersiveDarkMode   = 20
	dwmwaWindowCornerPreference = 33
	dwmwcpRound                 = 2
	dpiAwarenessPerMonitorV2    = ^uintptr(3) // -4

	nimAdd        = 0x00000000
	nimModify     = 0x00000001
	nimDelete     = 0x00000002
	nimSetVersion = 0x00000004
	nifMessage    = 0x00000001
	nifIcon       = 0x00000002
	nifTip        = 0x00000004
	notifyIconV4  = 4

	tpmLeftAlign   = 0x0000
	tpmRightButton = 0x0002
	tpmReturnCmd   = 0x0100
	tpmNonotify    = 0x0080

	mfString    = 0x00000000
	mfChecked   = 0x00000008
	mfPopup     = 0x00000010
	mfSeparator = 0x00000800
)

var (
	user32   = windows.NewLazySystemDLL("user32.dll")
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")
	gdi32    = windows.NewLazySystemDLL("gdi32.dll")
	dwmapi   = windows.NewLazySystemDLL("dwmapi.dll")
	shell32  = windows.NewLazySystemDLL("shell32.dll")
	gdiplus  = windows.NewLazySystemDLL("gdiplus.dll")

	pGetModuleHandleW              = kernel32.NewProc("GetModuleHandleW")
	pGlobalAlloc                   = kernel32.NewProc("GlobalAlloc")
	pGlobalLock                    = kernel32.NewProc("GlobalLock")
	pGlobalSize                    = kernel32.NewProc("GlobalSize")
	pGlobalUnlock                  = kernel32.NewProc("GlobalUnlock")
	pSetProcessDpiAwarenessContext = user32.NewProc("SetProcessDpiAwarenessContext")
	pGetDpiForWindow               = user32.NewProc("GetDpiForWindow")
	pGetSystemMetrics              = user32.NewProc("GetSystemMetrics")
	pRegisterClassExW              = user32.NewProc("RegisterClassExW")
	pCreateWindowExW               = user32.NewProc("CreateWindowExW")
	pDefWindowProcW                = user32.NewProc("DefWindowProcW")
	pFindWindowW                   = user32.NewProc("FindWindowW")
	pShowWindow                    = user32.NewProc("ShowWindow")
	pUpdateWindow                  = user32.NewProc("UpdateWindow")
	pSetWindowPos                  = user32.NewProc("SetWindowPos")
	pSetForegroundWindow           = user32.NewProc("SetForegroundWindow")
	pIsWindowVisible               = user32.NewProc("IsWindowVisible")
	pGetMessageW                   = user32.NewProc("GetMessageW")
	pTranslateMessage              = user32.NewProc("TranslateMessage")
	pDispatchMessageW              = user32.NewProc("DispatchMessageW")
	pPostQuitMessage               = user32.NewProc("PostQuitMessage")
	pPostMessageW                  = user32.NewProc("PostMessageW")
	pSendMessageW                  = user32.NewProc("SendMessageW")
	pInvalidateRect                = user32.NewProc("InvalidateRect")
	pBeginPaint                    = user32.NewProc("BeginPaint")
	pEndPaint                      = user32.NewProc("EndPaint")
	pGetClientRect                 = user32.NewProc("GetClientRect")
	pSetTimer                      = user32.NewProc("SetTimer")
	pKillTimer                     = user32.NewProc("KillTimer")
	pLoadCursorW                   = user32.NewProc("LoadCursorW")
	pSetCursor                     = user32.NewProc("SetCursor")
	pGetKeyState                   = user32.NewProc("GetKeyState")
	pCreatePopupMenu               = user32.NewProc("CreatePopupMenu")
	pAppendMenuW                   = user32.NewProc("AppendMenuW")
	pTrackPopupMenuEx              = user32.NewProc("TrackPopupMenuEx")
	pDestroyMenu                   = user32.NewProc("DestroyMenu")
	pGetCursorPos                  = user32.NewProc("GetCursorPos")
	pOpenClipboard                 = user32.NewProc("OpenClipboard")
	pCloseClipboard                = user32.NewProc("CloseClipboard")
	pEmptyClipboard                = user32.NewProc("EmptyClipboard")
	pGetClipboardData              = user32.NewProc("GetClipboardData")
	pSetClipboardData              = user32.NewProc("SetClipboardData")
	pCreateIconIndirect            = user32.NewProc("CreateIconIndirect")
	pDestroyIcon                   = user32.NewProc("DestroyIcon")

	pCreateCompatibleDC = gdi32.NewProc("CreateCompatibleDC")
	pDeleteDC           = gdi32.NewProc("DeleteDC")
	pCreateDIBSection   = gdi32.NewProc("CreateDIBSection")
	pCreateBitmap       = gdi32.NewProc("CreateBitmap")
	pSelectObject       = gdi32.NewProc("SelectObject")
	pDeleteObject       = gdi32.NewProc("DeleteObject")
	pBitBlt             = gdi32.NewProc("BitBlt")

	pDwmSetWindowAttribute = dwmapi.NewProc("DwmSetWindowAttribute")
	pShellNotifyIconW      = shell32.NewProc("Shell_NotifyIconW")

	pGdiplusStartup               = gdiplus.NewProc("GdiplusStartup")
	pGdiplusShutdown              = gdiplus.NewProc("GdiplusShutdown")
	pGdipCreateFromHDC            = gdiplus.NewProc("GdipCreateFromHDC")
	pGdipDeleteGraphics           = gdiplus.NewProc("GdipDeleteGraphics")
	pGdipSetSmoothingMode         = gdiplus.NewProc("GdipSetSmoothingMode")
	pGdipSetTextRenderingHint     = gdiplus.NewProc("GdipSetTextRenderingHint")
	pGdipCreateSolidFill          = gdiplus.NewProc("GdipCreateSolidFill")
	pGdipDeleteBrush              = gdiplus.NewProc("GdipDeleteBrush")
	pGdipCreateFontFromLogfontW   = gdiplus.NewProc("GdipCreateFontFromLogfontW")
	pGdipDeleteFont               = gdiplus.NewProc("GdipDeleteFont")
	pGdipCreateStringFormat       = gdiplus.NewProc("GdipCreateStringFormat")
	pGdipDeleteStringFormat       = gdiplus.NewProc("GdipDeleteStringFormat")
	pGdipSetStringFormatAlign     = gdiplus.NewProc("GdipSetStringFormatAlign")
	pGdipSetStringFormatLineAlign = gdiplus.NewProc("GdipSetStringFormatLineAlign")
	pGdipSetStringFormatTrimming  = gdiplus.NewProc("GdipSetStringFormatTrimming")
	pGdipDrawString               = gdiplus.NewProc("GdipDrawString")
	pGdipFlush                    = gdiplus.NewProc("GdipFlush")
)

type point struct {
	X, Y int32
}

type rect struct {
	Left, Top, Right, Bottom int32
}

func (r rect) width() int32  { return r.Right - r.Left }
func (r rect) height() int32 { return r.Bottom - r.Top }
func (r rect) contains(x, y int32) bool {
	return x >= r.Left && x < r.Right && y >= r.Top && y < r.Bottom
}

type minMaxInfo struct {
	Reserved     point
	MaxSize      point
	MaxPosition  point
	MinTrackSize point
	MaxTrackSize point
}

type wndClassExW struct {
	CbSize        uint32
	Style         uint32
	LpfnWndProc   uintptr
	CbClsExtra    int32
	CbWndExtra    int32
	HInstance     uintptr
	HIcon         uintptr
	HCursor       uintptr
	HbrBackground uintptr
	LpszMenuName  *uint16
	LpszClassName *uint16
	HIconSm       uintptr
}

type msgW struct {
	HWnd     uintptr
	Message  uint32
	WParam   uintptr
	LParam   uintptr
	Time     uint32
	Pt       point
	LPrivate uint32
}

type paintStruct struct {
	HDC         uintptr
	FErase      uint32
	RcPaint     rect
	FRestore    uint32
	FIncUpdate  uint32
	RgbReserved [32]byte
}

type bitmapInfoHeader struct {
	BiSize          uint32
	BiWidth         int32
	BiHeight        int32
	BiPlanes        uint16
	BiBitCount      uint16
	BiCompression   uint32
	BiSizeImage     uint32
	BiXPelsPerMeter int32
	BiYPelsPerMeter int32
	BiClrUsed       uint32
	BiClrImportant  uint32
}

type bitmapInfo struct {
	BmiHeader bitmapInfoHeader
	BmiColors [1]uint32
}

type iconInfo struct {
	FIcon    uint32
	XHotspot uint32
	YHotspot uint32
	HbmMask  uintptr
	HbmColor uintptr
}

type notifyIconDataW struct {
	CbSize           uint32
	HWnd             uintptr
	UID              uint32
	UFlags           uint32
	UCallbackMessage uint32
	HIcon            uintptr
	SzTip            [128]uint16
	DwState          uint32
	DwStateMask      uint32
	SzInfo           [256]uint16
	UVersion         uint32
	SzInfoTitle      [64]uint16
	DwInfoFlags      uint32
	GuidItem         windows.GUID
	HBalloonIcon     uintptr
}

type logFontW struct {
	LfHeight         int32
	LfWidth          int32
	LfEscapement     int32
	LfOrientation    int32
	LfWeight         int32
	LfItalic         byte
	LfUnderline      byte
	LfStrikeOut      byte
	LfCharSet        byte
	LfOutPrecision   byte
	LfClipPrecision  byte
	LfQuality        byte
	LfPitchAndFamily byte
	LfFaceName       [32]uint16
}

type gdiplusStartupInput struct {
	GdiplusVersion           uint32
	DebugEventCallback       uintptr
	SuppressBackgroundThread uint32
	SuppressExternalCodecs   uint32
}

type rectF struct {
	X, Y, Width, Height float32
}

func utf16Ptr(s string) *uint16 {
	p, _ := syscall.UTF16PtrFromString(s)
	return p
}

func copyUTF16(dst []uint16, s string) {
	u := utf16.Encode([]rune(s))
	n := len(dst) - 1
	if len(u) < n {
		n = len(u)
	}
	copy(dst[:n], u[:n])
	dst[n] = 0
}

func enablePerMonitorDPI() {
	_, _, _ = pSetProcessDpiAwarenessContext.Call(dpiAwarenessPerMonitorV2)
}

func windowDPI(hwnd uintptr) int32 {
	r, _, _ := pGetDpiForWindow.Call(hwnd)
	if r < 96 {
		return 96
	}
	return int32(r)
}

func applyDarkWindowChrome(hwnd uintptr) {
	dark := uint32(1)
	_, _, _ = pDwmSetWindowAttribute.Call(hwnd, dwmwaUseImmersiveDarkMode, uintptr(unsafe.Pointer(&dark)), unsafe.Sizeof(dark))
	round := uint32(dwmwcpRound)
	_, _, _ = pDwmSetWindowAttribute.Call(hwnd, dwmwaWindowCornerPreference, uintptr(unsafe.Pointer(&round)), unsafe.Sizeof(round))
}

// AcquireSingleInstance creates the named single-instance mutex. If an earlier
// instance already owns it, this sends the wakeup message to its window and
// returns (0, false) so the caller can exit cleanly.
func AcquireSingleInstance() (windows.Handle, bool) {
	if os.Getenv("GFT_NO_SINGLE_INSTANCE") == "1" {
		return 0, true
	}
	mutPtr := utf16Ptr(singleMutexName)
	h, err := windows.CreateMutex(nil, false, mutPtr)
	runtime.KeepAlive(mutPtr)
	if h != 0 && err == windows.ERROR_ALREADY_EXISTS {
		_ = windows.CloseHandle(h)
		cls := utf16Ptr(windowClassName)
		for i := 0; i < 6; i++ {
			hwnd, _, _ := pFindWindowW.Call(uintptr(unsafe.Pointer(cls)), 0)
			runtime.KeepAlive(cls)
			if hwnd != 0 {
				_, _, _ = pPostMessageW.Call(hwnd, wmAppWake, 0, 0)
				_, _, _ = pShowWindow.Call(hwnd, swRestore)
				_, _, _ = pSetForegroundWindow.Call(hwnd)
				return 0, false
			}
			windows.SleepEx(60, false)
		}
		return 0, false
	}
	if err != nil && h == 0 {
		return 0, true // proceed if mutex API unexpectedly restricted
	}
	return h, true
}

func osPtr(addr uintptr) unsafe.Pointer {
	return *(*unsafe.Pointer)(unsafe.Pointer(&addr))
}

// SetClipboardText writes UTF-16 text to the native Windows clipboard.
func SetClipboardText(hwnd uintptr, s string) bool {
	u := utf16.Encode([]rune(s))
	u = append(u, 0)
	byteLen := uintptr(len(u) * 2)

	hMem, _, _ := pGlobalAlloc.Call(gmemMoveable, byteLen)
	if hMem == 0 {
		return false
	}
	ptr, _, _ := pGlobalLock.Call(hMem)
	if ptr == 0 {
		return false
	}
	dst := unsafe.Slice((*uint16)(osPtr(ptr)), len(u))
	copy(dst, u)
	_, _, _ = pGlobalUnlock.Call(hMem)

	ok, _, _ := pOpenClipboard.Call(hwnd)
	if ok == 0 {
		return false
	}
	defer func() { _, _, _ = pCloseClipboard.Call() }()
	_, _, _ = pEmptyClipboard.Call()
	r, _, _ := pSetClipboardData.Call(cfUnicodeText, hMem)
	return r != 0
}

// GetClipboardText reads UTF-16 text from the native Windows clipboard with strict GlobalSize bounds.
func GetClipboardText(hwnd uintptr) string {
	ok, _, _ := pOpenClipboard.Call(hwnd)
	if ok == 0 {
		return ""
	}
	defer func() { _, _, _ = pCloseClipboard.Call() }()
	hData, _, _ := pGetClipboardData.Call(cfUnicodeText)
	if hData == 0 {
		return ""
	}
	byteSize, _, _ := pGlobalSize.Call(hData)
	maxUnits := int(byteSize / 2)
	if maxUnits <= 0 {
		return ""
	}
	if maxUnits > 128*1024 {
		maxUnits = 128 * 1024
	}
	ptr, _, _ := pGlobalLock.Call(hData)
	if ptr == 0 {
		return ""
	}
	defer func() { _, _, _ = pGlobalUnlock.Call(hData) }()

	src := unsafe.Slice((*uint16)(osPtr(ptr)), maxUnits)
	n := 0
	for n < len(src) && src[n] != 0 {
		n++
	}
	return string(utf16.Decode(src[:n]))
}

// ---- Reusable Offscreen 32bpp DIBSection + Pixel SDF Antialiased Rasterizer ----

type backBuffer struct {
	dc     uintptr
	bmp    uintptr
	oldBmp uintptr
	w, h   int32
	pixels []uint32
}

func (b *backBuffer) ensure(refDC uintptr, w, h int32, onBeforeRelease func()) (bool, bool) {
	if w <= 0 || h <= 0 {
		return false, false
	}
	if b.dc != 0 && b.w == w && b.h == h {
		return true, false
	}
	if onBeforeRelease != nil {
		onBeforeRelease()
	}
	b.release()

	dc, _, _ := pCreateCompatibleDC.Call(refDC)
	if dc == 0 {
		return false, true
	}
	bmi := bitmapInfo{
		BmiHeader: bitmapInfoHeader{
			BiSize:        uint32(unsafe.Sizeof(bitmapInfoHeader{})),
			BiWidth:       w,
			BiHeight:      -h, // top-down DIB matching screen Y axis
			BiPlanes:      1,
			BiBitCount:    32,
			BiCompression: biRGB,
		},
	}
	var bits unsafe.Pointer
	bmp, _, _ := pCreateDIBSection.Call(dc, uintptr(unsafe.Pointer(&bmi)), dibRGBColors, uintptr(unsafe.Pointer(&bits)), 0, 0)
	runtime.KeepAlive(&bmi)
	if bmp == 0 || bits == nil {
		_, _, _ = pDeleteDC.Call(dc)
		return false, true
	}
	old, _, _ := pSelectObject.Call(dc, bmp)
	b.dc = dc
	b.bmp = bmp
	b.oldBmp = old
	b.w = w
	b.h = h
	b.pixels = unsafe.Slice((*uint32)(bits), int(w)*int(h))
	return true, true
}

func (b *backBuffer) release() {
	if b.dc != 0 {
		if b.oldBmp != 0 {
			_, _, _ = pSelectObject.Call(b.dc, b.oldBmp)
		}
		if b.bmp != 0 {
			_, _, _ = pDeleteObject.Call(b.bmp)
		}
		_, _, _ = pDeleteDC.Call(b.dc)
	}
	b.dc, b.bmp, b.oldBmp, b.w, b.h, b.pixels = 0, 0, 0, 0, 0, nil
}

func (b *backBuffer) clear(col uint32) {
	px := b.pixels
	opaque := col | 0xFF000000
	for i := range px {
		px[i] = opaque
	}
}

func blendPixel(dst uint32, col uint32, cov float32) uint32 {
	if cov <= 0 {
		return dst
	}
	sa := float32((col>>24)&0xFF) / 255.0 * cov
	if sa <= 0 {
		return dst
	}
	if sa >= 0.999 {
		return 0xFF000000 | (col & 0x00FFFFFF)
	}
	dr := float32((dst >> 16) & 0xFF)
	dg := float32((dst >> 8) & 0xFF)
	db := float32(dst & 0xFF)
	sr := float32((col >> 16) & 0xFF)
	sg := float32((col >> 8) & 0xFF)
	sb := float32(col & 0xFF)
	inv := 1.0 - sa
	r := uint32(sr*sa + dr*inv + 0.5)
	g := uint32(sg*sa + dg*inv + 0.5)
	bl := uint32(sb*sa + db*inv + 0.5)
	return 0xFF000000 | (r << 16) | (g << 8) | bl
}

func lerpColor(c0, c1 uint32, t float32) uint32 {
	if t <= 0 {
		return c0
	}
	if t >= 1 {
		return c1
	}
	a := uint32(float32((c0>>24)&0xFF)*(1-t) + float32((c1>>24)&0xFF)*t + 0.5)
	r := uint32(float32((c0>>16)&0xFF)*(1-t) + float32((c1>>16)&0xFF)*t + 0.5)
	g := uint32(float32((c0>>8)&0xFF)*(1-t) + float32((c1>>8)&0xFF)*t + 0.5)
	b := uint32(float32(c0&0xFF)*(1-t) + float32(c1&0xFF)*t + 0.5)
	return (a << 24) | (r << 16) | (g << 8) | b
}

func roundRectSDF(px, py, cx, cy, hw, hh, r float32) float32 {
	dx := float32(math.Abs(float64(px-cx))) - hw + r
	dy := float32(math.Abs(float64(py-cy))) - hh + r
	ox := dx
	if ox < 0 {
		ox = 0
	}
	oy := dy
	if oy < 0 {
		oy = 0
	}
	in := dx
	if dy > in {
		in = dy
	}
	if in > 0 {
		in = 0
	}
	return float32(math.Hypot(float64(ox), float64(oy))) + in - r
}

func (b *backBuffer) fillRoundRect(x, y, w, h, radius int32, col uint32) {
	b.fillRoundRectGrad(x, y, w, h, radius, col, col)
}

func (b *backBuffer) fillRoundRectGrad(x, y, w, h, radius int32, colLeft, colRight uint32) {
	if w <= 0 || h <= 0 {
		return
	}
	r := float32(radius)
	if r > float32(w)/2 {
		r = float32(w) / 2
	}
	if r > float32(h)/2 {
		r = float32(h) / 2
	}
	cx := float32(x) + float32(w)/2
	cy := float32(y) + float32(h)/2
	hw := float32(w) / 2
	hh := float32(h) / 2

	x0 := maxI32(0, x-1)
	y0 := maxI32(0, y-1)
	x1 := minI32(b.w, x+w+1)
	y1 := minI32(b.h, y+h+1)

	fw := float32(w)
	for py := y0; py < y1; py++ {
		row := int(py) * int(b.w)
		fy := float32(py) + 0.5
		for px := x0; px < x1; px++ {
			fx := float32(px) + 0.5
			d := roundRectSDF(fx, fy, cx, cy, hw, hh, r)
			if d < 0.7 {
				cov := 0.5 - d
				if cov > 1 {
					cov = 1
				}
				if cov > 0 {
					c := colLeft
					if colLeft != colRight {
						t := (fx - float32(x)) / fw
						c = lerpColor(colLeft, colRight, t)
					}
					b.pixels[row+int(px)] = blendPixel(b.pixels[row+int(px)], c, cov)
				}
			}
		}
	}
}

func (b *backBuffer) strokeRoundRect(x, y, w, h, radius int32, stroke float32, col uint32) {
	if w <= 0 || h <= 0 || stroke <= 0 {
		return
	}
	r := float32(radius)
	if r > float32(w)/2 {
		r = float32(w) / 2
	}
	if r > float32(h)/2 {
		r = float32(h) / 2
	}
	cx := float32(x) + float32(w)/2
	cy := float32(y) + float32(h)/2
	hw := float32(w) / 2
	hh := float32(h) / 2

	x0 := maxI32(0, x-2)
	y0 := maxI32(0, y-2)
	x1 := minI32(b.w, x+w+2)
	y1 := minI32(b.h, y+h+2)

	halfT := stroke * 0.5
	for py := y0; py < y1; py++ {
		row := int(py) * int(b.w)
		fy := float32(py) + 0.5
		for px := x0; px < x1; px++ {
			fx := float32(px) + 0.5
			d := roundRectSDF(fx, fy, cx, cy, hw, hh, r)
			dist := float32(math.Abs(float64(d))) - halfT
			if dist < 0.75 {
				cov := 0.65 - dist
				if cov > 1 {
					cov = 1
				}
				if cov > 0 {
					b.pixels[row+int(px)] = blendPixel(b.pixels[row+int(px)], col, cov)
				}
			}
		}
	}
}

func (b *backBuffer) fillCircle(cx, cy, radius float32, col uint32) {
	x0 := maxI32(0, int32(cx-radius-2))
	y0 := maxI32(0, int32(cy-radius-2))
	x1 := minI32(b.w, int32(cx+radius+2)+1)
	y1 := minI32(b.h, int32(cy+radius+2)+1)
	for py := y0; py < y1; py++ {
		row := int(py) * int(b.w)
		fy := float32(py) + 0.5
		for px := x0; px < x1; px++ {
			fx := float32(px) + 0.5
			d := float32(math.Hypot(float64(fx-cx), float64(fy-cy))) - radius
			if d < 0.7 {
				cov := 0.5 - d
				if cov > 1 {
					cov = 1
				}
				if cov > 0 {
					b.pixels[row+int(px)] = blendPixel(b.pixels[row+int(px)], col, cov)
				}
			}
		}
	}
}

func (b *backBuffer) fillRect(x, y, w, h int32, col uint32) {
	x0 := maxI32(0, x)
	y0 := maxI32(0, y)
	x1 := minI32(b.w, x+w)
	y1 := minI32(b.h, y+h)
	for py := y0; py < y1; py++ {
		row := int(py) * int(b.w)
		for px := x0; px < x1; px++ {
			b.pixels[row+int(px)] = blendPixel(b.pixels[row+int(px)], col, 1)
		}
	}
}

func (b *backBuffer) drawLineAA(x1, y1, x2, y2, thickness float32, col uint32, clip rect) {
	clip.Left = maxI32(0, clip.Left)
	clip.Top = maxI32(0, clip.Top)
	clip.Right = minI32(b.w, clip.Right)
	clip.Bottom = minI32(b.h, clip.Bottom)
	if clip.Right <= clip.Left || clip.Bottom <= clip.Top {
		return
	}

	minX := maxI32(clip.Left, int32(minF32(x1, x2)-thickness-2))
	maxX := minI32(clip.Right, int32(maxF32(x1, x2)+thickness+2)+1)
	minY := maxI32(clip.Top, int32(minF32(y1, y2)-thickness-2))
	maxY := minI32(clip.Bottom, int32(maxF32(y1, y2)+thickness+2)+1)

	dx, dy := x2-x1, y2-y1
	lenSq := dx*dx + dy*dy
	halfT := thickness * 0.5

	for py := minY; py < maxY; py++ {
		row := int(py) * int(b.w)
		fy := float32(py) + 0.5
		for px := minX; px < maxX; px++ {
			fx := float32(px) + 0.5
			var dist float32
			if lenSq < 1e-4 {
				dist = float32(math.Hypot(float64(fx-x1), float64(fy-y1)))
			} else {
				t := ((fx-x1)*dx + (fy-y1)*dy) / lenSq
				if t < 0 {
					t = 0
				} else if t > 1 {
					t = 1
				}
				projX := x1 + t*dx
				projY := y1 + t*dy
				dist = float32(math.Hypot(float64(fx-projX), float64(fy-projY)))
			}
			edge := dist - halfT
			if edge < 0.75 {
				cov := 0.65 - edge
				if cov > 1 {
					cov = 1
				}
				if cov > 0 {
					idx := row + int(px)
					if uint(idx) < uint(len(b.pixels)) {
						b.pixels[idx] = blendPixel(b.pixels[idx], col, cov)
					}
				}
			}
		}
	}
}

// fillCurveArea shades the vertical gradient fill beneath a piecewise-linear curve down to baseY.
func (b *backBuffer) fillCurveArea(xs, ys []float32, baseY float32, topCol, botCol uint32, clip rect) {
	if len(xs) < 2 || len(xs) != len(ys) {
		return
	}
	clip.Left = maxI32(0, clip.Left)
	clip.Top = maxI32(0, clip.Top)
	clip.Right = minI32(b.w, clip.Right)
	clip.Bottom = minI32(b.h, clip.Bottom)
	if clip.Right <= clip.Left || clip.Bottom <= clip.Top {
		return
	}
	yEnd := minI32(clip.Bottom, int32(baseY))
	for i := 0; i < len(xs)-1; i++ {
		x0f, y0f := xs[i], ys[i]
		x1f, y1f := xs[i+1], ys[i+1]
		if x1f <= x0f {
			continue
		}
		sx := maxI32(clip.Left, int32(math.Floor(float64(x0f))))
		ex := minI32(clip.Right, int32(math.Ceil(float64(x1f))))
		span := x1f - x0f
		for px := sx; px < ex; px++ {
			t := (float32(px) + 0.5 - x0f) / span
			if t < 0 {
				t = 0
			} else if t > 1 {
				t = 1
			}
			yCurve := y0f + t*(y1f-y0f)
			yStart := maxI32(clip.Top, int32(math.Floor(float64(yCurve))))
			h := baseY - yCurve
			if h < 1 {
				h = 1
			}
			for py := yStart; py < yEnd; py++ {
				cov := float32(py) + 0.5 - yCurve
				if cov <= 0 {
					continue
				}
				if cov > 1 {
					cov = 1
				}
				vT := (float32(py) - yCurve) / h
				c := lerpColor(topCol, botCol, vT)
				idx := int(py)*int(b.w) + int(px)
				if uint(idx) < uint(len(b.pixels)) {
					b.pixels[idx] = blendPixel(b.pixels[idx], c, cov)
				}
			}
		}
	}
}

// ---- GDI+ Antialiased ClearType Text Engine ----

type fontSet struct {
	graphics uintptr
	fmtLeft  uintptr
	fmtCent  uintptr
	fmtRight uintptr

	fTitle uintptr
	fBold  uintptr
	fBody  uintptr
	fSmall uintptr
	fHero  uintptr
	fMono  uintptr
	fMonoB uintptr
}

func initFontSet(hdc uintptr, dpi int32) *fontSet {
	fs := &fontSet{}
	_, _, _ = pGdipCreateFromHDC.Call(hdc, uintptr(unsafe.Pointer(&fs.graphics)))
	if fs.graphics != 0 {
		_, _, _ = pGdipSetSmoothingMode.Call(fs.graphics, 4)     // SmoothingModeAntiAlias
		_, _, _ = pGdipSetTextRenderingHint.Call(fs.graphics, 5) // TextRenderingHintClearTypeGridFit
	}
	fs.fmtLeft = newStringFormat(0, 1)
	fs.fmtCent = newStringFormat(1, 1)
	fs.fmtRight = newStringFormat(2, 1)

	scale := func(px int32) int32 {
		v := (px * dpi) / 96
		if v < 10 {
			v = 10
		}
		return -v
	}
	fs.fTitle = createGDIPFont(hdc, "Microsoft YaHei UI", scale(17), 700)
	fs.fHero = createGDIPFont(hdc, "Microsoft YaHei UI", scale(15), 700)
	fs.fBold = createGDIPFont(hdc, "Microsoft YaHei UI", scale(13), 700)
	fs.fBody = createGDIPFont(hdc, "Microsoft YaHei UI", scale(13), 400)
	fs.fSmall = createGDIPFont(hdc, "Microsoft YaHei UI", scale(11), 400)
	fs.fMono = createGDIPFont(hdc, "Consolas", scale(12), 400)
	fs.fMonoB = createGDIPFont(hdc, "Consolas", scale(13), 700)
	return fs
}

func newStringFormat(align, lineAlign int32) uintptr {
	var fmtH uintptr
	// StringFormatFlagsNoWrap = 0x00001000
	_, _, _ = pGdipCreateStringFormat.Call(0x00001000, 0, uintptr(unsafe.Pointer(&fmtH)))
	if fmtH != 0 {
		_, _, _ = pGdipSetStringFormatAlign.Call(fmtH, uintptr(align))
		_, _, _ = pGdipSetStringFormatLineAlign.Call(fmtH, uintptr(lineAlign))
		_, _, _ = pGdipSetStringFormatTrimming.Call(fmtH, 3) // StringTrimmingEllipsisCharacter
	}
	return fmtH
}

func createGDIPFont(hdc uintptr, face string, negHeight, weight int32) uintptr {
	lf := logFontW{
		LfHeight:  negHeight,
		LfWeight:  weight,
		LfCharSet: 1, // DEFAULT_CHARSET
		LfQuality: 5, // CLEARTYPE_QUALITY
	}
	copyUTF16(lf.LfFaceName[:], face)
	var f uintptr
	_, _, _ = pGdipCreateFontFromLogfontW.Call(hdc, uintptr(unsafe.Pointer(&lf)), uintptr(unsafe.Pointer(&f)))
	runtime.KeepAlive(&lf)
	if f == 0 {
		copyUTF16(lf.LfFaceName[:], "Segoe UI")
		_, _, _ = pGdipCreateFontFromLogfontW.Call(hdc, uintptr(unsafe.Pointer(&lf)), uintptr(unsafe.Pointer(&f)))
		runtime.KeepAlive(&lf)
	}
	return f
}

func (fs *fontSet) flush() {
	if fs != nil && fs.graphics != 0 {
		_, _, _ = pGdipFlush.Call(fs.graphics, 1) // FlushIntentionSync
	}
}

func (fs *fontSet) destroy() {
	if fs == nil {
		return
	}
	for _, f := range []uintptr{fs.fTitle, fs.fHero, fs.fBold, fs.fBody, fs.fSmall, fs.fMono, fs.fMonoB} {
		if f != 0 {
			_, _, _ = pGdipDeleteFont.Call(f)
		}
	}
	for _, sf := range []uintptr{fs.fmtLeft, fs.fmtCent, fs.fmtRight} {
		if sf != 0 {
			_, _, _ = pGdipDeleteStringFormat.Call(sf)
		}
	}
	if fs.graphics != 0 {
		_, _, _ = pGdipDeleteGraphics.Call(fs.graphics)
		fs.graphics = 0
	}
}

func (fs *fontSet) drawText(font, strFmt uintptr, r rect, col uint32, text string) {
	if fs == nil || fs.graphics == 0 || font == 0 || text == "" {
		return
	}
	var brush uintptr
	_, _, _ = pGdipCreateSolidFill.Call(uintptr(col), uintptr(unsafe.Pointer(&brush)))
	if brush == 0 {
		return
	}
	defer func() { _, _, _ = pGdipDeleteBrush.Call(brush) }()

	u := utf16.Encode([]rune(text))
	if len(u) == 0 {
		return
	}
	rf := rectF{
		X:      float32(r.Left),
		Y:      float32(r.Top),
		Width:  float32(r.width()),
		Height: float32(r.height()),
	}
	_, _, _ = pGdipDrawString.Call(
		fs.graphics,
		uintptr(unsafe.Pointer(&u[0])),
		uintptr(int32(len(u))),
		font,
		uintptr(unsafe.Pointer(&rf)),
		strFmt,
		brush,
	)
	runtime.KeepAlive(u)
	runtime.KeepAlive(&rf)
}

func maxI32(a, b int32) int32 {
	if a > b {
		return a
	}
	return b
}

func minI32(a, b int32) int32 {
	if a < b {
		return a
	}
	return b
}

func minF32(a, b float32) float32 {
	if a < b {
		return a
	}
	return b
}

func maxF32(a, b float32) float32 {
	if a > b {
		return a
	}
	return b
}
