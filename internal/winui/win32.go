//go:build windows

package winui

import (
	"os"
	"runtime"
	"syscall"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	windowClassName = "KestrelProWndClass"
	singleMutexName = `Local\KestrelPro_SingleInstance`

	wmAppWake    = 0x8001 // WM_APP + 1
	wmAppTray    = 0x8002 // WM_APP + 2
	wmAppQuit    = 0x8003 // WM_APP + 3
	wmAppRefresh = 0x8004 // WM_APP + 4

	wmCreate              = 0x0001
	wmDestroy             = 0x0002
	wmSize                = 0x0005
	wmSetFocus            = 0x0007
	wmPaint               = 0x000F
	wmClose               = 0x0010
	wmQueryEndSession     = 0x0011
	wmEraseBkgnd          = 0x0014
	wmEndSession          = 0x0016
	wmPowerBroadcast      = 0x0218
	pbtApmSuspend         = 0x0004
	pbtApmResumeSuspend   = 0x0007
	pbtApmResumeAutomatic = 0x0012
	wmGetMinMaxInfo       = 0x0024
	wmSetIcon             = 0x0080
	wmKeyDown             = 0x0100
	wmChar                = 0x0102
	wmCommand             = 0x0111
	wmTimer               = 0x0113
	wmMouseMove           = 0x0200
	wmLButtonDown         = 0x0201
	wmLButtonUp           = 0x0202
	wmLButtonDblClk       = 0x0203
	wmRButtonUp           = 0x0205
	wmMouseWheel          = 0x020A
	wmDpiChanged          = 0x02E0
	wmContextMenu         = 0x007B

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
	dwmapi = windows.NewLazySystemDLL("dwmapi.dll")
	shell32 = windows.NewLazySystemDLL("shell32.dll")
	ole32   = windows.NewLazySystemDLL("ole32.dll")

	pCoInitializeEx                = ole32.NewProc("CoInitializeEx")
	pCoUninitialize                = ole32.NewProc("CoUninitialize")
	pShellExecuteW                 = shell32.NewProc("ShellExecuteW")
	pCreateSolidBrush              = gdi32.NewProc("CreateSolidBrush")
	pFillRect                      = user32.NewProc("FillRect")

	pGetModuleHandleW              = kernel32.NewProc("GetModuleHandleW")
	pOpenMutexW                    = kernel32.NewProc("OpenMutexW")
	pSetProcessShutdownParameters  = kernel32.NewProc("SetProcessShutdownParameters")
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
	pDestroyWindow                 = user32.NewProc("DestroyWindow")
	pPostMessageW                  = user32.NewProc("PostMessageW")
	pSendMessageW                  = user32.NewProc("SendMessageW")
	pInvalidateRect                = user32.NewProc("InvalidateRect")
	pBeginPaint                    = user32.NewProc("BeginPaint")
	pEndPaint                      = user32.NewProc("EndPaint")
	pGetClientRect                 = user32.NewProc("GetClientRect")
	pSetTimer                      = user32.NewProc("SetTimer")
	pKillTimer                     = user32.NewProc("KillTimer")
	pLoadCursorW                   = user32.NewProc("LoadCursorW")
	pLoadIconW                     = user32.NewProc("LoadIconW")
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

func applyLightWindowChrome(hwnd uintptr) {
	dark := uint32(0)
	_, _, _ = pDwmSetWindowAttribute.Call(hwnd, dwmwaUseImmersiveDarkMode, uintptr(unsafe.Pointer(&dark)), unsafe.Sizeof(dark))
	round := uint32(dwmwcpRound)
	_, _, _ = pDwmSetWindowAttribute.Call(hwnd, dwmwaWindowCornerPreference, uintptr(unsafe.Pointer(&round)), unsafe.Sizeof(round))
}

// AcquireSingleInstance creates the named single-instance mutex. If an earlier
// instance already owns it, this sends the wakeup message to its window and
// returns (0, false) so the caller can exit cleanly.
func AcquireSingleInstance() (windows.Handle, bool) {
	if os.Getenv("KSL_NO_SINGLE_INSTANCE") == "1" || os.Getenv("GFT_NO_SINGLE_INSTANCE") == "1" {
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

// SetHighestAppShutdownPriority requests Windows notify Kestrel-Pro first among user applications
// during shutdown/reboot so WM_QUERYENDSESSION can cleanly restore system proxy before session teardown.
func SetHighestAppShutdownPriority() {
	_, _, _ = pSetProcessShutdownParameters.Call(0x3FF, 0)
}

// IsAnotherInstanceRunning reports whether a live Kestrel-Pro instance currently holds the single-instance mutex.
func IsAnotherInstanceRunning() bool {
	const mutexSynchronize = 0x00100000
	mutPtr := utf16Ptr(singleMutexName)
	h, _, _ := pOpenMutexW.Call(mutexSynchronize, 0, uintptr(unsafe.Pointer(mutPtr)))
	runtime.KeepAlive(mutPtr)
	if h != 0 {
		_ = windows.CloseHandle(windows.Handle(h))
		return true
	}
	return false
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
