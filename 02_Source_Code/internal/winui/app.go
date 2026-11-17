//go:build windows

package winui

import (
	"fmt"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"ghostframe/internal/client"
)

const (
	timerRefreshID = 1

	// Palette (GhostFrame Obsidian Dark)
	colBg         uint32 = 0xFF070B12
	colCard       uint32 = 0xFF0F172A
	colCardAlt    uint32 = 0xFF131D33
	colBorder     uint32 = 0xFF1E293B
	colBorderHi   uint32 = 0xFF334155
	colTextMain   uint32 = 0xFFF1F5F9
	colTextSub    uint32 = 0xFF94A3B8
	colTextMuted  uint32 = 0xFF64748B
	colEmerald    uint32 = 0xFF10B981
	colEmeraldDim uint32 = 0x4410B981
	colCyan       uint32 = 0xFF06B6D4
	colCyanDim    uint32 = 0x3A06B6D4
	colSky        uint32 = 0xFF38BDF8
	colAmber      uint32 = 0xFFF59E0B
	colRed        uint32 = 0xFFEF4444
	colRedDim     uint32 = 0x33EF4444
	colBtnIdleA   uint32 = 0xFF059669
	colBtnIdleB   uint32 = 0xFF0891B2
	colBtnStopA   uint32 = 0xFFDC2626
	colBtnStopB   uint32 = 0xFFB91C1C
	colBtnWaitA   uint32 = 0xFFD97706
	colBtnWaitB   uint32 = 0xFFB45309
)

type hitKind int

const (
	hitNone hitKind = iota
	hitConnect
	hitPing
	hitImport
	hitNodeDrop
	hitNodeDelete
	hitRouteRule
	hitRouteGlobal
	hitRouteCore
	hitTransAuto
	hitTransQUIC
	hitTransTCP
	hitCopyClash
	hitCopyLink
	hitClearLogs
	hitNodeOption
)

type hitBox struct {
	id   hitKind
	idx  int
	rect rect
}

type appUI struct {
	eng  *client.Engine
	hwnd uintptr
	tray *trayManager

	dpi   int32
	buf   backBuffer
	fonts *fontSet

	hArrow uintptr
	hHand  uintptr
	hIcon  uintptr

	hoverID  hitKind
	hoverIdx int
	pressed  hitKind
	hits     []hitBox

	nodeDropOpen bool
	logScroll    int
	autoScroll   bool
	lastLogCount int

	toastMu    sync.Mutex
	toastText  string
	toastErr   bool
	toastUntil time.Time

	shutOnce sync.Once
}

var (
	activeAppMu sync.Mutex
	activeApp   *appUI
)

// Run launches the pure-Go native Win32/GDI+ console window and system tray
// message loop, blocking until the user selects Exit or Windows shuts down.
func Run(eng *client.Engine) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	enablePerMonitorDPI()

	var gdipToken uintptr
	in := gdiplusStartupInput{GdiplusVersion: 1}
	_, _, _ = pGdiplusStartup.Call(uintptr(unsafe.Pointer(&gdipToken)), uintptr(unsafe.Pointer(&in)), 0)
	defer func() {
		if gdipToken != 0 {
			_, _, _ = pGdiplusShutdown.Call(gdipToken)
		}
	}()

	hInst, _, _ := pGetModuleHandleW.Call(0)
	hArrow, _, _ := pLoadCursorW.Call(0, idcArrow)
	hHand, _, _ := pLoadCursorW.Call(0, idcHand)
	appIcon := CreateVectorIcon(client.StateDisconnected)

	app := &appUI{
		eng:        eng,
		dpi:        96,
		hArrow:     hArrow,
		hHand:      hHand,
		hIcon:      appIcon,
		autoScroll: true,
	}

	activeAppMu.Lock()
	activeApp = app
	activeAppMu.Unlock()
	defer func() {
		activeAppMu.Lock()
		activeApp = nil
		activeAppMu.Unlock()
	}()

	clsPtr := utf16Ptr(windowClassName)
	wcx := wndClassExW{
		CbSize:        uint32(unsafe.Sizeof(wndClassExW{})),
		Style:         csHRedraw | csVRedraw | csDblClks,
		LpfnWndProc:   syscall.NewCallback(wndProc),
		HInstance:     hInst,
		HIcon:         appIcon,
		HCursor:       hArrow,
		LpszClassName: clsPtr,
		HIconSm:       appIcon,
	}
	atom, _, err := pRegisterClassExW.Call(uintptr(unsafe.Pointer(&wcx)))
	runtime.KeepAlive(&wcx)
	runtime.KeepAlive(clsPtr)
	if atom == 0 {
		return fmt.Errorf("RegisterClassExW failed: %v", err)
	}

	// Center initial 920x640 window using primary monitor dimensions.
	sysDPI := int32(96)
	sw, _, _ := pGetSystemMetrics.Call(0)
	sh, _, _ := pGetSystemMetrics.Call(1)
	winW := int32(920)
	winH := int32(640)
	posX := uintptr(cwUseDefault)
	posY := uintptr(cwUseDefault)
	if sw > uintptr(winW) && sh > uintptr(winH) {
		posX = uintptr(int32(sw-uintptr(winW)) / 2)
		posY = uintptr(int32(sh-uintptr(winH)) / 2)
	}
	_ = sysDPI

	titlePtr := utf16Ptr("GhostFrame-Pro v3.2.1")
	hwnd, _, err := pCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(clsPtr)),
		uintptr(unsafe.Pointer(titlePtr)),
		wsOverlappedWindow|wsClipChildren,
		posX,
		posY,
		uintptr(winW),
		uintptr(winH),
		0,
		0,
		hInst,
		0,
	)
	runtime.KeepAlive(clsPtr)
	runtime.KeepAlive(titlePtr)
	if hwnd == 0 {
		return fmt.Errorf("CreateWindowExW failed: %v", err)
	}
	app.hwnd = hwnd
	app.dpi = windowDPI(hwnd)
	if app.dpi != 96 {
		scaledW := (winW * app.dpi) / 96
		scaledH := (winH * app.dpi) / 96
		if sw > uintptr(scaledW) && sh > uintptr(scaledH) {
			posX = uintptr(int32(sw-uintptr(scaledW)) / 2)
			posY = uintptr(int32(sh-uintptr(scaledH)) / 2)
		}
		_, _, _ = pSetWindowPos.Call(hwnd, 0, posX, posY, uintptr(scaledW), uintptr(scaledH), swpNoZOrder)
	}

	applyDarkWindowChrome(hwnd)
	if appIcon != 0 {
		_, _, _ = pSendMessageW.Call(hwnd, wmSetIcon, iconBig, appIcon)
		_, _, _ = pSendMessageW.Call(hwnd, wmSetIcon, iconSmall, appIcon)
	}

	app.tray = newTrayManager(hwnd)
	_, _, _ = pShowWindow.Call(hwnd, swShow)
	_, _, _ = pUpdateWindow.Call(hwnd)
	_, _, _ = pSetTimer.Call(hwnd, timerRefreshID, 450, 0)

	var msg msgW
	for {
		r, _, _ := pGetMessageW.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0)
		if int32(r) <= 0 {
			break
		}
		_, _, _ = pTranslateMessage.Call(uintptr(unsafe.Pointer(&msg)))
		_, _, _ = pDispatchMessageW.Call(uintptr(unsafe.Pointer(&msg)))
	}
	app.cleanup()
	return nil
}

func getApp() *appUI {
	activeAppMu.Lock()
	a := activeApp
	activeAppMu.Unlock()
	return a
}

func wndProc(hwnd uintptr, msg uint32, wParam, lParam uintptr) uintptr {
	a := getApp()
	if a == nil {
		r, _, _ := pDefWindowProcW.Call(hwnd, uintptr(msg), wParam, lParam)
		return r
	}
	switch msg {
	case wmEraseBkgnd:
		return 1

	case wmGetMinMaxInfo:
		mmi := (*minMaxInfo)(osPtr(lParam))
		mmi.MinTrackSize.X = a.s(780)
		mmi.MinTrackSize.Y = a.s(560)
		return 0

	case wmDpiChanged:
		newDPI := int32(wParam & 0xFFFF)
		if newDPI >= 96 {
			a.dpi = newDPI
			if a.fonts != nil {
				a.fonts.destroy()
				a.fonts = nil
			}
			rc := (*rect)(osPtr(lParam))
			_, _, _ = pSetWindowPos.Call(hwnd, 0, uintptr(rc.Left), uintptr(rc.Top), uintptr(rc.width()), uintptr(rc.height()), swpNoZOrder|swpNoActivate)
			a.invalidate()
		}
		return 0

	case wmSize:
		a.invalidate()
		return 0

	case wmTimer:
		if wParam == timerRefreshID {
			a.tray.update(a.eng.Status())
			vis, _, _ := pIsWindowVisible.Call(hwnd)
			if vis != 0 {
				a.invalidate()
			}
		}
		return 0

	case wmPaint:
		var ps paintStruct
		hdc, _, _ := pBeginPaint.Call(hwnd, uintptr(unsafe.Pointer(&ps)))
		a.paint(hdc)
		_, _, _ = pEndPaint.Call(hwnd, uintptr(unsafe.Pointer(&ps)))
		return 0

	case wmMouseMove:
		x := int32(int16(lParam & 0xFFFF))
		y := int32(int16((lParam >> 16) & 0xFFFF))
		hid, hidx := a.hitTest(x, y)
		if hid != hitNone {
			_, _, _ = pSetCursor.Call(a.hHand)
		} else {
			_, _, _ = pSetCursor.Call(a.hArrow)
		}
		if hid != a.hoverID || hidx != a.hoverIdx {
			a.hoverID = hid
			a.hoverIdx = hidx
			a.invalidate()
		}
		return 0

	case wmLButtonDown:
		x := int32(int16(lParam & 0xFFFF))
		y := int32(int16((lParam >> 16) & 0xFFFF))
		hid, _ := a.hitTest(x, y)
		a.pressed = hid
		a.invalidate()
		return 0

	case wmLButtonUp:
		x := int32(int16(lParam & 0xFFFF))
		y := int32(int16((lParam >> 16) & 0xFFFF))
		hid, hidx := a.hitTest(x, y)
		wasPressed := a.pressed
		a.pressed = hitNone
		if hid != hitNone && hid == wasPressed {
			a.handleClick(hid, hidx)
		} else if a.nodeDropOpen && hid != hitNodeDrop && hid != hitNodeOption {
			a.nodeDropOpen = false
			a.invalidate()
		}
		return 0

	case wmMouseWheel:
		delta := int16((wParam >> 16) & 0xFFFF)
		lines := int(delta) / 120 * 3
		if lines == 0 {
			if delta > 0 {
				lines = 1
			} else {
				lines = -1
			}
		}
		a.scrollLogs(-lines)
		return 0

	case wmKeyDown:
		if wParam == 'V' {
			ctrl, _, _ := pGetKeyState.Call(0x11)
			if (uint16(ctrl) & 0x8000) != 0 {
				a.importFromClipboard()
				return 0
			}
		}
		if wParam == 0x1B && a.nodeDropOpen { // Escape closes dropdown
			a.nodeDropOpen = false
			a.invalidate()
			return 0
		}
		return 0

	case wmAppWake:
		a.showAndFocus()
		return 0

	case wmAppRefresh:
		a.invalidate()
		return 0

	case wmAppTray:
		ev := uint32(lParam & 0xFFFF)
		switch ev {
		case wmLButtonDblClk, wmLButtonUp, 0x0400: // NIN_SELECT
			a.showAndFocus()
		case wmRButtonUp, wmContextMenu:
			a.tray.showContextMenu(
				a.eng,
				func() { a.showAndFocus() },
				func() { a.importFromClipboard() },
				func() { _, _, _ = pPostMessageW.Call(hwnd, wmAppQuit, 0, 0) },
				func(msg string, isErr bool) { a.setToast(msg, isErr) },
				func() { a.postRefresh() },
			)
		}
		return 0

	case wmAppQuit:
		a.cleanup()
		_, _, _ = pPostQuitMessage.Call(0)
		return 0

	case wmClose:
		// Hide to system tray instead of killing the background proxy tunnel!
		a.nodeDropOpen = false
		_, _, _ = pShowWindow.Call(hwnd, swHide)
		return 0

	case wmQueryEndSession:
		return 1

	case wmEndSession:
		if wParam != 0 {
			a.cleanup()
		}
		return 0

	case wmDestroy:
		a.cleanup()
		_, _, _ = pPostQuitMessage.Call(0)
		return 0
	}

	r, _, _ := pDefWindowProcW.Call(hwnd, uintptr(msg), wParam, lParam)
	return r
}

func (a *appUI) showAndFocus() {
	_, _, _ = pShowWindow.Call(a.hwnd, swShow)
	_, _, _ = pShowWindow.Call(a.hwnd, swRestore)
	_, _, _ = pSetForegroundWindow.Call(a.hwnd)
	a.invalidate()
}

func (a *appUI) cleanup() {
	a.shutOnce.Do(func() {
		if a.hwnd != 0 {
			_, _, _ = pKillTimer.Call(a.hwnd, timerRefreshID)
		}
		if a.tray != nil {
			a.tray.destroy()
		}
		if a.fonts != nil {
			a.fonts.destroy()
			a.fonts = nil
		}
		a.buf.release()
		if a.hIcon != 0 {
			_, _, _ = pDestroyIcon.Call(a.hIcon)
			a.hIcon = 0
		}
		if a.eng != nil {
			a.eng.Close()
		}
	})
}

func (a *appUI) s(px int32) int32 {
	return (px * a.dpi) / 96
}

func (a *appUI) invalidate() {
	if a.hwnd != 0 {
		_, _, _ = pInvalidateRect.Call(a.hwnd, 0, 0)
	}
}

func (a *appUI) postRefresh() {
	if a.hwnd != 0 {
		_, _, _ = pPostMessageW.Call(a.hwnd, wmAppRefresh, 0, 0)
	}
}

func (a *appUI) setToast(msg string, isErr bool) {
	a.toastMu.Lock()
	a.toastText = msg
	a.toastErr = isErr
	a.toastUntil = time.Now().Add(2600 * time.Millisecond)
	a.toastMu.Unlock()
	a.postRefresh()
}

func (a *appUI) hitTest(x, y int32) (hitKind, int) {
	// Check reverse order so dropdown overlays win over underlying controls.
	for i := len(a.hits) - 1; i >= 0; i-- {
		if a.hits[i].rect.contains(x, y) {
			return a.hits[i].id, a.hits[i].idx
		}
	}
	return hitNone, 0
}

func (a *appUI) handleClick(k hitKind, idx int) {
	st := a.eng.Status()
	state := client.ConnState(strVal(st["state"]))
	activeIdx := intVal(st["active_node"])

	switch k {
	case hitConnect:
		if state == client.StateConnected || state == client.StateConnecting {
			a.eng.Disconnect()
			a.setToast("已断开安全隧道", false)
		} else {
			go func() {
				if err := a.eng.Connect(); err != nil {
					a.setToast("连接失败: "+err.Error(), true)
				} else {
					a.setToast("安全隧道已建立", false)
				}
				a.postRefresh()
			}()
		}
	case hitPing:
		go func() {
			pr, err := a.eng.PingNow()
			if err != nil {
				a.setToast("测速失败: "+err.Error(), true)
			} else {
				a.setToast(fmt.Sprintf("延迟 %dms (%s)", pr.RTTMs, pr.Transport), false)
			}
			a.postRefresh()
		}()
	case hitImport:
		a.importFromClipboard()
	case hitNodeDrop:
		a.nodeDropOpen = !a.nodeDropOpen
	case hitNodeOption:
		a.nodeDropOpen = false
		go func(i int) {
			if err := a.eng.SelectNode(i); err != nil {
				a.setToast("切换节点失败: "+err.Error(), true)
			} else {
				a.setToast("已切换并持久化节点", false)
			}
			a.postRefresh()
		}(idx)
	case hitNodeDelete:
		a.nodeDropOpen = false
		if err := a.eng.DeleteNode(activeIdx); err != nil {
			a.setToast("删除节点失败: "+err.Error(), true)
		} else {
			a.setToast("已删除当前节点", false)
		}
	case hitRouteRule:
		_ = a.eng.SetRouteMode(client.RouteRule)
		a.setToast("模式已切换: Rule (智能分流)", false)
	case hitRouteGlobal:
		_ = a.eng.SetRouteMode(client.RouteGlobal)
		a.setToast("模式已切换: Global (全局代理)", false)
	case hitRouteCore:
		_ = a.eng.SetRouteMode(client.RouteCore)
		a.setToast("模式已切换: Core (仅开放本地端口)", false)
	case hitTransAuto:
		go func() {
			_ = a.eng.SetTransport("auto")
			a.setToast("传输通道: Auto (QUIC+TCP)", false)
			a.postRefresh()
		}()
	case hitTransQUIC:
		go func() {
			_ = a.eng.SetTransport("quic")
			a.setToast("传输通道: QUIC (极速端口跳跃)", false)
			a.postRefresh()
		}()
	case hitTransTCP:
		go func() {
			_ = a.eng.SetTransport("tcp")
			a.setToast("传输通道: TCP (uTLS 强稳健)", false)
			a.postRefresh()
		}()
	case hitCopyClash:
		yaml := a.eng.ClashYAML()
		if SetClipboardText(a.hwnd, yaml) {
			a.setToast("已复制 Clash Meta 配置到剪贴板", false)
		} else {
			a.setToast("写入剪贴板失败", true)
		}
	case hitCopyLink:
		uri := a.eng.LinkURI()
		if uri == "" {
			a.setToast("当前没有可复制的节点链接", true)
		} else if SetClipboardText(a.hwnd, uri) {
			a.setToast("已复制 gft3:// 节点链接到剪贴板", false)
		} else {
			a.setToast("写入剪贴板失败", true)
		}
	case hitClearLogs:
		a.eng.ClearLogs()
		a.logScroll = 0
		a.autoScroll = true
		a.setToast("日志已清空", false)
	}
	a.invalidate()
}

func (a *appUI) importFromClipboard() {
	raw := strings.TrimSpace(GetClipboardText(a.hwnd))
	if raw == "" {
		a.setToast("剪贴板为空，请先复制 gft3:// 链接", true)
		return
	}
	lines := strings.Split(raw, "\n")
	imported := 0
	var lastErr error
	for _, ln := range lines {
		ln = strings.TrimSpace(ln)
		if ln == "" || (!strings.HasPrefix(ln, "gft3://") && !strings.HasPrefix(ln, "gft://")) {
			continue
		}
		if _, err := a.eng.ImportLink(ln, imported == 0); err != nil {
			lastErr = err
		} else {
			imported++
		}
	}
	if imported == 0 {
		if _, err := a.eng.ImportLink(raw, true); err != nil {
			if lastErr != nil {
				err = lastErr
			}
			a.setToast("节点导入失败: "+err.Error(), true)
			return
		}
		imported = 1
	}
	a.setToast(fmt.Sprintf("已导入 %d 个节点并激活", imported), false)
	a.invalidate()
}

func (a *appUI) scrollLogs(deltaLines int) {
	logs := a.eng.Logs()
	if len(logs) == 0 {
		return
	}
	a.logScroll += deltaLines
	if a.logScroll < 0 {
		a.logScroll = 0
	}
	if a.logScroll >= len(logs)-1 {
		a.logScroll = len(logs) - 1
		a.autoScroll = true
	} else {
		a.autoScroll = false
	}
	a.invalidate()
}

func (a *appUI) paint(hdc uintptr) {
	var rc rect
	_, _, _ = pGetClientRect.Call(a.hwnd, uintptr(unsafe.Pointer(&rc)))
	w, h := rc.width(), rc.height()
	ok, recreated := a.buf.ensure(hdc, w, h, func() {
		if a.fonts != nil {
			a.fonts.destroy()
			a.fonts = nil
		}
	})
	if !ok {
		return
	}
	if recreated || a.fonts == nil {
		a.fonts = initFontSet(a.buf.dc, a.dpi)
	}

	st := a.eng.Status()
	logs := a.eng.Logs()
	a.hits = a.hits[:0]

	a.buf.clear(colBg)

	s := a.s
	pad := s(18)
	leftW := s(344)
	if w > s(980) {
		leftW = s(360)
	}

	a.drawHeader(&rc, st, pad)

	topY := s(68)
	leftR := rect{Left: pad, Top: topY, Right: pad + leftW, Bottom: h - s(16)}
	rightR := rect{Left: leftR.Right + s(14), Top: topY, Right: w - pad, Bottom: h - s(16)}

	a.drawHeroCard(rect{Left: leftR.Left, Top: leftR.Top, Right: leftR.Right, Bottom: leftR.Top + s(146)}, st)
	a.drawNodeCard(rect{Left: leftR.Left, Top: leftR.Top + s(158), Right: leftR.Right, Bottom: leftR.Bottom}, st)

	chartH := maxI32(s(175), (rightR.height()-s(12))*50/100)
	chartBot := minI32(rightR.Bottom-s(120), rightR.Top+chartH)
	if chartBot <= rightR.Top+s(110) {
		chartBot = rightR.Top + s(175)
	}
	a.drawTrafficCard(rect{Left: rightR.Left, Top: rightR.Top, Right: rightR.Right, Bottom: chartBot}, st)
	a.drawLogCard(rect{Left: rightR.Left, Top: chartBot + s(12), Right: rightR.Right, Bottom: rightR.Bottom}, logs)

	if a.nodeDropOpen {
		a.drawNodeDropdownOverlay(rect{Left: leftR.Left, Top: leftR.Top + s(158), Right: leftR.Right, Bottom: leftR.Bottom}, st)
	}
	a.drawToast(w, h)

	a.fonts.flush()
	_, _, _ = pBitBlt.Call(hdc, 0, 0, uintptr(w), uintptr(h), a.buf.dc, 0, 0, srcCopy)
}

func (a *appUI) drawHeader(rc *rect, st map[string]any, pad int32) {
	s := a.s
	f := a.fonts
	state := client.ConnState(strVal(st["state"]))
	mode := strVal(st["active_transport"])
	if mode == "" {
		mode = strings.ToUpper(strVal(st["transport_pref"])) + " Standby"
	}
	socksAddr := strVal(st["socks_addr"])
	httpAddr := strVal(st["http_addr"])
	pingMs := intVal(st["ping_ms"])

	var dotCol uint32
	switch state {
	case client.StateConnected:
		dotCol = colEmerald
	case client.StateConnecting:
		dotCol = colAmber
	case client.StateError:
		dotCol = colRed
	default:
		dotCol = colTextMuted
	}
	a.buf.fillCircle(float32(pad+s(9)), float32(s(35)), float32(s(6)), dotCol)
	f.drawText(f.fTitle, f.fmtLeft, rect{pad + s(22), s(16), pad + s(225), s(52)}, colTextMain, "GhostFrame-Pro")

	// Active transport badge
	badgeR := rect{pad + s(192), s(23), pad + s(324), s(47)}
	a.buf.fillRoundRect(badgeR.Left, badgeR.Top, badgeR.width(), badgeR.height(), s(12), colCardAlt)
	a.buf.strokeRoundRect(badgeR.Left, badgeR.Top, badgeR.width(), badgeR.height(), s(12), 1, colBorderHi)
	badgeCol := colSky
	if state == client.StateConnected && strings.HasPrefix(mode, "QUIC") {
		badgeCol = colEmerald
	}
	f.drawText(f.fSmall, f.fmtCent, badgeR, badgeCol, mode)

	// Right header buttons: [Import] [Ping] [Port Pill]
	impR := rect{rc.Right - pad - s(106), s(20), rc.Right - pad, s(50)}
	a.drawButton(impR, hitImport, "导入 gft3://", colCardAlt, colBorderHi, colTextMain)

	pingLabel := "测速"
	if pingMs > 0 {
		pingLabel = fmt.Sprintf("延迟 %dms", pingMs)
	}
	pingR := rect{impR.Left - s(98), s(20), impR.Left - s(8), s(50)}
	pingTextCol := colTextMain
	if pingMs > 0 && pingMs < 150 {
		pingTextCol = colEmerald
	} else if pingMs >= 150 {
		pingTextCol = colAmber
	}
	a.drawButton(pingR, hitPing, pingLabel, colCardAlt, colBorderHi, pingTextCol)

	portText := fmt.Sprintf("S5 %s  ·  HTTP %s", shortPort(socksAddr), shortPort(httpAddr))
	if rc.width() >= s(820) {
		f.drawText(f.fMono, f.fmtRight, rect{badgeR.Right + s(10), s(20), pingR.Left - s(12), s(50)}, colTextSub, portText)
	}
}

func (a *appUI) drawHeroCard(r rect, st map[string]any) {
	s := a.s
	f := a.fonts
	a.drawCard(r)

	state := client.ConnState(strVal(st["state"]))
	lastErr := strVal(st["last_err"])
	pingMs := intVal(st["ping_ms"])
	quicPort := intVal(st["quic_port"])
	conns := intVal(st["active_conns"])
	verify := strings.ToUpper(strVal(st["verify_mode"]))
	if verify == "" {
		verify = "SPKI"
	}

	btnR := rect{r.Left + s(16), r.Top + s(16), r.Right - s(16), r.Top + s(66)}
	var c0, c1 uint32
	var btnText string
	switch state {
	case client.StateConnected:
		c0, c1 = colBtnStopA, colBtnStopB
		btnText = "●  已加密连接 — 点击断开"
	case client.StateConnecting:
		c0, c1 = colBtnWaitA, colBtnWaitB
		btnText = "◌  正在建立双栈隐写通道..."
	default:
		c0, c1 = colBtnIdleA, colBtnIdleB
		btnText = "▶  连接安全隧道 (v3.2.1 Apex)"
	}
	if a.hoverID == hitConnect {
		c0 = lerpColor(c0, 0xFFFFFFFF, 0.10)
		c1 = lerpColor(c1, 0xFFFFFFFF, 0.10)
	}
	a.buf.fillRoundRectGrad(btnR.Left, btnR.Top, btnR.width(), btnR.height(), s(12), c0, c1)
	f.drawText(f.fHero, f.fmtCent, btnR, 0xFFFFFFFF, btnText)
	a.hits = append(a.hits, hitBox{id: hitConnect, rect: btnR})

	// Two compact metric rows inside hero card
	rowY := btnR.Bottom + s(12)
	cellW := (r.width() - s(40)) / 3
	drawMiniStat := func(col int32, label, val string, valCol uint32) {
		x0 := r.Left + s(16) + col*(cellW+s(4))
		cr := rect{x0, rowY, x0 + cellW, rowY + s(48)}
		a.buf.fillRoundRect(cr.Left, cr.Top, cr.width(), cr.height(), s(8), colBg)
		f.drawText(f.fSmall, f.fmtCent, rect{cr.Left, cr.Top + s(4), cr.Right, cr.Top + s(22)}, colTextMuted, label)
		f.drawText(f.fMonoB, f.fmtCent, rect{cr.Left, cr.Top + s(22), cr.Right, cr.Bottom - s(4)}, valCol, val)
	}

	rttTxt := "-- ms"
	rttCol := colTextSub
	if pingMs > 0 {
		rttTxt = fmt.Sprintf("%d ms", pingMs)
		rttCol = colEmerald
	}
	hopTxt := fmt.Sprintf("TLS %s", verify)
	if quicPort > 0 {
		hopTxt = fmt.Sprintf("UDP :%d", quicPort)
	}
	drawMiniStat(0, "通道延迟", rttTxt, rttCol)
	drawMiniStat(1, "活跃出口", hopTxt, colSky)
	drawMiniStat(2, "复用连接", fmt.Sprintf("%d 条", conns), colTextMain)

	if lastErr != "" && state != client.StateConnected {
		f.drawText(f.fSmall, f.fmtLeft, rect{r.Left + s(16), r.Bottom - s(22), r.Right - s(16), r.Bottom - s(4)}, colRed, lastErr)
	}
}

func (a *appUI) drawNodeCard(r rect, st map[string]any) {
	s := a.s
	f := a.fonts
	a.drawCard(r)

	routeMode := strVal(st["route_mode"])
	transPref := strVal(st["transport_pref"])
	nodeName := strVal(st["node_name"])
	if nodeName == "" {
		nodeName = "未选择节点 (Ctrl+V 粘贴导入)"
	}

	y := r.Top + s(16)
	f.drawText(f.fBold, f.fmtLeft, rect{r.Left + s(16), y, r.Left + s(140), y + s(20)}, colTextSub, "当前节点")
	y += s(26)

	delR := rect{r.Right - s(66), y, r.Right - s(16), y + s(34)}
	dropR := rect{r.Left + s(16), y, delR.Left - s(8), y + s(34)}
	dropBg := colBg
	if a.hoverID == hitNodeDrop || a.nodeDropOpen {
		dropBg = colCardAlt
	}
	a.buf.fillRoundRect(dropR.Left, dropR.Top, dropR.width(), dropR.height(), s(8), dropBg)
	a.buf.strokeRoundRect(dropR.Left, dropR.Top, dropR.width(), dropR.height(), s(8), 1, colBorderHi)
	f.drawText(f.fBody, f.fmtLeft, rect{dropR.Left + s(10), dropR.Top, dropR.Right - s(24), dropR.Bottom}, colTextMain, nodeName)
	arrow := "▾"
	if a.nodeDropOpen {
		arrow = "▴"
	}
	f.drawText(f.fBody, f.fmtCent, rect{dropR.Right - s(24), dropR.Top, dropR.Right - s(4), dropR.Bottom}, colTextSub, arrow)
	a.hits = append(a.hits, hitBox{id: hitNodeDrop, rect: dropR})

	a.drawButton(delR, hitNodeDelete, "删除", colBg, colBorderHi, colRed)

	// Segmented: Unified Route + System Proxy Mode
	y += s(52)
	f.drawText(f.fBold, f.fmtLeft, rect{r.Left + s(16), y, r.Right - s(16), y + s(20)}, colTextSub, "运行模式 (连接自动联动)")
	y += s(26)
	isCore := routeMode == "core" || routeMode == "direct"
	a.drawSeg3(rect{r.Left + s(16), y, r.Right - s(16), y + s(34)},
		[3]string{"Rule 智能", "Global 全局", "Core 仅端口"},
		[3]bool{routeMode == "rule" || routeMode == "", routeMode == "global", isCore},
		[3]hitKind{hitRouteRule, hitRouteGlobal, hitRouteCore},
		colEmerald,
	)

	// Segmented: Transport Preference
	y += s(52)
	f.drawText(f.fBold, f.fmtLeft, rect{r.Left + s(16), y, r.Right - s(16), y + s(20)}, colTextSub, "传输内核")
	y += s(26)
	a.drawSeg3(rect{r.Left + s(16), y, r.Right - s(16), y + s(34)},
		[3]string{"Auto 双栈", "QUIC 极速", "TCP uTLS"},
		[3]bool{transPref == "auto", transPref == "quic", transPref == "tcp"},
		[3]hitKind{hitTransAuto, hitTransQUIC, hitTransTCP},
		colCyan,
	)

	// Unified Mode Status Hint
	modeHint := "已启用联动：连接后自动接管系统代理并支持 CN 直连"
	if routeMode == "global" {
		modeHint = "已启用联动：连接后自动全局代理所有非本地流量"
	} else if isCore {
		modeHint = "仅开放本地 10808 / 10809 端口，不修改系统代理"
	}
	f.drawText(f.fSmall, f.fmtLeft, rect{r.Left + s(16), y + s(46), r.Right - s(16), y + s(68)}, colTextMuted, modeHint)

	// Bottom Copy Action Row
	btnY := r.Bottom - s(52)
	if btnY < y+s(74) {
		btnY = y + s(74)
	}
	halfW := (r.width() - s(40)) / 2
	c1R := rect{r.Left + s(16), btnY, r.Left + s(16) + halfW, btnY + s(36)}
	c2R := rect{c1R.Right + s(8), btnY, r.Right - s(16), btnY + s(36)}
	a.drawButton(c1R, hitCopyClash, "复制 Clash YAML", colCardAlt, colBorderHi, colSky)
	a.drawButton(c2R, hitCopyLink, "复制 gft3://", colCardAlt, colBorderHi, colEmerald)
}

func (a *appUI) drawNodeDropdownOverlay(card rect, st map[string]any) {
	s := a.s
	f := a.fonts
	nodes, _ := st["nodes"].([]client.NodeSummary)
	activeIdx := intVal(st["active_node"])

	rowH := s(32)
	count := len(nodes)
	if count == 0 {
		count = 1
	}
	if count > 7 {
		count = 7
	}
	pop := rect{
		Left:   card.Left + s(16),
		Top:    card.Top + s(76),
		Right:  card.Right - s(16),
		Bottom: card.Top + s(76) + int32(count)*rowH + s(8),
	}
	a.buf.fillRoundRect(pop.Left, pop.Top, pop.width(), pop.height(), s(10), 0xFF162036)
	a.buf.strokeRoundRect(pop.Left, pop.Top, pop.width(), pop.height(), s(10), 1.5, colCyan)

	if len(nodes) == 0 {
		f.drawText(f.fSmall, f.fmtCent, pop, colTextMuted, "暂无节点，请使用 Ctrl+V 粘贴导入")
		return
	}
	for i := 0; i < len(nodes) && i < 7; i++ {
		n := nodes[i]
		ir := rect{pop.Left + s(4), pop.Top + s(4) + int32(i)*rowH, pop.Right - s(4), pop.Top + s(4) + int32(i+1)*rowH}
		if a.hoverID == hitNodeOption && a.hoverIdx == n.Index {
			a.buf.fillRoundRect(ir.Left, ir.Top, ir.width(), ir.height(), s(6), colCyanDim)
		} else if n.Index == activeIdx {
			a.buf.fillRoundRect(ir.Left, ir.Top, ir.width(), ir.height(), s(6), colEmeraldDim)
		}
		mark := "  "
		txtCol := colTextMain
		if n.Index == activeIdx {
			mark = "✓ "
			txtCol = colEmerald
		}
		f.drawText(f.fBody, f.fmtLeft, rect{ir.Left + s(8), ir.Top, ir.Right - s(8), ir.Bottom}, txtCol,
			fmt.Sprintf("%s%s  (%s:%d)", mark, n.Name, n.Host, n.Port))
		a.hits = append(a.hits, hitBox{id: hitNodeOption, idx: n.Index, rect: ir})
	}
}

func (a *appUI) drawTrafficCard(r rect, st map[string]any) {
	s := a.s
	f := a.fonts
	a.drawCard(r)

	upBps := uint64Val(st["up_bps"])
	downBps := uint64Val(st["down_bps"])
	totUp := uint64Val(st["total_up"])
	totDown := uint64Val(st["total_down"])
	hist, _ := st["history"].([]client.TrafficPoint)

	// Top speed KPIs
	f.drawText(f.fBold, f.fmtLeft, rect{r.Left + s(16), r.Top + s(12), r.Left + s(130), r.Top + s(34)}, colTextSub, "实时吞吐")
	upStr := fmt.Sprintf("↑ %s/s  (累计 %s)", formatBytes(upBps), formatBytes(totUp))
	dnStr := fmt.Sprintf("↓ %s/s  (累计 %s)", formatBytes(downBps), formatBytes(totDown))
	mid := r.Left + r.width()/2 + s(16)
	f.drawText(f.fMonoB, f.fmtLeft, rect{r.Left + s(95), r.Top + s(12), mid, r.Top + s(34)}, colCyan, upStr)
	f.drawText(f.fMonoB, f.fmtLeft, rect{mid + s(6), r.Top + s(12), r.Right - s(14), r.Top + s(34)}, colEmerald, dnStr)

	// Plot box
	plot := rect{r.Left + s(16), r.Top + s(44), r.Right - s(16), r.Bottom - s(24)}
	a.buf.fillRoundRect(plot.Left, plot.Top, plot.width(), plot.height(), s(10), colBg)

	// Find dynamic Y max
	var maxVal uint64 = 64 * 1024
	for _, pt := range hist {
		if pt.Up > maxVal {
			maxVal = pt.Up
		}
		if pt.Down > maxVal {
			maxVal = pt.Down
		}
	}
	// Horizontal subtle grid lines (3 divisions)
	for g := 1; g <= 3; g++ {
		gy := float32(plot.Top) + float32(plot.height())*float32(g)/4.0
		a.buf.drawLineAA(float32(plot.Left+s(8)), gy, float32(plot.Right-s(8)), gy, 1, 0x22334155, plot)
	}
	f.drawText(f.fSmall, f.fmtRight, rect{plot.Right - s(120), plot.Top + s(4), plot.Right - s(10), plot.Top + s(22)}, colTextMuted, "峰值 "+formatBytes(maxVal)+"/s")
	f.drawText(f.fSmall, f.fmtLeft, rect{plot.Left + s(10), r.Bottom - s(22), r.Right - s(16), r.Bottom - s(4)}, colTextMuted, "最近 60 秒双通道流量波形   ·   Cyan 上传  /  Emerald 下载")

	const slots = 60
	xs := make([]float32, slots)
	ysDown := make([]float32, slots)
	ysUp := make([]float32, slots)

	padX := float32(s(8))
	padY := float32(s(10))
	usableW := float32(plot.width()) - padX*2
	usableH := float32(plot.height()) - padY*2
	baseY := float32(plot.Bottom) - padY

	offset := slots - len(hist)
	for i := 0; i < slots; i++ {
		xs[i] = float32(plot.Left) + padX + usableW*float32(i)/float32(slots-1)
		var uVal, dVal uint64
		if hi := i - offset; hi >= 0 && hi < len(hist) {
			uVal = hist[hi].Up
			dVal = hist[hi].Down
		}
		ysDown[i] = baseY - (float32(dVal)/float32(maxVal))*usableH
		ysUp[i] = baseY - (float32(uVal)/float32(maxVal))*usableH
	}

	a.buf.fillCurveArea(xs, ysDown, baseY, 0x4810B981, 0x0510B981, plot)
	a.buf.fillCurveArea(xs, ysUp, baseY, 0x4006B6D4, 0x0506B6D4, plot)

	for i := 0; i < slots-1; i++ {
		a.buf.drawLineAA(xs[i], ysDown[i], xs[i+1], ysDown[i+1], float32(s(2)), colEmerald, plot)
		a.buf.drawLineAA(xs[i], ysUp[i], xs[i+1], ysUp[i+1], float32(s(2)), colCyan, plot)
	}
}

func (a *appUI) drawLogCard(r rect, logs []client.LogEntry) {
	s := a.s
	f := a.fonts
	a.drawCard(r)

	hdrY := r.Top + s(10)
	f.drawText(f.fBold, f.fmtLeft, rect{r.Left + s(16), hdrY, r.Left + s(180), hdrY + s(26)}, colTextSub,
		fmt.Sprintf("内核运行日志 (%d)", len(logs)))

	clrR := rect{r.Right - s(92), hdrY, r.Right - s(16), hdrY + s(26)}
	a.drawButton(clrR, hitClearLogs, "清空日志", colBg, colBorderHi, colTextSub)

	view := rect{r.Left + s(14), r.Top + s(44), r.Right - s(14), r.Bottom - s(12)}
	a.buf.fillRoundRect(view.Left, view.Top, view.width(), view.height(), s(10), colBg)

	lineH := s(19)
	visLines := int((view.height() - s(12)) / lineH)
	if visLines < 1 {
		visLines = 1
	}

	if a.autoScroll || len(logs) != a.lastLogCount && a.logScroll >= maxInt(0, a.lastLogCount-visLines) {
		a.logScroll = maxInt(0, len(logs)-visLines)
		a.autoScroll = true
	}
	a.lastLogCount = len(logs)
	maxStart := maxInt(0, len(logs)-visLines)
	if a.logScroll > maxStart {
		a.logScroll = maxStart
	}

	if len(logs) == 0 {
		f.drawText(f.fMono, f.fmtCent, view, colTextMuted, "等待内核日志事件...")
		return
	}

	start := a.logScroll
	end := minInt(len(logs), start+visLines)
	for i := start; i < end; i++ {
		rowIdx := int32(i - start)
		y0 := view.Top + s(6) + rowIdx*lineH
		entry := logs[i]
		f.drawText(f.fMono, f.fmtLeft, rect{view.Left + s(10), y0, view.Left + s(76), y0 + lineH}, colTextMuted, entry.Time)

		msgCol := classifyLogColor(entry.Message)
		f.drawText(f.fMono, f.fmtLeft, rect{view.Left + s(78), y0, view.Right - s(14), y0 + lineH}, msgCol, entry.Message)
	}

	// Scrollbar thumb when logs exceed visible lines
	if len(logs) > visLines {
		trackH := view.height() - s(12)
		thumbH := maxI32(s(22), (trackH*int32(visLines))/int32(len(logs)))
		thumbY := view.Top + s(6)
		if maxStart > 0 {
			thumbY += ((trackH - thumbH) * int32(a.logScroll)) / int32(maxStart)
		}
		a.buf.fillRoundRect(view.Right-s(7), thumbY, s(3), thumbH, s(2), colBorderHi)
	}
}

func classifyLogColor(msg string) uint32 {
	low := strings.ToLower(msg)
	switch {
	case strings.Contains(low, "fail") || strings.Contains(low, "error") || strings.Contains(low, "timeout") || strings.Contains(low, "reject"):
		return colRed
	case strings.Contains(low, "fallback") || strings.Contains(low, "warn") || strings.Contains(low, "disconnect"):
		return colAmber
	case strings.Contains(low, "connected") || strings.Contains(low, "ok") || strings.Contains(low, "quic"):
		return colEmerald
	case strings.Contains(low, "utls") || strings.Contains(low, "proxy") || strings.Contains(low, "pool"):
		return colSky
	default:
		return colTextMain
	}
}

func (a *appUI) drawToast(w, h int32) {
	a.toastMu.Lock()
	msg := a.toastText
	isErr := a.toastErr
	until := a.toastUntil
	a.toastMu.Unlock()
	if msg == "" || time.Now().After(until) {
		return
	}
	s := a.s
	tw := minI32(w-s(40), s(420))
	tr := rect{(w - tw) / 2, h - s(54), (w + tw) / 2, h - s(18)}
	border := colCyan
	txtCol := colTextMain
	if isErr {
		border = colRed
		txtCol = 0xFFFCA5A5
	}
	a.buf.fillRoundRect(tr.Left, tr.Top, tr.width(), tr.height(), s(18), 0xEE0B1324)
	a.buf.strokeRoundRect(tr.Left, tr.Top, tr.width(), tr.height(), s(18), 1.2, border)
	a.fonts.drawText(a.fonts.fBody, a.fonts.fmtCent, tr, txtCol, msg)
}

func (a *appUI) drawCard(r rect) {
	rad := a.s(12)
	a.buf.fillRoundRect(r.Left, r.Top, r.width(), r.height(), rad, colCard)
	a.buf.strokeRoundRect(r.Left, r.Top, r.width(), r.height(), rad, 1, colBorder)
}

func (a *appUI) drawButton(r rect, id hitKind, label string, bg, border, textCol uint32) {
	if a.hoverID == id {
		bg = lerpColor(bg, 0xFFFFFFFF, 0.08)
		border = colCyan
	}
	if a.pressed == id {
		bg = lerpColor(bg, 0xFF000000, 0.15)
	}
	rad := a.s(8)
	a.buf.fillRoundRect(r.Left, r.Top, r.width(), r.height(), rad, bg)
	a.buf.strokeRoundRect(r.Left, r.Top, r.width(), r.height(), rad, 1, border)
	a.fonts.drawText(a.fonts.fSmall, a.fonts.fmtCent, r, textCol, label)
	a.hits = append(a.hits, hitBox{id: id, rect: r})
}

func (a *appUI) drawSeg3(r rect, labels [3]string, active [3]bool, ids [3]hitKind, activeCol uint32) {
	s := a.s
	rad := s(8)
	a.buf.fillRoundRect(r.Left, r.Top, r.width(), r.height(), rad, colBg)
	a.buf.strokeRoundRect(r.Left, r.Top, r.width(), r.height(), rad, 1, colBorder)
	segW := (r.width() - s(6)) / 3
	for i := 0; i < 3; i++ {
		sr := rect{
			Left:   r.Left + s(3) + int32(i)*segW,
			Top:    r.Top + s(3),
			Right:  r.Left + s(3) + int32(i+1)*segW,
			Bottom: r.Bottom - s(3),
		}
		if i == 2 {
			sr.Right = r.Right - s(3)
		}
		txtCol := colTextSub
		if active[i] {
			a.buf.fillRoundRect(sr.Left, sr.Top, sr.width(), sr.height(), s(6), lerpColor(activeCol, colBg, 0.72))
			a.buf.strokeRoundRect(sr.Left, sr.Top, sr.width(), sr.height(), s(6), 1, activeCol)
			txtCol = 0xFFFFFFFF
		} else if a.hoverID == ids[i] {
			a.buf.fillRoundRect(sr.Left, sr.Top, sr.width(), sr.height(), s(6), colCardAlt)
			txtCol = colTextMain
		}
		a.fonts.drawText(a.fonts.fSmall, a.fonts.fmtCent, sr, txtCol, labels[i])
		a.hits = append(a.hits, hitBox{id: ids[i], rect: sr})
	}
}

func shortPort(addr string) string {
	if idx := strings.LastIndex(addr, ":"); idx >= 0 {
		return addr[idx:]
	}
	return addr
}

func formatBytes(b uint64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.2f GB", float64(b)/(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(b)/(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(b)/(1<<10))
	default:
		return fmt.Sprintf("%d B", b)
	}
}

func strVal(v any) string {
	s, _ := v.(string)
	return s
}

func intVal(v any) int {
	switch x := v.(type) {
	case int:
		return x
	case int64:
		return int(x)
	case float64:
		return int(x)
	}
	return 0
}

func boolVal(v any) bool {
	b, _ := v.(bool)
	return b
}

func uint64Val(v any) uint64 {
	u, _ := v.(uint64)
	return u
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
