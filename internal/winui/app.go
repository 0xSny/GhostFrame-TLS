//go:build windows

package winui

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"ghostframe/internal/client"
)

const timerRefreshID = 1

type appUI struct {
	eng   *client.Engine
	hwnd  uintptr
	tray  *trayManager
	uiSrv *uiServer
	wv    *webView2Host

	dpi   int32
	hIcon uintptr

	wvFailed string
	shutOnce sync.Once
}

var (
	activeAppMu sync.Mutex
	activeApp   *appUI
)

// Run launches the pure-Go Win32 + Edge WebView2 Porcelain Light console window and system tray
// message loop, blocking until the user selects Exit or Windows shuts down.
func Run(eng *client.Engine) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	SetHighestAppShutdownPriority()
	enablePerMonitorDPI()

	_, _, _ = pCoInitializeEx.Call(0, coinitApartmentThreaded)
	defer pCoUninitialize.Call()

	hInst, _, _ := pGetModuleHandleW.Call(0)
	hArrow, _, _ := pLoadCursorW.Call(0, idcArrow)
	appIcon := CreateVectorIcon(client.StateDisconnected)

	app := &appUI{
		eng:   eng,
		dpi:   96,
		hIcon: appIcon,
	}

	uiSrv, err := startUIServer(eng, 0, func() { app.postRefresh() })
	if err != nil {
		return err
	}
	app.uiSrv = uiSrv
	defer uiSrv.Close()

	activeAppMu.Lock()
	activeApp = app
	activeAppMu.Unlock()
	defer func() {
		activeAppMu.Lock()
		activeApp = nil
		activeAppMu.Unlock()
	}()

	clsPtr := utf16Ptr(windowClassName)
	bgBrush, _, _ := pCreateSolidBrush.Call(0x00F9F6F4) // #F4F6F9 in Win32 BGR COLORREF
	wcx := wndClassExW{
		CbSize:        uint32(unsafe.Sizeof(wndClassExW{})),
		Style:         csHRedraw | csVRedraw,
		LpfnWndProc:   syscall.NewCallback(wndProc),
		HInstance:     hInst,
		HIcon:         appIcon,
		HCursor:       hArrow,
		HbrBackground: bgBrush,
		LpszClassName: clsPtr,
		HIconSm:       appIcon,
	}
	atom, _, err := pRegisterClassExW.Call(uintptr(unsafe.Pointer(&wcx)))
	runtime.KeepAlive(&wcx)
	runtime.KeepAlive(clsPtr)
	if atom == 0 {
		return fmt.Errorf("RegisterClassExW failed: %v", err)
	}

	sw, _, _ := pGetSystemMetrics.Call(0)
	sh, _, _ := pGetSystemMetrics.Call(1)
	winW := int32(1040)
	winH := int32(720)
	posX := uintptr(cwUseDefault)
	posY := uintptr(cwUseDefault)
	if sw > uintptr(winW) && sh > uintptr(winH) {
		posX = uintptr(int32(sw-uintptr(winW)) / 2)
		posY = uintptr(int32(sh-uintptr(winH)) / 2)
	}

	titlePtr := utf16Ptr("Kestrel Pro " + client.Version)
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
	app.uiSrv.SetHWND(hwnd)
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

	applyLightWindowChrome(hwnd)
	if appIcon != 0 {
		_, _, _ = pSendMessageW.Call(hwnd, wmSetIcon, iconBig, appIcon)
		_, _, _ = pSendMessageW.Call(hwnd, wmSetIcon, iconSmall, appIcon)
	}

	app.tray = newTrayManager(hwnd)
	wv, wvErr := newWebView2Host(hwnd, app.uiSrv.URL(), func(reason string) {
		app.wvFailed = reason
		app.postRefresh()
	})
	if wvErr != nil {
		app.wvFailed = wvErr.Error()
		eng.Logf("[WinUI] WebView2 init failed (%v), fallback prompt active", wvErr)
	} else {
		app.wv = wv
	}

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
	case wmGetMinMaxInfo:
		mmi := (*minMaxInfo)(osPtr(lParam))
		mmi.MinTrackSize.X = a.s(820)
		mmi.MinTrackSize.Y = a.s(620)
		return 0

	case wmDpiChanged:
		newDPI := int32(wParam & 0xFFFF)
		if newDPI >= 96 {
			a.dpi = newDPI
			rc := (*rect)(osPtr(lParam))
			_, _, _ = pSetWindowPos.Call(hwnd, 0, uintptr(rc.Left), uintptr(rc.Top), uintptr(rc.width()), uintptr(rc.height()), swpNoZOrder|swpNoActivate)
			if a.wv != nil {
				a.wv.Resize()
			}
		}
		return 0

	case wmSize:
		if a.wv != nil {
			a.wv.Resize()
		}
		return 0

	case wmTimer:
		if wParam == timerRefreshID && a.tray != nil && a.eng != nil {
			a.tray.update(a.eng.Status())
		}
		return 0

	case wmPaint:
		var ps paintStruct
		hdc, _, _ := pBeginPaint.Call(hwnd, uintptr(unsafe.Pointer(&ps)))
		if a.wvFailed != "" {
			var rc rect
			_, _, _ = pGetClientRect.Call(hwnd, uintptr(unsafe.Pointer(&rc)))
			brush, _, _ := pCreateSolidBrush.Call(0x00F9F6F4)
			_, _, _ = pFillRect.Call(hdc, uintptr(unsafe.Pointer(&rc)), brush)
			_, _, _ = pDeleteObject.Call(brush)
		}
		_, _, _ = pEndPaint.Call(hwnd, uintptr(unsafe.Pointer(&ps)))
		return 0

	case wmAppWake:
		a.showAndFocus()
		return 0

	case wmAppRefresh:
		if a.tray != nil && a.eng != nil {
			a.tray.update(a.eng.Status())
		}
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
				func() { a.importFromClipboardAsync() },
				func() { _, _, _ = pPostMessageW.Call(hwnd, wmAppQuit, 0, 0) },
				func(msg string, isErr bool) {
					if a.uiSrv != nil {
						a.uiSrv.setToast(msg, isErr)
					}
				},
				func() { a.postRefresh() },
			)
		}
		return 0

	case wmAppQuit:
		a.cleanup()
		_, _, _ = pPostQuitMessage.Call(0)
		return 0

	case wmClose:
		// Hide to system tray instead of killing the background proxy tunnel.
		if a.wv != nil {
			a.wv.SetVisible(false)
		}
		_, _, _ = pShowWindow.Call(hwnd, swHide)
		return 0

	case wmQueryEndSession:
		if a.eng != nil {
			a.eng.RestoreSystemProxySync()
		}
		return 1

	case wmEndSession:
		if wParam != 0 {
			if a.eng != nil {
				a.eng.RestoreSystemProxySync()
			}
			a.cleanup()
		}
		return 0

	case wmPowerBroadcast:
		switch wParam {
		case pbtApmSuspend:
			if a.eng != nil {
				a.eng.Logf("[Power] System entering sleep/standby")
			}
		case pbtApmResumeAutomatic, pbtApmResumeSuspend:
			if a.eng != nil {
				go a.eng.OnSystemWake()
			}
		}
		return 1

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
	if a.wv != nil {
		a.wv.SetVisible(true)
		a.wv.Resize()
	}
	if a.wvFailed != "" && a.uiSrv != nil {
		urlPtr := utf16Ptr(a.uiSrv.URL())
		openPtr := utf16Ptr("open")
		_, _, _ = pShellExecuteW.Call(0, uintptr(unsafe.Pointer(openPtr)), uintptr(unsafe.Pointer(urlPtr)), 0, 0, swShow)
		runtime.KeepAlive(urlPtr)
		runtime.KeepAlive(openPtr)
	}
}

func (a *appUI) cleanup() {
	a.shutOnce.Do(func() {
		if a.hwnd != 0 {
			_, _, _ = pKillTimer.Call(a.hwnd, timerRefreshID)
		}
		if a.wv != nil {
			a.wv.Close()
			a.wv = nil
		}
		if a.uiSrv != nil {
			a.uiSrv.Close()
		}
		if a.tray != nil {
			a.tray.destroy()
		}
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

func (a *appUI) postRefresh() {
	if a.hwnd != 0 {
		_, _, _ = pPostMessageW.Call(a.hwnd, wmAppRefresh, 0, 0)
	}
}

func (a *appUI) importFromClipboardAsync() {
	raw := strings.TrimSpace(GetClipboardText(a.hwnd))
	if raw == "" {
		if a.uiSrv != nil {
			a.uiSrv.setToast("剪贴板为空，请先复制 ksl4:// 或 gft3:// 链接", true)
		}
		return
	}
	go func() {
		lines := strings.Split(raw, "\n")
		imported := 0
		firstIdx := -1
		var lastErr error
		for _, ln := range lines {
			ln = strings.TrimSpace(ln)
			if ln == "" || (!strings.HasPrefix(ln, "ksl4://") && !strings.HasPrefix(ln, "gft3://") && !strings.HasPrefix(ln, "gft2://") && !strings.HasPrefix(ln, "gft://")) {
				continue
			}
			idx, err := a.eng.ImportLink(ln, imported == 0)
			if err != nil {
				lastErr = err
				continue
			}
			if imported == 0 {
				firstIdx = idx
			}
			imported++
		}
		if imported == 0 {
			idx, err := a.eng.ImportLink(raw, true)
			if err != nil {
				if lastErr != nil {
					err = lastErr
				}
				if a.uiSrv != nil {
					a.uiSrv.setToast("节点导入失败: "+err.Error(), true)
				}
				return
			}
			firstIdx = idx
			imported = 1
		}
		st := a.eng.Status()
		curState := client.ConnState(strVal(st["state"]))
		if firstIdx >= 0 && (curState == client.StateConnected || curState == client.StateConnecting) {
			if a.uiSrv != nil {
				a.uiSrv.setToast(fmt.Sprintf("已导入 %d 个节点，正在无损切换...", imported), false)
			}
			if err := a.eng.SelectNode(firstIdx); err != nil && !errors.Is(err, client.ErrSwitchCancelled) {
				if a.uiSrv != nil {
					a.uiSrv.setToast("热切换失败: "+err.Error(), true)
				}
			} else if a.uiSrv != nil {
				a.uiSrv.setToastSuccess(fmt.Sprintf("已导入 %d 个节点并热切换生效", imported))
			}
		} else if a.uiSrv != nil {
			a.uiSrv.setToastSuccess(fmt.Sprintf("已导入 %d 个节点并激活", imported))
		}
		a.postRefresh()
	}()
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
	case uint64:
		return int(x)
	case float64:
		return int(x)
	default:
		return 0
	}
}
