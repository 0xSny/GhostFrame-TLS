//go:build windows

package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"

	"ghostframe/internal/wininstall"
)

var Version = "v4.2.6"

const (
	setupWndClass = "KestrelProSetupWndClass"

	wsOverlapped = 0x00000000
	wsCaption    = 0x00C00000
	wsSysMenu    = 0x00080000
	wsMinBox     = 0x00020000
	wsVisible    = 0x10000000
	wsChild      = 0x40000000
	wsTabStop    = 0x00010000

	bsPushButton    = 0x00000000
	bsDefPushButton = 0x00000001
	bsAutoCheckBox  = 0x00000003
	bmGetCheck      = 0x00F0
	bmSetCheck      = 0x00F1
	bstChecked      = 1

	wmCreate   = 0x0001
	wmDestroy  = 0x0002
	wmCommand  = 0x0111
	wmSetFont  = 0x0030
	wmCtlColor = 0x0138
	wmAppDone  = 0x8010

	idChkDesktop   = 201
	idChkAutoStart = 202
	idBtnInstall   = 203
	idBtnCancel    = 204
	idLblStatus    = 205
)

var (
	u32 = windows.NewLazySystemDLL("user32.dll")
	k32 = windows.NewLazySystemDLL("kernel32.dll")
	g32 = windows.NewLazySystemDLL("gdi32.dll")

	pSetProcessDpiAwarenessContext = u32.NewProc("SetProcessDpiAwarenessContext")
	pGetDpiForWindow               = u32.NewProc("GetDpiForWindow")
	pGetSystemMetrics              = u32.NewProc("GetSystemMetrics")
	pRegisterClassExW              = u32.NewProc("RegisterClassExW")
	pCreateWindowExW               = u32.NewProc("CreateWindowExW")
	pDefWindowProcW                = u32.NewProc("DefWindowProcW")
	pShowWindow                    = u32.NewProc("ShowWindow")
	pUpdateWindow                  = u32.NewProc("UpdateWindow")
	pGetMessageW                   = u32.NewProc("GetMessageW")
	pTranslateMessage              = u32.NewProc("TranslateMessage")
	pDispatchMessageW              = u32.NewProc("DispatchMessageW")
	pPostQuitMessage               = u32.NewProc("PostQuitMessage")
	pPostMessageW                  = u32.NewProc("PostMessageW")
	pSendMessageW                  = u32.NewProc("SendMessageW")
	pDestroyWindow                 = u32.NewProc("DestroyWindow")
	pEnableWindow                  = u32.NewProc("EnableWindow")
	pSetWindowTextW                = u32.NewProc("SetWindowTextW")
	pLoadCursorW                   = u32.NewProc("LoadCursorW")
	pLoadIconW                     = u32.NewProc("LoadIconW")
	pMessageBoxW                   = u32.NewProc("MessageBoxW")
	pGetModuleHandleW              = k32.NewProc("GetModuleHandleW")
	pCreateSolidBrush              = g32.NewProc("CreateSolidBrush")
	pCreateFontW                   = g32.NewProc("CreateFontW")
	pSetBkMode                     = g32.NewProc("SetBkMode")
	pSetTextColor                  = g32.NewProc("SetTextColor")
)

type setupPoint struct{ X, Y int32 }
type setupMsg struct {
	HWnd     uintptr
	Message  uint32
	WParam   uintptr
	LParam   uintptr
	Time     uint32
	Pt       setupPoint
	LPrivate uint32
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

type setupUI struct {
	hwnd         uintptr
	hChkDesktop  uintptr
	hChkAutostart uintptr
	hBtnInstall  uintptr
	hBtnCancel   uintptr
	hLblStatus   uintptr
	hFontTitle   uintptr
	hFontBody    uintptr
	hBgBrush     uintptr

	installDir string
	installing bool
	errText    string
}

var (
	setupUIMu sync.Mutex
	curSetup  *setupUI
)

func u16(s string) *uint16 {
	p, _ := syscall.UTF16PtrFromString(s)
	return p
}

func msgBox(hwnd uintptr, title, text string, flags uint32) {
	pT, pM := u16(title), u16(text)
	_, _, _ = pMessageBoxW.Call(hwnd, uintptr(unsafe.Pointer(pM)), uintptr(unsafe.Pointer(pT)), uintptr(flags))
	runtime.KeepAlive(pT)
	runtime.KeepAlive(pM)
}

func runInstall(installDir string, createDesktop, autoStart, launchAfter bool) error {
	src, err := openSetupPayload()
	if err != nil {
		return err
	}
	defer src.Close()

	exe, _ := os.Executable()
	targetExe := filepath.Join(installDir, wininstall.ExeName)
	err = wininstall.InstallFromReader(src, targetExe, Version, wininstall.InstallOptions{
		CreateDesktop:   createDesktop,
		AutoStart:       autoStart,
		LegacyConfigDir: filepath.Dir(exe),
	})
	if err != nil {
		return err
	}
	if launchAfter {
		_ = wininstall.LaunchExecutable(targetExe)
	}
	return nil
}

func main() {
	quiet := flag.Bool("quiet", false, "install silently without UI")
	silent := flag.Bool("silent", false, "alias for -quiet")
	noDesktop := flag.Bool("nodesktop", false, "skip desktop shortcut")
	autoStart := flag.Bool("autostart", false, "enable launch on Windows startup")
	noLaunch := flag.Bool("nolaunch", false, "do not launch Kestrel Pro after installation")
	dirFlag := flag.String("dir", "", "override install directory")
	flag.Parse()

	installDir := wininstall.DefaultInstallDir()
	if *dirFlag != "" {
		installDir = *dirFlag
	}

	if *quiet || *silent {
		if err := runInstall(installDir, !*noDesktop, *autoStart, !*noLaunch); err != nil {
			os.Exit(1)
		}
		return
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	_, _, _ = pSetProcessDpiAwarenessContext.Call(^uintptr(3))

	hInst, _, _ := pGetModuleHandleW.Call(0)
	hArrow, _, _ := pLoadCursorW.Call(0, 32512)
	hIcon, _, _ := pLoadIconW.Call(hInst, 1)
	bgBrush, _, _ := pCreateSolidBrush.Call(0x00F9F6F4) // #F4F6F9 Porcelain Light

	ui := &setupUI{
		installDir: installDir,
		hBgBrush:   bgBrush,
	}
	setupUIMu.Lock()
	curSetup = ui
	setupUIMu.Unlock()

	cls := u16(setupWndClass)
	wcx := wndClassExW{
		CbSize:        uint32(unsafe.Sizeof(wndClassExW{})),
		Style:         0x0003,
		LpfnWndProc:   syscall.NewCallback(setupWndProc),
		HInstance:     hInst,
		HIcon:         hIcon,
		HCursor:       hArrow,
		HbrBackground: bgBrush,
		LpszClassName: cls,
		HIconSm:       hIcon,
	}
	atom, _, err := pRegisterClassExW.Call(uintptr(unsafe.Pointer(&wcx)))
	runtime.KeepAlive(&wcx)
	runtime.KeepAlive(cls)
	if atom == 0 {
		msgBox(0, "Kestrel Pro 安装程序", fmt.Sprintf("初始化安装窗口失败: %v", err), 0x10)
		os.Exit(1)
	}

	sw, _, _ := pGetSystemMetrics.Call(0)
	sh, _, _ := pGetSystemMetrics.Call(1)
	winW, winH := int32(490), int32(315)
	posX := uintptr(0x80000000)
	posY := uintptr(0x80000000)
	if sw > uintptr(winW) && sh > uintptr(winH) {
		posX = uintptr(int32(sw-uintptr(winW)) / 2)
		posY = uintptr(int32(sh-uintptr(winH)) / 2)
	}

	title := u16("Kestrel Pro " + Version + " 安装向导")
	style := uintptr(wsOverlapped | wsCaption | wsSysMenu | wsMinBox)
	hwnd, _, _ := pCreateWindowExW.Call(0, uintptr(unsafe.Pointer(cls)), uintptr(unsafe.Pointer(title)), style, posX, posY, uintptr(winW), uintptr(winH), 0, 0, hInst, 0)
	runtime.KeepAlive(cls)
	runtime.KeepAlive(title)
	if hwnd == 0 {
		os.Exit(1)
	}
	ui.hwnd = hwnd
	ui.initControls(hInst, !*noDesktop, *autoStart || wininstall.IsAutoStartEnabled())

	_, _, _ = pShowWindow.Call(hwnd, 5)
	_, _, _ = pUpdateWindow.Call(hwnd)

	var msg setupMsg
	for {
		r, _, _ := pGetMessageW.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0)
		if int32(r) <= 0 {
			break
		}
		_, _, _ = pTranslateMessage.Call(uintptr(unsafe.Pointer(&msg)))
		_, _, _ = pDispatchMessageW.Call(uintptr(unsafe.Pointer(&msg)))
	}
}

func (ui *setupUI) s(px int32) int32 {
	dpi, _, _ := pGetDpiForWindow.Call(ui.hwnd)
	if dpi < 96 {
		dpi = 96
	}
	return (px * int32(dpi)) / 96
}

func (ui *setupUI) createFont(ptSize int32, bold bool) uintptr {
	w := int32(400)
	if bold {
		w = 700
	}
	h := -ui.s(ptSize)
	face := u16("Microsoft YaHei UI")
	f, _, _ := pCreateFontW.Call(uintptr(h), 0, 0, 0, uintptr(w), 0, 0, 0, 1, 0, 0, 5, 0, uintptr(unsafe.Pointer(face)))
	runtime.KeepAlive(face)
	return f
}

func (ui *setupUI) ctrl(hInst uintptr, className, text string, style uint32, x, y, w, h, id int32, font uintptr) uintptr {
	cPtr, tPtr := u16(className), u16(text)
	hw, _, _ := pCreateWindowExW.Call(0, uintptr(unsafe.Pointer(cPtr)), uintptr(unsafe.Pointer(tPtr)),
		uintptr(wsChild|wsVisible|style), uintptr(ui.s(x)), uintptr(ui.s(y)), uintptr(ui.s(w)), uintptr(ui.s(h)),
		ui.hwnd, uintptr(id), hInst, 0)
	runtime.KeepAlive(cPtr)
	runtime.KeepAlive(tPtr)
	if hw != 0 && font != 0 {
		_, _, _ = pSendMessageW.Call(hw, wmSetFont, font, 1)
	}
	return hw
}

func (ui *setupUI) initControls(hInst uintptr, desktopChecked, autoStartChecked bool) {
	ui.hFontTitle = ui.createFont(19, true)
	ui.hFontBody = ui.createFont(14, false)

	// Scale window for DPI
	if dpi, _, _ := pGetDpiForWindow.Call(ui.hwnd); dpi > 96 {
		sw, _, _ := pGetSystemMetrics.Call(0)
		sh, _, _ := pGetSystemMetrics.Call(1)
		w := ui.s(490)
		h := ui.s(315)
		px, py := int32(0), int32(0)
		if sw > uintptr(w) && sh > uintptr(h) {
			px = int32(sw-uintptr(w)) / 2
			py = int32(sh-uintptr(h)) / 2
		}
		_, _, _ = u32.NewProc("SetWindowPos").Call(ui.hwnd, 0, uintptr(px), uintptr(py), uintptr(w), uintptr(h), 0x0004)
	}

	ui.ctrl(hInst, "STATIC", "Kestrel Pro "+Version, 0, 24, 18, 430, 28, 101, ui.hFontTitle)
	ui.ctrl(hInst, "STATIC", "将为您安装到系统并注册 Windows 开始菜单搜索与卸载项：", 0, 24, 52, 430, 22, 102, ui.hFontBody)
	ui.ctrl(hInst, "STATIC", "安装路径: "+ui.installDir, 0, 24, 78, 430, 22, 103, ui.hFontBody)

	ui.hChkDesktop = ui.ctrl(hInst, "BUTTON", "创建桌面快捷方式 (Kestrel Pro)", bsAutoCheckBox|wsTabStop, 24, 114, 340, 24, idChkDesktop, ui.hFontBody)
	if desktopChecked {
		_, _, _ = pSendMessageW.Call(ui.hChkDesktop, bmSetCheck, bstChecked, 0)
	}
	ui.hChkAutostart = ui.ctrl(hInst, "BUTTON", "开机自动启动（后台托盘运行）", bsAutoCheckBox|wsTabStop, 24, 144, 340, 24, idChkAutoStart, ui.hFontBody)
	if autoStartChecked {
		_, _, _ = pSendMessageW.Call(ui.hChkAutostart, bmSetCheck, bstChecked, 0)
	}

	ui.hLblStatus = ui.ctrl(hInst, "STATIC", "安装会自动迁移/保留现有节点配置，不会丢失任何设置。", 0, 24, 182, 430, 24, idLblStatus, ui.hFontBody)
	ui.hBtnInstall = ui.ctrl(hInst, "BUTTON", "立即安装并启动", bsDefPushButton|wsTabStop, 206, 224, 152, 34, idBtnInstall, ui.hFontBody)
	ui.hBtnCancel = ui.ctrl(hInst, "BUTTON", "取消", bsPushButton|wsTabStop, 370, 224, 84, 34, idBtnCancel, ui.hFontBody)
}

func setupWndProc(hwnd uintptr, msg uint32, wParam, lParam uintptr) uintptr {
	setupUIMu.Lock()
	ui := curSetup
	setupUIMu.Unlock()
	if ui == nil {
		r, _, _ := pDefWindowProcW.Call(hwnd, uintptr(msg), wParam, lParam)
		return r
	}
	switch msg {
	case wmCtlColor:
		_, _, _ = pSetBkMode.Call(wParam, 1) // TRANSPARENT
		_, _, _ = pSetTextColor.Call(wParam, 0x002A170F)
		return ui.hBgBrush

	case wmCommand:
		id := uint32(wParam & 0xFFFF)
		switch id {
		case idBtnCancel:
			if !ui.installing {
				_, _, _ = pDestroyWindow.Call(hwnd)
			}
		case idBtnInstall:
			if ui.installing {
				return 0
			}
			ui.installing = true
			_, _, _ = pEnableWindow.Call(ui.hBtnInstall, 0)
			_, _, _ = pEnableWindow.Call(ui.hBtnCancel, 0)
			st := u16("正在关闭旧进程、安装主程序并注册开始菜单快捷方式...")
			_, _, _ = pSetWindowTextW.Call(ui.hLblStatus, uintptr(unsafe.Pointer(st)))
			runtime.KeepAlive(st)

			cDesk, _, _ := pSendMessageW.Call(ui.hChkDesktop, bmGetCheck, 0, 0)
			cAuto, _, _ := pSendMessageW.Call(ui.hChkAutostart, bmGetCheck, 0, 0)
			go func(desk, auto bool) {
				err := runInstall(ui.installDir, desk, auto, true)
				if err != nil {
					ui.errText = err.Error()
					_, _, _ = pPostMessageW.Call(hwnd, wmAppDone, 0, 0)
				} else {
					_, _, _ = pPostMessageW.Call(hwnd, wmAppDone, 1, 0)
				}
			}(cDesk == bstChecked, cAuto == bstChecked)
		}
		return 0

	case wmAppDone:
		ui.installing = false
		if wParam == 1 {
			_, _, _ = pDestroyWindow.Call(hwnd)
		} else {
			_, _, _ = pEnableWindow.Call(ui.hBtnInstall, 1)
			_, _, _ = pEnableWindow.Call(ui.hBtnCancel, 1)
			st := u16("安装失败: " + ui.errText)
			_, _, _ = pSetWindowTextW.Call(ui.hLblStatus, uintptr(unsafe.Pointer(st)))
			runtime.KeepAlive(st)
			msgBox(hwnd, "安装失败", ui.errText, 0x10)
		}
		return 0

	case wmDestroy:
		_, _, _ = pPostQuitMessage.Call(0)
		return 0
	}
	r, _, _ := pDefWindowProcW.Call(hwnd, uintptr(msg), wParam, lParam)
	return r
}
