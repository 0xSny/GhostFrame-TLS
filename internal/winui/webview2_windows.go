//go:build windows

package winui

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	coinitApartmentThreaded = 0x2
	eNoInterface            = uintptr(0x80004002)
	sOK                     = uintptr(0)

	webView2ClientGUID = `{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}`
)

var (
	iidUnknown = windows.GUID{
		Data1: 0x00000000,
		Data2: 0x0000,
		Data3: 0x0000,
		Data4: [8]byte{0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46},
	}
	iidEnvCompletedHandler = windows.GUID{
		Data1: 0x4E8A3389,
		Data2: 0xC9D8,
		Data3: 0x4BD2,
		Data4: [8]byte{0xB6, 0xB5, 0x12, 0x4F, 0xEE, 0x6C, 0xC1, 0x4D},
	}
	iidCtrlCompletedHandler = windows.GUID{
		Data1: 0x6C4819F3,
		Data2: 0xC9B7,
		Data3: 0x4260,
		Data4: [8]byte{0x81, 0x27, 0xC9, 0xF5, 0xBD, 0xE7, 0xF6, 0x8C},
	}
	iidProcessFailedHandler = windows.GUID{
		Data1: 0x79E0AEA4,
		Data2: 0x990B,
		Data3: 0x42D9,
		Data4: [8]byte{0xAA, 0x1D, 0x0F, 0xCC, 0x2E, 0x5B, 0xC7, 0xAE},
	}
)

type comCallbackVtbl struct {
	QueryInterface uintptr
	AddRef         uintptr
	Release        uintptr
	Invoke         uintptr
}

type comEnvCompletedHandler struct {
	vtbl     *comCallbackVtbl
	refCount atomic.Int32
	host     *webView2Host
}

type comCtrlCompletedHandler struct {
	vtbl     *comCallbackVtbl
	refCount atomic.Int32
	host     *webView2Host
}

type comProcessFailedHandler struct {
	vtbl     *comCallbackVtbl
	refCount atomic.Int32
	host     *webView2Host
}

type eventRegistrationToken struct {
	Value int64
}

// webView2Host embeds Microsoft Edge WebView2 inside a Win32 HWND using pure Go COM vtables
// loaded from the system EdgeWebView2 Runtime's EmbeddedBrowserWebView.dll (zero external DLLs).
type webView2Host struct {
	mu       sync.Mutex
	hwnd     uintptr
	startURL string

	dll     *windows.DLL
	env     uintptr // *ICoreWebView2Environment
	ctrl    uintptr // *ICoreWebView2Controller
	webview uintptr // *ICoreWebView2

	envVtbl           comCallbackVtbl
	ctrlVtbl          comCallbackVtbl
	procFailedVtbl    comCallbackVtbl
	envHandler        *comEnvCompletedHandler
	ctrlHandler       *comCtrlCompletedHandler
	procFailedHandler *comProcessFailedHandler
	procFailedToken   eventRegistrationToken
	pinner            runtime.Pinner

	ready           bool
	failed          bool
	failErr         string
	onFailed        func(err string)
	onProcessFailed func(kind uint32)
}

func webViewArchDir() string {
	switch runtime.GOARCH {
	case "arm64":
		return "arm64"
	case "386":
		return "x86"
	default:
		return "x64"
	}
}

func findEmbeddedWebViewDLL() (string, error) {
	arch := webViewArchDir()
	regRoots := []struct {
		root registry.Key
		path string
	}{
		{registry.LOCAL_MACHINE, `SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\` + webView2ClientGUID},
		{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\EdgeUpdate\Clients\` + webView2ClientGUID},
		{registry.CURRENT_USER, `Software\Microsoft\EdgeUpdate\Clients\` + webView2ClientGUID},
	}
	for _, r := range regRoots {
		k, err := registry.OpenKey(r.root, r.path, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		eb, _, err := k.GetStringValue("EBWebView")
		_ = k.Close()
		if err != nil || eb == "" {
			continue
		}
		cand := filepath.Join(eb, "EBWebView", arch, "EmbeddedBrowserWebView.dll")
		if _, stErr := os.Stat(cand); stErr == nil {
			return cand, nil
		}
	}

	globPatterns := []string{
		filepath.Join(os.Getenv("ProgramFiles(x86)"), "Microsoft", "EdgeWebView", "Application", "*", "EBWebView", arch, "EmbeddedBrowserWebView.dll"),
		filepath.Join(os.Getenv("ProgramFiles"), "Microsoft", "EdgeWebView", "Application", "*", "EBWebView", arch, "EmbeddedBrowserWebView.dll"),
		filepath.Join(os.Getenv("ProgramFiles(x86)"), "Microsoft", "Edge", "Application", "*", "EBWebView", arch, "EmbeddedBrowserWebView.dll"),
		filepath.Join(os.Getenv("ProgramFiles"), "Microsoft", "Edge", "Application", "*", "EBWebView", arch, "EmbeddedBrowserWebView.dll"),
	}
	for _, pat := range globPatterns {
		matches, _ := filepath.Glob(pat)
		if len(matches) > 0 {
			sort.Strings(matches)
			return matches[len(matches)-1], nil
		}
	}
	return "", fmt.Errorf("Edge WebView2 Runtime 未找到，请安装 Microsoft Edge WebView2 Runtime")
}

func defaultWebViewUserDataDir() string {
	base := os.Getenv("LOCALAPPDATA")
	if base == "" {
		if uc, err := os.UserCacheDir(); err == nil && uc != "" {
			base = uc
		}
	}
	if base == "" {
		base = os.TempDir()
	}
	dir := filepath.Join(base, "KestrelPro", "WebView2")
	_ = os.MkdirAll(dir, 0o755)
	return dir
}

func comSlot(obj uintptr, index uintptr) uintptr {
	vtbl := *(*uintptr)(osPtr(obj))
	return *(*uintptr)(unsafe.Add(osPtr(vtbl), index*unsafe.Sizeof(uintptr(0))))
}

func comAddRef(obj uintptr) {
	if obj != 0 {
		_, _, _ = syscall.SyscallN(comSlot(obj, 1), obj)
	}
}

func comRelease(obj uintptr) {
	if obj != 0 {
		_, _, _ = syscall.SyscallN(comSlot(obj, 2), obj)
	}
}

const defaultWebView2BrowserArgs = "--disable-gpu --disable-gpu-compositing --disable-features=RendererCodeIntegrity --no-proxy-server"

// ensureWebView2BrowserArgs disables hardware GPU compositing and WinINET proxy interception
// for the lightweight Kestrel Pro console unless overridden by WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS.
func ensureWebView2BrowserArgs() {
	if _, ok := os.LookupEnv("WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS"); !ok {
		_ = os.Setenv("WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS", defaultWebView2BrowserArgs)
	}
}

func newWebView2Host(hwnd uintptr, startURL string, onFailed func(string), onProcFailed func(uint32)) (*webView2Host, error) {
	ensureWebView2BrowserArgs()
	dllPath, err := findEmbeddedWebViewDLL()
	if err != nil {
		return nil, err
	}
	dll, err := windows.LoadDLL(dllPath)
	if err != nil {
		return nil, fmt.Errorf("load EmbeddedBrowserWebView.dll failed: %w", err)
	}
	proc, err := dll.FindProc("CreateWebViewEnvironmentWithOptionsInternal")
	if err != nil {
		_ = dll.Release()
		return nil, fmt.Errorf("CreateWebViewEnvironmentWithOptionsInternal not found: %w", err)
	}

	h := &webView2Host{
		hwnd:            hwnd,
		startURL:        startURL,
		dll:             dll,
		onFailed:        onFailed,
		onProcessFailed: onProcFailed,
	}

	h.envVtbl = comCallbackVtbl{
		QueryInterface: syscall.NewCallback(envHandlerQueryInterface),
		AddRef:         syscall.NewCallback(envHandlerAddRef),
		Release:        syscall.NewCallback(envHandlerRelease),
		Invoke:         syscall.NewCallback(envHandlerInvoke),
	}
	h.ctrlVtbl = comCallbackVtbl{
		QueryInterface: syscall.NewCallback(ctrlHandlerQueryInterface),
		AddRef:         syscall.NewCallback(ctrlHandlerAddRef),
		Release:        syscall.NewCallback(ctrlHandlerRelease),
		Invoke:         syscall.NewCallback(ctrlHandlerInvoke),
	}
	h.procFailedVtbl = comCallbackVtbl{
		QueryInterface: syscall.NewCallback(procFailedQueryInterface),
		AddRef:         syscall.NewCallback(procFailedAddRef),
		Release:        syscall.NewCallback(procFailedRelease),
		Invoke:         syscall.NewCallback(procFailedInvoke),
	}
	h.envHandler = &comEnvCompletedHandler{vtbl: &h.envVtbl, host: h}
	h.envHandler.refCount.Store(1)
	h.ctrlHandler = &comCtrlCompletedHandler{vtbl: &h.ctrlVtbl, host: h}
	h.ctrlHandler.refCount.Store(1)
	h.procFailedHandler = &comProcessFailedHandler{vtbl: &h.procFailedVtbl, host: h}
	h.procFailedHandler.refCount.Store(1)
	h.pinner.Pin(h.envHandler)
	h.pinner.Pin(h.ctrlHandler)
	h.pinner.Pin(h.procFailedHandler)
	h.pinner.Pin(&h.envVtbl)
	h.pinner.Pin(&h.ctrlVtbl)
	h.pinner.Pin(&h.procFailedVtbl)

	userDataPtr := utf16Ptr(defaultWebViewUserDataDir())
	// CreateWebViewEnvironmentWithOptionsInternal(checkEdgeBinary=1, runtimeType=0, userDataFolder, envOpts=0, handler)
	hr, _, callErr := proc.Call(
		1,
		0,
		uintptr(unsafe.Pointer(userDataPtr)),
		0,
		uintptr(unsafe.Pointer(h.envHandler)),
	)
	runtime.KeepAlive(userDataPtr)
	if int32(hr) < 0 {
		return nil, fmt.Errorf("CreateWebViewEnvironmentWithOptionsInternal failed: hr=0x%x err=%v", uint32(hr), callErr)
	}
	return h, nil
}

func envHandlerQueryInterface(this, riid, ppv uintptr) uintptr {
	if ppv == 0 || riid == 0 {
		return eNoInterface
	}
	g := *(*windows.GUID)(osPtr(riid))
	if g == iidUnknown || g == iidEnvCompletedHandler {
		*(*uintptr)(osPtr(ppv)) = this
		envHandlerAddRef(this)
		return sOK
	}
	*(*uintptr)(osPtr(ppv)) = 0
	return eNoInterface
}

func envHandlerAddRef(this uintptr) uintptr {
	h := (*comEnvCompletedHandler)(osPtr(this))
	return uintptr(h.refCount.Add(1))
}

func envHandlerRelease(this uintptr) uintptr {
	h := (*comEnvCompletedHandler)(osPtr(this))
	return uintptr(h.refCount.Add(-1))
}

func envHandlerInvoke(this, errorCode, createdEnv uintptr) uintptr {
	cb := (*comEnvCompletedHandler)(osPtr(this))
	h := cb.host
	if int32(errorCode) < 0 || createdEnv == 0 {
		h.markFailed(fmt.Sprintf("WebView2 Environment 创建失败 (0x%x)", uint32(errorCode)))
		return sOK
	}
	comAddRef(createdEnv)
	h.mu.Lock()
	h.env = createdEnv
	hwnd := h.hwnd
	ctrlHandler := h.ctrlHandler
	h.mu.Unlock()

	// ICoreWebView2Environment::CreateCoreWebView2Controller (vtable slot 3)
	hr, _, _ := syscall.SyscallN(
		comSlot(createdEnv, 3),
		createdEnv,
		hwnd,
		uintptr(unsafe.Pointer(ctrlHandler)),
	)
	if int32(hr) < 0 {
		h.markFailed(fmt.Sprintf("CreateCoreWebView2Controller 失败 (0x%x)", uint32(hr)))
	}
	return sOK
}

func ctrlHandlerQueryInterface(this, riid, ppv uintptr) uintptr {
	if ppv == 0 || riid == 0 {
		return eNoInterface
	}
	g := *(*windows.GUID)(osPtr(riid))
	if g == iidUnknown || g == iidCtrlCompletedHandler {
		*(*uintptr)(osPtr(ppv)) = this
		ctrlHandlerAddRef(this)
		return sOK
	}
	*(*uintptr)(osPtr(ppv)) = 0
	return eNoInterface
}

func ctrlHandlerAddRef(this uintptr) uintptr {
	h := (*comCtrlCompletedHandler)(osPtr(this))
	return uintptr(h.refCount.Add(1))
}

func ctrlHandlerRelease(this uintptr) uintptr {
	h := (*comCtrlCompletedHandler)(osPtr(this))
	return uintptr(h.refCount.Add(-1))
}

func ctrlHandlerInvoke(this, errorCode, createdCtrl uintptr) uintptr {
	cb := (*comCtrlCompletedHandler)(osPtr(this))
	h := cb.host
	if int32(errorCode) < 0 || createdCtrl == 0 {
		h.markFailed(fmt.Sprintf("WebView2 Controller 创建失败 (0x%x)", uint32(errorCode)))
		return sOK
	}
	comAddRef(createdCtrl)

	// ICoreWebView2Controller::get_CoreWebView2 (vtable slot 25)
	var wv uintptr
	hr, _, _ := syscall.SyscallN(comSlot(createdCtrl, 25), createdCtrl, uintptr(unsafe.Pointer(&wv)))
	if int32(hr) < 0 || wv == 0 {
		comRelease(createdCtrl)
		h.markFailed(fmt.Sprintf("get_CoreWebView2 失败 (0x%x)", uint32(hr)))
		return sOK
	}

	h.mu.Lock()
	h.ctrl = createdCtrl
	h.webview = wv
	h.ready = true
	startURL := h.startURL
	procFailedHandler := h.procFailedHandler
	h.mu.Unlock()

	// ICoreWebView2::add_ProcessFailed (vtable slot 25) for automatic renderer/browser crash recovery.
	var pfTok eventRegistrationToken
	if pfHr, _, _ := syscall.SyscallN(comSlot(wv, 25), wv, uintptr(unsafe.Pointer(procFailedHandler)), uintptr(unsafe.Pointer(&pfTok))); int32(pfHr) >= 0 {
		h.mu.Lock()
		h.procFailedToken = pfTok
		h.mu.Unlock()
	}

	// Configure ICoreWebView2Settings (get_Settings = vtable slot 3)
	var settings uintptr
	hr, _, _ = syscall.SyscallN(comSlot(wv, 3), wv, uintptr(unsafe.Pointer(&settings)))
	if int32(hr) >= 0 && settings != 0 {
		// put_IsStatusBarEnabled (slot 10) = FALSE
		_, _, _ = syscall.SyscallN(comSlot(settings, 10), settings, 0)
		// put_AreDevToolsEnabled (slot 12) = FALSE
		_, _, _ = syscall.SyscallN(comSlot(settings, 12), settings, 0)
		// put_IsZoomControlEnabled (slot 18) = FALSE
		_, _, _ = syscall.SyscallN(comSlot(settings, 18), settings, 0)
		comRelease(settings)
	}

	h.Resize()
	// put_IsVisible (slot 4) = TRUE
	_, _, _ = syscall.SyscallN(comSlot(createdCtrl, 4), createdCtrl, 1)

	if startURL != "" {
		u16 := utf16Ptr(startURL)
		// ICoreWebView2::Navigate (vtable slot 5)
		_, _, _ = syscall.SyscallN(comSlot(wv, 5), wv, uintptr(unsafe.Pointer(u16)))
		runtime.KeepAlive(u16)
	}
	return sOK
}

func procFailedQueryInterface(this, riid, ppv uintptr) uintptr {
	if ppv == 0 || riid == 0 {
		return eNoInterface
	}
	g := *(*windows.GUID)(osPtr(riid))
	if g == iidUnknown || g == iidProcessFailedHandler {
		*(*uintptr)(osPtr(ppv)) = this
		procFailedAddRef(this)
		return sOK
	}
	*(*uintptr)(osPtr(ppv)) = 0
	return eNoInterface
}

func procFailedAddRef(this uintptr) uintptr {
	h := (*comProcessFailedHandler)(osPtr(this))
	return uintptr(h.refCount.Add(1))
}

func procFailedRelease(this uintptr) uintptr {
	h := (*comProcessFailedHandler)(osPtr(this))
	return uintptr(h.refCount.Add(-1))
}

func procFailedInvoke(this, _sender, args uintptr) uintptr {
	cb := (*comProcessFailedHandler)(osPtr(this))
	h := cb.host
	var kind uint32
	if args != 0 {
		// ICoreWebView2ProcessFailedEventArgs::get_ProcessFailedKind (vtable slot 3)
		_, _, _ = syscall.SyscallN(comSlot(args, 3), args, uintptr(unsafe.Pointer(&kind)))
	}
	h.mu.Lock()
	fn := h.onProcessFailed
	h.mu.Unlock()
	if fn != nil {
		fn(kind)
	}
	return sOK
}

func (h *webView2Host) markFailed(reason string) {
	h.mu.Lock()
	h.failed = true
	h.failErr = reason
	cb := h.onFailed
	h.mu.Unlock()
	if cb != nil {
		cb(reason)
	}
}

func (h *webView2Host) Resize() {
	if h == nil {
		return
	}
	h.mu.Lock()
	ctrl := h.ctrl
	hwnd := h.hwnd
	h.mu.Unlock()
	if ctrl == 0 || hwnd == 0 {
		return
	}
	var rc rect
	_, _, _ = pGetClientRect.Call(hwnd, uintptr(unsafe.Pointer(&rc)))
	if rc.Right <= rc.Left || rc.Bottom <= rc.Top {
		return
	}
	// On Windows x64 ABI, 16-byte RECT struct passed by value in C++ put_Bounds(RECT)
	// is passed by pointer (&rc).
	_, _, _ = syscall.SyscallN(comSlot(ctrl, 6), ctrl, uintptr(unsafe.Pointer(&rc)))
	runtime.KeepAlive(&rc)
}

func (h *webView2Host) SetVisible(visible bool) {
	if h == nil {
		return
	}
	h.mu.Lock()
	ctrl := h.ctrl
	h.mu.Unlock()
	if ctrl == 0 {
		return
	}
	v := uintptr(0)
	if visible {
		v = 1
	}
	_, _, _ = syscall.SyscallN(comSlot(ctrl, 4), ctrl, v)
}

func (h *webView2Host) Close() {
	if h == nil {
		return
	}
	h.mu.Lock()
	wv := h.webview
	ctrl := h.ctrl
	env := h.env
	h.webview = 0
	h.ctrl = 0
	h.env = 0
	h.dll = nil
	h.mu.Unlock()

	if ctrl != 0 {
		// ICoreWebView2Controller::Close (vtable slot 24)
		_, _, _ = syscall.SyscallN(comSlot(ctrl, 24), ctrl)
		comRelease(ctrl)
	}
	if wv != 0 {
		comRelease(wv)
	}
	if env != 0 {
		comRelease(env)
	}
	// Intentionally skip FreeLibrary(EmbeddedBrowserWebView.dll) right before exit so
	// lingering WebView2 COM STA apartment callbacks cannot stall or jump into unmapped pages.
	h.pinner.Unpin()
}
