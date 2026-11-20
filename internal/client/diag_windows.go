//go:build windows

package client

import (
	"runtime"
	"syscall"
	"unicode/utf16"
	"unsafe"
)

const (
	diagCFUnicodeText = 13
	diagGmemMoveable  = 0x0002
)

var (
	diagUser32            = syscall.NewLazyDLL("user32.dll")
	diagKernel32          = syscall.NewLazyDLL("kernel32.dll")
	pDiagOpenClipboard    = diagUser32.NewProc("OpenClipboard")
	pDiagCloseClipboard   = diagUser32.NewProc("CloseClipboard")
	pDiagEmptyClipboard   = diagUser32.NewProc("EmptyClipboard")
	pDiagSetClipboardData = diagUser32.NewProc("SetClipboardData")
	pDiagGlobalAlloc      = diagKernel32.NewProc("GlobalAlloc")
	pDiagGlobalLock       = diagKernel32.NewProc("GlobalLock")
	pDiagGlobalUnlock     = diagKernel32.NewProc("GlobalUnlock")
	pDiagGlobalFree       = diagKernel32.NewProc("GlobalFree")
	pDiagRtlMoveMemory    = diagKernel32.NewProc("RtlMoveMemory")
)

func copyTextClipboardNative(hwnd uintptr, text string) bool {
	u16 := utf16.Encode([]rune(text))
	u16 = append(u16, 0)
	sz := uintptr(len(u16) * 2)

	hMem, _, _ := pDiagGlobalAlloc.Call(diagGmemMoveable, sz)
	if hMem == 0 {
		return false
	}
	ptr, _, _ := pDiagGlobalLock.Call(hMem)
	if ptr == 0 {
		_, _, _ = pDiagGlobalFree.Call(hMem)
		return false
	}
	_, _, _ = pDiagRtlMoveMemory.Call(ptr, uintptr(unsafe.Pointer(&u16[0])), sz)
	runtime.KeepAlive(u16)
	_, _, _ = pDiagGlobalUnlock.Call(hMem)

	ok, _, _ := pDiagOpenClipboard.Call(hwnd)
	if ok == 0 {
		_, _, _ = pDiagGlobalFree.Call(hMem)
		return false
	}
	defer pDiagCloseClipboard.Call()
	_, _, _ = pDiagEmptyClipboard.Call()
	res, _, _ := pDiagSetClipboardData.Call(diagCFUnicodeText, hMem)
	if res == 0 {
		_, _, _ = pDiagGlobalFree.Call(hMem)
		return false
	}
	return true
}
