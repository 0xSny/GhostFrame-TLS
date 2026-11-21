//go:build windows

package client

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

var (
	modWininet            = syscall.NewLazyDLL("wininet.dll")
	procInternetSetOption = modWininet.NewProc("InternetSetOptionW")

	modAdvapi32        = syscall.NewLazyDLL("advapi32.dll")
	procRegOpenKeyEx   = modAdvapi32.NewProc("RegOpenKeyExW")
	procRegCreateKeyEx = modAdvapi32.NewProc("RegCreateKeyExW")
	procRegCloseKey    = modAdvapi32.NewProc("RegCloseKey")
	procRegSetValueEx  = modAdvapi32.NewProc("RegSetValueExW")
	procRegQueryValue  = modAdvapi32.NewProc("RegQueryValueExW")
	procRegDeleteValue = modAdvapi32.NewProc("RegDeleteValueW")
)

const (
	hkeyCurrentUser = 0x80000001

	keyQueryValue = 0x0001
	keySetValue   = 0x0002

	regSz    = 1
	regDword = 4

	internetOptionSettingsChanged = 39
	internetOptionRefresh         = 37

	runOnceSubKey    = `Software\Microsoft\Windows\CurrentVersion\RunOnce`
	runOnceValueName = "KestrelProSysProxyRecovery"
)

func refreshSysProxy() {
	_, _, _ = procInternetSetOption.Call(0, uintptr(internetOptionSettingsChanged), 0, 0)
	_, _, _ = procInternetSetOption.Call(0, uintptr(internetOptionRefresh), 0, 0)
}

// SetSystemProxy sets or unsets the Windows Internet Settings system proxy.
func SetSystemProxy(addr string, enable bool) error {
	if IsMockSysProxy() {
		setMockSystemProxy(addr, enable)
		return nil
	}
	subKey, err := syscall.UTF16PtrFromString(`Software\Microsoft\Windows\CurrentVersion\Internet Settings`)
	if err != nil {
		return err
	}
	var hKey uintptr
	r1, _, err := procRegOpenKeyEx.Call(
		uintptr(hkeyCurrentUser),
		uintptr(unsafe.Pointer(subKey)),
		0,
		uintptr(keySetValue|keyQueryValue),
		uintptr(unsafe.Pointer(&hKey)),
	)
	if r1 != 0 {
		return err
	}
	defer procRegCloseKey.Call(hKey)

	valNameEnable, _ := syscall.UTF16PtrFromString("ProxyEnable")
	valNameServer, _ := syscall.UTF16PtrFromString("ProxyServer")
	valNameOverride, _ := syscall.UTF16PtrFromString("ProxyOverride")

	var enableDword uint32
	if enable {
		enableDword = 1
	}

	procRegSetValueEx.Call(
		hKey,
		uintptr(unsafe.Pointer(valNameEnable)),
		0,
		uintptr(regDword),
		uintptr(unsafe.Pointer(&enableDword)),
		4,
	)

	if enable && addr != "" {
		serverBytes, _ := syscall.UTF16FromString(addr)
		procRegSetValueEx.Call(
			hKey,
			uintptr(unsafe.Pointer(valNameServer)),
			0,
			uintptr(regSz),
			uintptr(unsafe.Pointer(&serverBytes[0])),
			uintptr(len(serverBytes)*2),
		)

		overrideBytes, _ := syscall.UTF16FromString("localhost;127.*;10.*;172.16.*;192.168.*;<local>")
		procRegSetValueEx.Call(
			hKey,
			uintptr(unsafe.Pointer(valNameOverride)),
			0,
			uintptr(regSz),
			uintptr(unsafe.Pointer(&overrideBytes[0])),
			uintptr(len(overrideBytes)*2),
		)
	}

	refreshSysProxy()
	return nil
}

// GetSystemProxy returns current system proxy settings.
func GetSystemProxy() (enabled bool, server string, err error) {
	if IsMockSysProxy() {
		return getMockSystemProxy()
	}
	subKey, err := syscall.UTF16PtrFromString(`Software\Microsoft\Windows\CurrentVersion\Internet Settings`)
	if err != nil {
		return false, "", err
	}
	var hKey uintptr
	r1, _, err := procRegOpenKeyEx.Call(
		uintptr(hkeyCurrentUser),
		uintptr(unsafe.Pointer(subKey)),
		0,
		uintptr(keyQueryValue),
		uintptr(unsafe.Pointer(&hKey)),
	)
	if r1 != 0 {
		return false, "", err
	}
	defer procRegCloseKey.Call(hKey)

	valNameEnable, _ := syscall.UTF16PtrFromString("ProxyEnable")
	var valType, enableDword, valLen uint32
	valLen = 4
	r1, _, _ = procRegQueryValue.Call(
		hKey,
		uintptr(unsafe.Pointer(valNameEnable)),
		0,
		uintptr(unsafe.Pointer(&valType)),
		uintptr(unsafe.Pointer(&enableDword)),
		uintptr(unsafe.Pointer(&valLen)),
	)
	if r1 == 0 && enableDword == 1 {
		enabled = true
	}

	valNameServer, _ := syscall.UTF16PtrFromString("ProxyServer")
	var buf [512]uint16
	valLen = uint32(len(buf) * 2)
	r1, _, _ = procRegQueryValue.Call(
		hKey,
		uintptr(unsafe.Pointer(valNameServer)),
		0,
		uintptr(unsafe.Pointer(&valType)),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&valLen)),
	)
	if r1 == 0 {
		server = syscall.UTF16ToString(buf[:])
	}
	return enabled, server, nil
}

// QueryFullSystemProxy reads ProxyEnable, ProxyServer, and ProxyOverride from Registry.
func QueryFullSystemProxy() (ProxySnapshot, error) {
	if IsMockSysProxy() {
		return queryMockSystemProxy(), nil
	}
	var snap ProxySnapshot
	subKey, err := syscall.UTF16PtrFromString(`Software\Microsoft\Windows\CurrentVersion\Internet Settings`)
	if err != nil {
		return snap, err
	}
	var hKey uintptr
	r1, _, err := procRegOpenKeyEx.Call(
		uintptr(hkeyCurrentUser),
		uintptr(unsafe.Pointer(subKey)),
		0,
		uintptr(keyQueryValue),
		uintptr(unsafe.Pointer(&hKey)),
	)
	if r1 != 0 {
		return snap, err
	}
	defer procRegCloseKey.Call(hKey)

	valNameEnable, _ := syscall.UTF16PtrFromString("ProxyEnable")
	var valType, enableDword, valLen uint32
	valLen = 4
	r1, _, _ = procRegQueryValue.Call(
		hKey,
		uintptr(unsafe.Pointer(valNameEnable)),
		0,
		uintptr(unsafe.Pointer(&valType)),
		uintptr(unsafe.Pointer(&enableDword)),
		uintptr(unsafe.Pointer(&valLen)),
	)
	if r1 == 0 && enableDword == 1 {
		snap.Enabled = true
	}

	readSZ := func(name string) string {
		vn, _ := syscall.UTF16PtrFromString(name)
		var b [1024]uint16
		l := uint32(len(b) * 2)
		var vt uint32
		rc, _, _ := procRegQueryValue.Call(
			hKey,
			uintptr(unsafe.Pointer(vn)),
			0,
			uintptr(unsafe.Pointer(&vt)),
			uintptr(unsafe.Pointer(&b[0])),
			uintptr(unsafe.Pointer(&l)),
		)
		if rc == 0 {
			return syscall.UTF16ToString(b[:])
		}
		return ""
	}
	snap.Server = readSZ("ProxyServer")
	snap.Override = readSZ("ProxyOverride")
	return snap, nil
}

// ApplySystemProxySnapshot restores an exact ProxySnapshot back to the Windows Registry.
func ApplySystemProxySnapshot(snap ProxySnapshot) error {
	if IsMockSysProxy() {
		applyMockSystemProxySnapshot(snap)
		return nil
	}
	subKey, err := syscall.UTF16PtrFromString(`Software\Microsoft\Windows\CurrentVersion\Internet Settings`)
	if err != nil {
		return err
	}
	var hKey uintptr
	r1, _, err := procRegOpenKeyEx.Call(
		uintptr(hkeyCurrentUser),
		uintptr(unsafe.Pointer(subKey)),
		0,
		uintptr(keySetValue),
		uintptr(unsafe.Pointer(&hKey)),
	)
	if r1 != 0 {
		return err
	}
	defer procRegCloseKey.Call(hKey)

	valNameEnable, _ := syscall.UTF16PtrFromString("ProxyEnable")
	var enableDword uint32
	if snap.Enabled {
		enableDword = 1
	}
	procRegSetValueEx.Call(hKey, uintptr(unsafe.Pointer(valNameEnable)), 0, uintptr(regDword), uintptr(unsafe.Pointer(&enableDword)), 4)

	writeSZ := func(name, val string) {
		vn, _ := syscall.UTF16PtrFromString(name)
		ub, _ := syscall.UTF16FromString(val)
		procRegSetValueEx.Call(hKey, uintptr(unsafe.Pointer(vn)), 0, uintptr(regSz), uintptr(unsafe.Pointer(&ub[0])), uintptr(len(ub)*2))
	}
	writeSZ("ProxyServer", snap.Server)
	writeSZ("ProxyOverride", snap.Override)
	refreshSysProxy()
	return nil
}

// registerSysProxyBootRecovery installs a one-shot HKCU RunOnce entry so that
// even if Windows powers off or the process crashes before cleaning up,
// the next Windows login immediately restores a clean system proxy before any browser runs.
func registerSysProxyBootRecovery(backupPath, httpAddr string) {
	if IsMockSysProxy() {
		return
	}
	exePath, err := os.Executable()
	if err != nil || exePath == "" {
		return
	}
	cmd := fmt.Sprintf("\"%s\" -restore-sysproxy -backup \"%s\" -expected \"%s\"", exePath, backupPath, httpAddr)

	subKey, err := syscall.UTF16PtrFromString(runOnceSubKey)
	if err != nil {
		return
	}
	var hKey uintptr
	r1, _, _ := procRegCreateKeyEx.Call(
		uintptr(hkeyCurrentUser),
		uintptr(unsafe.Pointer(subKey)),
		0,
		0,
		0,
		uintptr(keySetValue),
		0,
		uintptr(unsafe.Pointer(&hKey)),
		0,
	)
	if r1 != 0 {
		return
	}
	defer procRegCloseKey.Call(hKey)

	valName, _ := syscall.UTF16PtrFromString(runOnceValueName)
	cmdUTF16, _ := syscall.UTF16FromString(cmd)
	_, _, _ = procRegSetValueEx.Call(
		hKey,
		uintptr(unsafe.Pointer(valName)),
		0,
		uintptr(regSz),
		uintptr(unsafe.Pointer(&cmdUTF16[0])),
		uintptr(len(cmdUTF16)*2),
	)
}

func clearSysProxyBootRecovery() {
	if IsMockSysProxy() {
		return
	}
	subKey, err := syscall.UTF16PtrFromString(runOnceSubKey)
	if err != nil {
		return
	}
	var hKey uintptr
	r1, _, _ := procRegOpenKeyEx.Call(
		uintptr(hkeyCurrentUser),
		uintptr(unsafe.Pointer(subKey)),
		0,
		uintptr(keySetValue),
		uintptr(unsafe.Pointer(&hKey)),
	)
	if r1 != 0 {
		return
	}
	defer procRegCloseKey.Call(hKey)

	valName, _ := syscall.UTF16PtrFromString(runOnceValueName)
	_, _, _ = procRegDeleteValue.Call(hKey, uintptr(unsafe.Pointer(valName)))
}
