//go:build windows

package wininstall

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	AppName          = "Kestrel Pro"
	ExeName          = "Kestrel-Pro.exe"
	AppUserModelID   = "Kestrel.Pro.Client"
	UninstallSubKey  = `Software\Microsoft\Windows\CurrentVersion\Uninstall\KestrelPro`
	AppPathsSubKey   = `Software\Microsoft\Windows\CurrentVersion\App Paths\Kestrel-Pro.exe`
	RunSubKey        = `Software\Microsoft\Windows\CurrentVersion\Run`
	RunOnceSubKey    = `Software\Microsoft\Windows\CurrentVersion\RunOnce`
	RunValueName     = "KestrelPro"
	WindowClassName  = "KestrelProWndClass"
	wmAppQuit        = 0x8003
	createNoWindow   = 0x08000000
	shcneAssocChange = 0x08000000
	shcnfIDList      = 0x0000
)

var (
	ole32   = windows.NewLazySystemDLL("ole32.dll")
	shell32 = windows.NewLazySystemDLL("shell32.dll")
	user32  = windows.NewLazySystemDLL("user32.dll")

	pCoInitializeEx                         = ole32.NewProc("CoInitializeEx")
	pCoUninitialize                         = ole32.NewProc("CoUninitialize")
	pCoCreateInstance                       = ole32.NewProc("CoCreateInstance")
	pSetCurrentProcessExplicitAppUserModelID = shell32.NewProc("SetCurrentProcessExplicitAppUserModelID")
	pSHChangeNotify                         = shell32.NewProc("SHChangeNotify")
	pFindWindowW                            = user32.NewProc("FindWindowW")
	pPostMessageW                           = user32.NewProc("PostMessageW")
)

var (
	clsidShellLink = windows.GUID{
		Data1: 0x00021401, Data2: 0x0000, Data3: 0x0000,
		Data4: [8]byte{0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46},
	}
	iidShellLinkW = windows.GUID{
		Data1: 0x000214F9, Data2: 0x0000, Data3: 0x0000,
		Data4: [8]byte{0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46},
	}
	iidPersistFile = windows.GUID{
		Data1: 0x0000010B, Data2: 0x0000, Data3: 0x0000,
		Data4: [8]byte{0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46},
	}
	iidPropertyStore = windows.GUID{
		Data1: 0x886D8EEB, Data2: 0x8CF2, Data3: 0x4446,
		Data4: [8]byte{0x8D, 0x02, 0xCD, 0xBA, 0x1D, 0xBD, 0xCF, 0x99},
	}
	fmtIDAppUserModel = windows.GUID{
		Data1: 0x9F4C2855, Data2: 0x9F79, Data3: 0x4B39,
		Data4: [8]byte{0xA8, 0xD0, 0xE1, 0xD4, 0x2D, 0xE1, 0xD5, 0xF3},
	}
)

type propertyKey struct {
	FmtID windows.GUID
	PID   uint32
}

type propVariantLPWSTR struct {
	VT        uint16
	Reserved1 uint16
	Reserved2 uint16
	Reserved3 uint16
	Ptr       uintptr
	Extra     uint64
}

func u16(s string) *uint16 {
	p, _ := syscall.UTF16PtrFromString(s)
	return p
}

func osPtr(addr uintptr) unsafe.Pointer {
	return *(*unsafe.Pointer)(unsafe.Pointer(&addr))
}

func comSlot(obj uintptr, slot uintptr) uintptr {
	vtbl := *(*uintptr)(osPtr(obj))
	return *(*uintptr)(unsafe.Add(osPtr(vtbl), slot*unsafe.Sizeof(uintptr(0))))
}

func comRelease(obj uintptr) {
	if obj != 0 {
		_, _, _ = syscall.SyscallN(comSlot(obj, 2), obj)
	}
}

// SetProcessAppUserModelID binds the running process to Kestrel.Pro.Client so Windows 11
// taskbar grouping, Start Search, and notifications align cleanly with installed shortcuts.
func SetProcessAppUserModelID() {
	if pSetCurrentProcessExplicitAppUserModelID.Find() != nil {
		return
	}
	p := u16(AppUserModelID)
	_, _, _ = pSetCurrentProcessExplicitAppUserModelID.Call(uintptr(unsafe.Pointer(p)))
	runtime.KeepAlive(p)
}

// DefaultInstallDir returns the standard per-user Windows install directory (%LocalAppData%\Programs\KestrelPro).
func DefaultInstallDir() string {
	base := os.Getenv("LOCALAPPDATA")
	if base == "" {
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			base = filepath.Join(home, "AppData", "Local")
		}
	}
	if base == "" {
		base = os.TempDir()
	}
	return filepath.Join(base, "Programs", "KestrelPro")
}

// InstalledExePath returns the canonical installed Kestrel-Pro.exe path.
func InstalledExePath() string {
	return filepath.Join(DefaultInstallDir(), ExeName)
}

// IsInstalledBinary reports whether currentExe resides in the canonical install directory
// (or matches Uninstall InstallLocation) and has an Uninstall registry entry.
func IsInstalledBinary(currentExe string) bool {
	if strings.TrimSpace(currentExe) == "" {
		var err error
		currentExe, err = os.Executable()
		if err != nil {
			return false
		}
	}
	absCur, _ := filepath.Abs(currentExe)
	absInst, _ := filepath.Abs(InstalledExePath())
	if strings.EqualFold(filepath.Dir(absCur), filepath.Dir(absInst)) {
		return true
	}
	k, err := registry.OpenKey(registry.CURRENT_USER, UninstallSubKey, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	loc, _, gerr := k.GetStringValue("InstallLocation")
	_ = k.Close()
	if gerr == nil && strings.TrimSpace(loc) != "" {
		absLoc, _ := filepath.Abs(loc)
		if strings.EqualFold(filepath.Dir(absCur), absLoc) {
			return true
		}
	}
	return false
}

// InstallOptions controls Windows desktop/Start-Menu installation behavior.
type InstallOptions struct {
	CreateDesktop   bool
	AutoStart       bool
	LegacyConfigDir string
}

// StatusSnapshot summarizes installed state and autostart preference for UI display.
type StatusSnapshot struct {
	Installed        bool   `json:"installed"`
	InstallDir       string `json:"install_dir"`
	CurrentExe       string `json:"current_exe"`
	AutoStart        bool   `json:"auto_start"`
	StartMenuPresent bool   `json:"start_menu_present"`
}

// QueryStatus inspects current executable location, Start Menu registration, and Windows autostart state.
func QueryStatus(currentExe string) StatusSnapshot {
	if strings.TrimSpace(currentExe) == "" {
		currentExe, _ = os.Executable()
	}
	smLink := filepath.Join(startMenuProgramsDir(), "Kestrel Pro.lnk")
	_, smErr := os.Stat(smLink)
	return StatusSnapshot{
		Installed:        IsInstalledBinary(currentExe),
		InstallDir:       DefaultInstallDir(),
		CurrentExe:       currentExe,
		AutoStart:        IsAutoStartEnabled(),
		StartMenuPresent: smErr == nil,
	}
}

func startMenuProgramsDir() string {
	appData := os.Getenv("APPDATA")
	if appData == "" {
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			appData = filepath.Join(home, "AppData", "Roaming")
		}
	}
	return filepath.Join(appData, "Microsoft", "Windows", "Start Menu", "Programs")
}

func desktopDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Desktop")
}

// CreateShortcut creates a Windows .lnk file via pure Go COM (IShellLinkW + IPersistFile + IPropertyStore).
func CreateShortcut(lnkPath, targetPath, args, workDir, iconPath, desc, appID string) error {
	if err := os.MkdirAll(filepath.Dir(lnkPath), 0o755); err != nil {
		return err
	}
	hrInit, _, _ := pCoInitializeEx.Call(0, 0x2) // COINIT_APARTMENTTHREADED
	if int32(hrInit) >= 0 {
		defer pCoUninitialize.Call()
	}

	var psl uintptr
	hr, _, _ := pCoCreateInstance.Call(
		uintptr(unsafe.Pointer(&clsidShellLink)),
		0,
		1, // CLSCTX_INPROC_SERVER
		uintptr(unsafe.Pointer(&iidShellLinkW)),
		uintptr(unsafe.Pointer(&psl)),
	)
	if int32(hr) < 0 || psl == 0 {
		return fmt.Errorf("CoCreateInstance(ShellLink) failed: 0x%x", uint32(hr))
	}
	defer comRelease(psl)

	pTarget := u16(targetPath)
	hr, _, _ = syscall.SyscallN(comSlot(psl, 20), psl, uintptr(unsafe.Pointer(pTarget))) // SetPath
	runtime.KeepAlive(pTarget)
	if int32(hr) < 0 {
		return fmt.Errorf("IShellLinkW::SetPath failed: 0x%x", uint32(hr))
	}

	if args != "" {
		pArgs := u16(args)
		_, _, _ = syscall.SyscallN(comSlot(psl, 11), psl, uintptr(unsafe.Pointer(pArgs))) // SetArguments
		runtime.KeepAlive(pArgs)
	}
	if workDir != "" {
		pWork := u16(workDir)
		_, _, _ = syscall.SyscallN(comSlot(psl, 9), psl, uintptr(unsafe.Pointer(pWork))) // SetWorkingDirectory
		runtime.KeepAlive(pWork)
	}
	if desc != "" {
		pDesc := u16(desc)
		_, _, _ = syscall.SyscallN(comSlot(psl, 7), psl, uintptr(unsafe.Pointer(pDesc))) // SetDescription
		runtime.KeepAlive(pDesc)
	}
	if iconPath != "" {
		pIcon := u16(iconPath)
		_, _, _ = syscall.SyscallN(comSlot(psl, 17), psl, uintptr(unsafe.Pointer(pIcon)), 0) // SetIconLocation
		runtime.KeepAlive(pIcon)
	}

	if appID != "" {
		var pps uintptr
		hrPS, _, _ := syscall.SyscallN(comSlot(psl, 0), psl, uintptr(unsafe.Pointer(&iidPropertyStore)), uintptr(unsafe.Pointer(&pps)))
		if int32(hrPS) >= 0 && pps != 0 {
			pkey := propertyKey{FmtID: fmtIDAppUserModel, PID: 5}
			pAppID := u16(appID)
			pv := propVariantLPWSTR{VT: 31, Ptr: uintptr(unsafe.Pointer(pAppID))} // VT_LPWSTR
			_, _, _ = syscall.SyscallN(comSlot(pps, 6), pps, uintptr(unsafe.Pointer(&pkey)), uintptr(unsafe.Pointer(&pv)))
			_, _, _ = syscall.SyscallN(comSlot(pps, 7), pps) // Commit
			runtime.KeepAlive(pAppID)
			runtime.KeepAlive(&pv)
			runtime.KeepAlive(&pkey)
			comRelease(pps)
		}
	}

	var ppf uintptr
	hr, _, _ = syscall.SyscallN(comSlot(psl, 0), psl, uintptr(unsafe.Pointer(&iidPersistFile)), uintptr(unsafe.Pointer(&ppf)))
	if int32(hr) < 0 || ppf == 0 {
		return fmt.Errorf("QueryInterface(IPersistFile) failed: 0x%x", uint32(hr))
	}
	defer comRelease(ppf)

	pLnk := u16(lnkPath)
	hr, _, _ = syscall.SyscallN(comSlot(ppf, 6), ppf, uintptr(unsafe.Pointer(pLnk)), 1) // Save(path, fRemember=TRUE)
	runtime.KeepAlive(pLnk)
	if int32(hr) < 0 {
		return fmt.Errorf("IPersistFile::Save failed: 0x%x", uint32(hr))
	}
	return nil
}

func cleanVersionDisplay(ver string) string {
	v := strings.TrimSpace(ver)
	v = strings.TrimPrefix(strings.TrimPrefix(v, "v"), "V")
	if v == "" {
		return "1.0.0"
	}
	return v
}

// RegisterWindowsApp creates Start Menu / Desktop shortcuts and registers Apps & Features + App Paths.
func RegisterWindowsApp(exePath, version string, createDesktop, setAutoStart bool) error {
	absExe, err := filepath.Abs(exePath)
	if err != nil {
		absExe = exePath
	}
	installDir := filepath.Dir(absExe)
	programs := startMenuProgramsDir()

	// Top-level Start Menu\Programs shortcut ensures immediate Windows Start Search indexing.
	topLnk := filepath.Join(programs, "Kestrel Pro.lnk")
	if err := CreateShortcut(topLnk, absExe, "", installDir, absExe, "Kestrel Pro (KSL) 透明代理客户端", AppUserModelID); err != nil {
		return err
	}

	// Start Menu subfolder with Launch + Uninstall shortcuts.
	folderDir := filepath.Join(programs, AppName)
	_ = CreateShortcut(filepath.Join(folderDir, "Kestrel Pro.lnk"), absExe, "", installDir, absExe, "Kestrel Pro (KSL) 透明代理客户端", AppUserModelID)
	_ = CreateShortcut(filepath.Join(folderDir, "卸载 Kestrel Pro.lnk"), absExe, "-uninstall", installDir, absExe, "卸载 Kestrel Pro", "")

	if createDesktop {
		deskLnk := filepath.Join(desktopDir(), "Kestrel Pro.lnk")
		_ = CreateShortcut(deskLnk, absExe, "", installDir, absExe, "Kestrel Pro (KSL) 透明代理客户端", AppUserModelID)
	}

	// Register App Paths (allows Win+R -> Kestrel-Pro)
	if k, _, err := registry.CreateKey(registry.CURRENT_USER, AppPathsSubKey, registry.SET_VALUE); err == nil {
		_ = k.SetStringValue("", absExe)
		_ = k.SetStringValue("Path", installDir)
		_ = k.Close()
	}

	// Register Windows Settings -> Apps -> Installed Apps entry
	var estKB uint32 = 12288
	if fi, err := os.Stat(absExe); err == nil && fi.Size() > 0 {
		estKB = uint32(fi.Size()/1024) + 512
	}
	if k, _, err := registry.CreateKey(registry.CURRENT_USER, UninstallSubKey, registry.SET_VALUE); err == nil {
		_ = k.SetStringValue("DisplayName", AppName)
		_ = k.SetStringValue("DisplayVersion", cleanVersionDisplay(version))
		_ = k.SetStringValue("Publisher", "Kestrel Project")
		_ = k.SetStringValue("DisplayIcon", absExe+",0")
		_ = k.SetStringValue("InstallLocation", installDir)
		_ = k.SetStringValue("UninstallString", fmt.Sprintf(`"%s" -uninstall`, absExe))
		_ = k.SetStringValue("QuietUninstallString", fmt.Sprintf(`"%s" -uninstall -quiet`, absExe))
		_ = k.SetStringValue("URLInfoAbout", "https://github.com/0xSny/Ghost")
		_ = k.SetDWordValue("EstimatedSize", estKB)
		_ = k.SetDWordValue("NoModify", 1)
		_ = k.SetDWordValue("NoRepair", 1)
		_ = k.Close()
	}

	if setAutoStart {
		_ = SetAutoStart(absExe, true)
	}
	if pSHChangeNotify.Find() == nil {
		_, _, _ = pSHChangeNotify.Call(shcneAssocChange, shcnfIDList, 0, 0)
	}
	return nil
}

// RefreshInstalledMetadata updates DisplayVersion / DisplayIcon (and Run path if enabled) after OTA update.
func RefreshInstalledMetadata(exePath, version string) {
	absExe, err := filepath.Abs(exePath)
	if err != nil {
		absExe = exePath
	}
	if k, err := registry.OpenKey(registry.CURRENT_USER, UninstallSubKey, registry.SET_VALUE|registry.QUERY_VALUE); err == nil {
		_ = k.SetStringValue("DisplayVersion", cleanVersionDisplay(version))
		_ = k.SetStringValue("DisplayIcon", absExe+",0")
		_ = k.SetStringValue("InstallLocation", filepath.Dir(absExe))
		_ = k.SetStringValue("UninstallString", fmt.Sprintf(`"%s" -uninstall`, absExe))
		_ = k.SetStringValue("QuietUninstallString", fmt.Sprintf(`"%s" -uninstall -quiet`, absExe))
		_ = k.Close()
	}
	if IsAutoStartEnabled() {
		_ = SetAutoStart(absExe, true)
	}
}

// IsAutoStartEnabled reports whether HKCU Run contains KestrelPro.
func IsAutoStartEnabled() bool {
	k, err := registry.OpenKey(registry.CURRENT_USER, RunSubKey, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	val, _, err := k.GetStringValue(RunValueName)
	return err == nil && strings.TrimSpace(val) != ""
}

// SetAutoStart enables or disables Kestrel Pro startup with Windows (minimized to tray).
func SetAutoStart(exePath string, enabled bool) error {
	if !enabled {
		k, err := registry.OpenKey(registry.CURRENT_USER, RunSubKey, registry.SET_VALUE)
		if err != nil {
			return nil
		}
		defer k.Close()
		err = k.DeleteValue(RunValueName)
		if errors.Is(err, registry.ErrNotExist) {
			return nil
		}
		return err
	}
	absExe, err := filepath.Abs(exePath)
	if err != nil {
		absExe = exePath
	}
	k, _, err := registry.CreateKey(registry.CURRENT_USER, RunSubKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	return k.SetStringValue(RunValueName, fmt.Sprintf(`"%s" -tray`, absExe))
}

// StopRunningInstances gracefully asks existing Kestrel Pro windows to quit and terminates any stubborn leftovers.
func StopRunningInstances(excludePID int) {
	cls := u16(WindowClassName)
	for i := 0; i < 4; i++ {
		hwnd, _, _ := pFindWindowW.Call(uintptr(unsafe.Pointer(cls)), 0)
		runtime.KeepAlive(cls)
		if hwnd == 0 {
			break
		}
		_, _, _ = pPostMessageW.Call(hwnd, wmAppQuit, 0, 0)
		time.Sleep(450 * time.Millisecond)
	}
	terminateMatchingProcesses(excludePID)
}

func terminateMatchingProcesses(excludePID int) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return
	}
	defer windows.CloseHandle(snap)

	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	if err := windows.Process32First(snap, &pe); err != nil {
		return
	}
	for {
		pid := int(pe.ProcessID)
		if pid > 4 && pid != excludePID {
			name := strings.ToLower(windows.UTF16ToString(pe.ExeFile[:]))
			if name == "kestrel-pro.exe" ||
				name == "kestrel-pro-windows-amd64.exe" ||
				(strings.HasPrefix(name, "kestrel-pro-v") && strings.HasSuffix(name, ".exe")) {
				if h, err := windows.OpenProcess(windows.PROCESS_TERMINATE|windows.SYNCHRONIZE, false, uint32(pid)); err == nil {
					_ = windows.TerminateProcess(h, 0)
					_, _ = windows.WaitForSingleObject(h, 2500)
					_ = windows.CloseHandle(h)
				}
			}
		}
		if err := windows.Process32Next(snap, &pe); err != nil {
			break
		}
	}
}

// MigrateLegacyClientConfig copies client.json from legacyDirs to ~/.kestrel/client.json if not already present.
func MigrateLegacyClientConfig(legacyDirs ...string) {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return
	}
	targetCfg := filepath.Join(home, ".kestrel", "client.json")
	if info, err := os.Stat(targetCfg); err == nil && info.Size() > 2 {
		return
	}
	for _, dir := range legacyDirs {
		if strings.TrimSpace(dir) == "" {
			continue
		}
		cand := filepath.Join(dir, "client.json")
		b, err := os.ReadFile(cand)
		if err != nil || len(b) < 2 {
			continue
		}
		_ = os.MkdirAll(filepath.Dir(targetCfg), 0o700)
		if os.WriteFile(targetCfg, b, 0o600) == nil {
			return
		}
	}
}

// InstallFromReader installs Kestrel-Pro.exe from src to targetExe (stopping running instances,
// migrating legacy config if needed, registering shortcuts + Apps & Features + optional autostart).
func InstallFromReader(src io.Reader, targetExe, version string, opts InstallOptions) error {
	if strings.TrimSpace(targetExe) == "" {
		targetExe = InstalledExePath()
	}
	installDir := filepath.Dir(targetExe)
	if err := os.MkdirAll(installDir, 0o755); err != nil {
		return err
	}

	StopRunningInstances(os.Getpid())

	tmp := targetExe + ".new"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, src); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}

	_ = os.Remove(targetExe + ".old")
	if _, serr := os.Stat(targetExe); serr == nil {
		if rerr := os.Rename(targetExe, targetExe+".old"); rerr != nil {
			// Give AV / handle release a brief retry window
			time.Sleep(400 * time.Millisecond)
			_ = os.Remove(targetExe)
		}
	}
	if err := os.Rename(tmp, targetExe); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	_ = os.Remove(targetExe + ".old")

	home, _ := os.UserHomeDir()
	MigrateLegacyClientConfig(opts.LegacyConfigDir, installDir, filepath.Join(home, "Desktop"))

	return RegisterWindowsApp(targetExe, version, opts.CreateDesktop, opts.AutoStart)
}

// CleanupStaleUpdateArtifacts removes leftover .old / .new files beside the running executable.
func CleanupStaleUpdateArtifacts() {
	exe, err := os.Executable()
	if err != nil || exe == "" {
		return
	}
	_ = os.Remove(exe + ".old")
	_ = os.Remove(exe + ".new")
}

// LaunchExecutable starts exePath detached with optional CLI arguments.
func LaunchExecutable(exePath string, args ...string) error {
	cmd := exec.Command(exePath, args...)
	cmd.Dir = filepath.Dir(exePath)
	return cmd.Start()
}

// LaunchAfterExit waits for currentPID to release its SingleInstance mutex and exit,
// then launches targetExe cleanly.
func LaunchAfterExit(targetExe string, currentPID int, args ...string) error {
	psExe := filepath.Join(os.Getenv("SystemRoot"), "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
	if _, err := os.Stat(psExe); err != nil {
		psExe = "powershell.exe"
	}
	escPS := func(s string) string {
		return "'" + strings.ReplaceAll(s, "'", "''") + "'"
	}
	argLiteral := "@()"
	if len(args) > 0 {
		quoted := make([]string, len(args))
		for i, a := range args {
			quoted[i] = escPS(a)
		}
		argLiteral = "@(" + strings.Join(quoted, ",") + ")"
	}
	script := fmt.Sprintf(
		"$pidWait=%d; $dst=%s; "+
			"for($i=0;$i -lt 60;$i++){ if(-not (Get-Process -Id $pidWait -ErrorAction SilentlyContinue)){ break }; Start-Sleep -Milliseconds 200 }; "+
			"Start-Sleep -Milliseconds 250; "+
			"if(Test-Path $dst){ $a=%s; if($a.Count -gt 0){ Start-Process -FilePath $dst -ArgumentList $a -WorkingDirectory (Split-Path -Parent $dst) } else { Start-Process -FilePath $dst -WorkingDirectory (Split-Path -Parent $dst) } }",
		currentPID, escPS(targetExe), argLiteral,
	)
	cmd := exec.Command(psExe, "-NoProfile", "-WindowStyle", "Hidden", "-ExecutionPolicy", "Bypass", "-Command", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: createNoWindow}
	return cmd.Start()
}

// ScheduleSelfReplaceAndRestart spawns a hidden PowerShell helper that waits for currentPID to exit,
// atomically replaces targetExe with stagedExe, removes staged/old files, and relaunches targetExe.
func ScheduleSelfReplaceAndRestart(stagedExe, targetExe, nextVersion string, currentPID int, relaunchArgs []string) error {
	if _, err := os.Stat(stagedExe); err != nil {
		return err
	}
	if IsInstalledBinary(targetExe) {
		RefreshInstalledMetadata(targetExe, nextVersion)
	}
	psExe := filepath.Join(os.Getenv("SystemRoot"), "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
	if _, err := os.Stat(psExe); err != nil {
		psExe = "powershell.exe"
	}

	escPS := func(s string) string {
		return "'" + strings.ReplaceAll(s, "'", "''") + "'"
	}
	argLiteral := "@()"
	if len(relaunchArgs) > 0 {
		quoted := make([]string, len(relaunchArgs))
		for i, a := range relaunchArgs {
			quoted[i] = escPS(a)
		}
		argLiteral = "@(" + strings.Join(quoted, ",") + ")"
	}

	script := fmt.Sprintf(
		"$pidWait=%d; $src=%s; $dst=%s; $old=%s; "+
			"for($i=0;$i -lt 60;$i++){ if(-not (Get-Process -Id $pidWait -ErrorAction SilentlyContinue)){ break }; Start-Sleep -Milliseconds 250 }; "+
			"Start-Sleep -Milliseconds 300; "+
			"for($j=0;$j -lt 15;$j++){ try { if(Test-Path $old){ Remove-Item -Force $old -ErrorAction SilentlyContinue }; if(Test-Path $dst){ Move-Item -Force $dst $old -ErrorAction SilentlyContinue }; Move-Item -Force $src $dst -ErrorAction Stop; break } catch { Start-Sleep -Milliseconds 350 } }; "+
			"if(Test-Path $dst){ $a=%s; if($a.Count -gt 0){ Start-Process -FilePath $dst -ArgumentList $a -WorkingDirectory (Split-Path -Parent $dst) } else { Start-Process -FilePath $dst -WorkingDirectory (Split-Path -Parent $dst) } }; "+
			"Start-Sleep -Seconds 1; if(Test-Path $old){ Remove-Item -Force $old -ErrorAction SilentlyContinue }",
		currentPID,
		escPS(stagedExe),
		escPS(targetExe),
		escPS(targetExe+".old"),
		argLiteral,
	)

	cmd := exec.Command(psExe, "-NoProfile", "-WindowStyle", "Hidden", "-ExecutionPolicy", "Bypass", "-Command", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: createNoWindow}
	return cmd.Start()
}

// Uninstall removes shortcuts, registry registrations (Run, App Paths, Uninstall, RunOnce), stops other
// instances, optionally purges user config/WebView2 data, and schedules removal of the executable directory.
func Uninstall(currentExe string, currentPID int, purgeData bool) error {
	if strings.TrimSpace(currentExe) == "" {
		currentExe, _ = os.Executable()
	}
	StopRunningInstances(currentPID)

	_ = SetAutoStart(currentExe, false)

	programs := startMenuProgramsDir()
	_ = os.Remove(filepath.Join(programs, "Kestrel Pro.lnk"))
	_ = os.RemoveAll(filepath.Join(programs, AppName))
	_ = os.Remove(filepath.Join(desktopDir(), "Kestrel Pro.lnk"))

	_ = registry.DeleteKey(registry.CURRENT_USER, UninstallSubKey)
	_ = registry.DeleteKey(registry.CURRENT_USER, AppPathsSubKey)
	if k, err := registry.OpenKey(registry.CURRENT_USER, RunOnceSubKey, registry.SET_VALUE); err == nil {
		_ = k.DeleteValue("KestrelProSysProxyRecovery")
		_ = k.Close()
	}

	if pSHChangeNotify.Find() == nil {
		_, _, _ = pSHChangeNotify.Call(shcneAssocChange, shcnfIDList, 0, 0)
	}

	if purgeData {
		home, _ := os.UserHomeDir()
		if home != "" {
			_ = os.RemoveAll(filepath.Join(home, ".kestrel"))
		}
		if la := os.Getenv("LOCALAPPDATA"); la != "" {
			_ = os.RemoveAll(filepath.Join(la, "KestrelPro"))
		}
	}

	absExe, _ := filepath.Abs(currentExe)
	absInstDir, _ := filepath.Abs(DefaultInstallDir())
	exeDir := filepath.Dir(absExe)

	// Only schedule directory cleanup when running inside KestrelPro install folder (never delete Desktop!).
	removeDir := strings.EqualFold(exeDir, absInstDir)
	rawCmd := "cmd.exe /C ping -n 2 127.0.0.1 >nul & del /F /Q " + strconv.Quote(absExe)
	if removeDir {
		rawCmd += " & ping -n 2 127.0.0.1 >nul & rmdir /S /Q " + strconv.Quote(exeDir)
	}
	cmd := exec.Command("cmd.exe")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: createNoWindow,
		CmdLine:       rawCmd,
	}
	return cmd.Start()
}
