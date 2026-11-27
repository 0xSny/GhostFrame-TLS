//go:build windows

package main

import (
	"flag"
	"os"
	"path/filepath"
	"runtime/debug"

	"golang.org/x/sys/windows"

	"ghostframe/internal/client"
	"ghostframe/internal/gft"
	"ghostframe/internal/wininstall"
	"ghostframe/internal/winui"
)

func initCrashLog() *os.File {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return nil
	}
	dir := filepath.Join(home, ".kestrel")
	_ = os.MkdirAll(dir, 0o755)
	f, err := os.OpenFile(filepath.Join(dir, "crash.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil
	}
	_ = debug.SetCrashOutput(f, debug.CrashOptions{})
	return f
}

func main() {
	if crashFile := initCrashLog(); crashFile != nil {
		defer crashFile.Close()
	}

	cfgFlag := flag.String("config", "", "path to client config.json")
	autoConnect := flag.Bool("connect", false, "automatically connect tunnel on startup")
	trayMode := flag.Bool("tray", false, "start minimized in system tray (used by Windows autostart)")
	noSysProxy := flag.Bool("no-sysproxy", false, "disable real Windows Registry system proxy writes (sandbox mode)")
	lowMem := flag.Bool("low-mem", false, "enable low-memory mode (4MB stream windows)")
	restoreSysProxy := flag.Bool("restore-sysproxy", false, "internal boot-time recovery for orphaned system proxy")
	restoreBackup := flag.String("backup", "", "path to sysproxy_backup.json for -restore-sysproxy")
	restoreExpected := flag.String("expected", "", "expected loopback proxy addr for -restore-sysproxy")
	uninstallFlag := flag.Bool("uninstall", false, "uninstall Kestrel Pro shortcuts and Windows registrations")
	quietFlag := flag.Bool("quiet", false, "suppress interactive uninstall prompts")
	purgeFlag := flag.Bool("purge", false, "remove saved client configuration during -uninstall")
	flag.Parse()

	wininstall.SetProcessAppUserModelID()
	wininstall.CleanupStaleUpdateArtifacts()

	if *uninstallFlag {
		if !*quietFlag && !winui.ShowConfirmBox("卸载 Kestrel Pro", "确定要卸载 Kestrel Pro 并清理开始菜单与桌面快捷方式吗？\n\n（您的节点与分流配置将保留在 .kestrel 目录，方便以后重装恢复。）") {
			return
		}
		exe, _ := os.Executable()
		wininstall.StopRunningInstances(os.Getpid())
		bp := filepath.Join(filepath.Dir(resolveConfigPath(*cfgFlag)), "sysproxy_backup.json")
		_, _ = client.RecoverSystemProxyIfDirtyFor(bp, "")
		_ = wininstall.Uninstall(exe, os.Getpid(), *purgeFlag)
		if !*quietFlag {
			winui.ShowInfoBox("卸载完成", "Kestrel Pro 已从系统卸载完成。")
		}
		return
	}

	if *restoreSysProxy {
		if !winui.IsAnotherInstanceRunning() {
			bp := *restoreBackup
			if bp == "" {
				bp = filepath.Join(filepath.Dir(resolveConfigPath(*cfgFlag)), "sysproxy_backup.json")
			}
			_, _ = client.RecoverSystemProxyIfDirtyFor(bp, *restoreExpected)
		}
		return
	}

	if *noSysProxy {
		client.SetNoSysProxy(true)
	}
	if *lowMem {
		gft.SetLowMemMode(true)
	}
	if os.Getenv("GOMEMLIMIT") == "" {
		if *lowMem {
			debug.SetMemoryLimit(64 << 20)
		} else {
			debug.SetMemoryLimit(384 << 20)
		}
	}

	mutex, primary := winui.AcquireSingleInstance()
	if !primary {
		return
	}
	releaseMutex := func() {
		if mutex != 0 {
			_ = windows.CloseHandle(mutex)
			mutex = 0
		}
	}
	defer releaseMutex()

	cfgPath := resolveConfigPath(*cfgFlag)
	eng, err := client.NewEngine(cfgPath)
	if err != nil {
		os.Exit(1)
	}
	defer eng.Close()

	if err := eng.StartServersAutoFallback(); err != nil {
		eng.Logf("本地代理端口监听失败（请在界面修改本地端口后点击保存）: %v", err)
	}
	eng.Logf("Kestrel Pro %s (Kestrel-RTC) native desktop initialized", client.Version)

	if *autoConnect || eng.ShouldAutoConnect() {
		go func() {
			if err := eng.Connect(); err != nil {
				_, _ = eng.RecoverSystemProxyIfDirty()
			}
		}()
	}

	runErr := winui.RunWithOptions(eng, winui.RunOptions{StartHidden: *trayMode})
	releaseMutex()
	if runErr != nil {
		os.Exit(1)
	}
}
