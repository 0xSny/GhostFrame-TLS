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

var desktopVersion = "v4.0.33-LTS"

func main() {
	if client.Version == "v4.0.32-LTS" {
		client.Version = desktopVersion
	}
	if crashFile := initCrashLog(); crashFile != nil {
		defer crashFile.Close()
	}

	cfgFlag := flag.String("config", "", "path to client config.json")
	autoConnect := flag.Bool("connect", false, "automatically connect tunnel on startup")
	noSysProxy := flag.Bool("no-sysproxy", false, "disable real Windows Registry system proxy writes (sandbox mode)")
	lowMem := flag.Bool("low-mem", false, "enable low-memory mode (4MB stream windows)")
	restoreSysProxy := flag.Bool("restore-sysproxy", false, "internal boot-time recovery for orphaned system proxy")
	restoreBackup := flag.String("backup", "", "path to sysproxy_backup.json for -restore-sysproxy")
	restoreExpected := flag.String("expected", "", "expected loopback proxy addr for -restore-sysproxy")
	flag.Parse()

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
			debug.SetMemoryLimit(256 << 20)
		}
	}

	mutex, primary := winui.AcquireSingleInstance()
	if !primary {
		return
	}
	if mutex != 0 {
		defer windows.CloseHandle(mutex)
	}

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
		go func() { _ = eng.Connect() }()
	}

	if err := winui.Run(eng); err != nil {
		os.Exit(1)
	}
}
