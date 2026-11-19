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
	dir := filepath.Join(home, ".gft")
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
	noSysProxy := flag.Bool("no-sysproxy", false, "disable real Windows Registry system proxy writes (sandbox mode)")
	lowMem := flag.Bool("low-mem", false, "enable low-memory mode (4MB stream windows)")
	flag.Parse()

	if *noSysProxy {
		client.SetNoSysProxy(true)
	}
	if *lowMem {
		gft.SetLowMemMode(true)
		debug.SetMemoryLimit(32 << 20)
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

	if err := eng.StartServers(); err != nil {
		os.Exit(1)
	}
	eng.Logf("GhostFrame-Pro v3.2 native desktop initialized")

	if *autoConnect {
		go func() { _ = eng.Connect() }()
	}

	if err := winui.Run(eng); err != nil {
		os.Exit(1)
	}
}
