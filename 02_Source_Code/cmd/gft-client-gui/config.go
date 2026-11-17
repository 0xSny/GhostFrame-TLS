package main

import (
	"os"
	"path/filepath"
)

func resolveConfigPath(flagVal string) string {
	if flagVal != "" {
		return flagVal
	}
	if exe, err := os.Executable(); err == nil {
		cand := filepath.Join(filepath.Dir(exe), "client.json")
		if _, err := os.Stat(cand); err == nil {
			return cand
		}
	}
	if _, err := os.Stat("client.json"); err == nil {
		return "client.json"
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".gft", "client.json")
}
