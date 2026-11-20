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
	newPath := filepath.Join(home, ".kestrel", "client.json")
	if _, err := os.Stat(newPath); err == nil {
		return newPath
	}
	legacyPath := filepath.Join(home, ".gft", "client.json")
	if b, err := os.ReadFile(legacyPath); err == nil {
		_ = os.MkdirAll(filepath.Dir(newPath), 0o700)
		if werr := os.WriteFile(newPath, b, 0o600); werr == nil {
			return newPath
		}
		return legacyPath
	}
	return newPath
}
