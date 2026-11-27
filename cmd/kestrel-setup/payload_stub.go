//go:build !setup_embed

package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func openSetupPayload() (io.ReadCloser, error) {
	exe, _ := os.Executable()
	dir := filepath.Dir(exe)
	for _, name := range []string{"Kestrel-Pro-windows-amd64.exe", "Kestrel-Pro.exe"} {
		cand := filepath.Join(dir, name)
		if f, err := os.Open(cand); err == nil {
			return f, nil
		}
	}
	return nil, fmt.Errorf("未找到内嵌安装包或同目录下的 Kestrel-Pro.exe")
}
