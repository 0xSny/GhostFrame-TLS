//go:build ignore

package main

import (
	"bytes"
	"compress/zlib"
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	inPath := flag.String("in", filepath.Join("dist", "Kestrel-Pro-windows-amd64.exe"), "input Kestrel Pro exe")
	outPath := flag.String("out", filepath.Join("cmd", "kestrel-setup", "Kestrel-Pro.payload.zlib"), "output zlib payload")
	flag.Parse()

	raw, err := os.ReadFile(*inPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read %s: %v\n", *inPath, err)
		os.Exit(1)
	}
	if len(raw) < 1024 || raw[0] != 'M' || raw[1] != 'Z' {
		fmt.Fprintf(os.Stderr, "%s is not a valid Windows PE binary\n", *inPath)
		os.Exit(1)
	}
	var buf bytes.Buffer
	zw, err := zlib.NewWriterLevel(&buf, zlib.BestCompression)
	if err != nil {
		fmt.Fprintf(os.Stderr, "zlib init: %v\n", err)
		os.Exit(1)
	}
	if _, err := zw.Write(raw); err != nil {
		fmt.Fprintf(os.Stderr, "zlib write: %v\n", err)
		os.Exit(1)
	}
	if err := zw.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "zlib close: %v\n", err)
		os.Exit(1)
	}
	if err := os.MkdirAll(filepath.Dir(*outPath), 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "mkdir: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(*outPath, buf.Bytes(), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write %s: %v\n", *outPath, err)
		os.Exit(1)
	}
	fmt.Printf("Packed %s (%d bytes) -> %s (%d bytes)\n", *inPath, len(raw), *outPath, buf.Len())
}
