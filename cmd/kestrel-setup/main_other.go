//go:build !windows

package main

import "fmt"

var Version = "v4.2.6"

func main() {
	fmt.Printf("Kestrel Pro Setup (%s) is intended for Windows only.\n", Version)
}
