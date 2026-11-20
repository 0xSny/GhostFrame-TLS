package client

import (
	"bytes"
	"compress/zlib"
	_ "embed"
	"encoding/binary"
	"fmt"
	"io"
	"sync"
)

//go:embed cn_ipv4.zlib
var cnIPv4Zlib []byte

var (
	cnOnce     sync.Once
	cnRanges   []ipRange
	cnCIDRStrs []string
)

func initCNCIDRs() {
	cnOnce.Do(func() {
		if len(cnIPv4Zlib) == 0 {
			return
		}
		zr, err := zlib.NewReader(bytes.NewReader(cnIPv4Zlib))
		if err != nil {
			return
		}
		defer zr.Close()
		raw, err := io.ReadAll(io.LimitReader(zr, 4<<20))
		if err != nil || len(raw) < 5 {
			return
		}

		n := len(raw) / 5
		ranges := make([]ipRange, 0, n)
		strs := make([]string, 0, n)
		for i := 0; i < n; i++ {
			off := i * 5
			ipU32 := binary.BigEndian.Uint32(raw[off : off+4])
			pref := raw[off+4]
			if pref > 32 {
				continue
			}
			var mask uint32
			if pref > 0 {
				mask = ^uint32(0) << (32 - pref)
			}
			lo := ipU32 & mask
			hi := lo | ^mask
			ranges = append(ranges, ipRange{lo: lo, hi: hi})
			strs = append(strs, fmt.Sprintf("%d.%d.%d.%d/%d",
				byte(lo>>24), byte(lo>>16), byte(lo>>8), byte(lo), pref))
		}
		cnRanges = ranges
		cnCIDRStrs = strs
	})
}

// CNPublicIPv4CIDRs returns a copy of the embedded APNIC Mainland China IPv4 CIDR table
// for kernel-level nftables/ipset fast-path bypass in side-router mode.
func CNPublicIPv4CIDRs() []string {
	initCNCIDRs()
	out := make([]string, len(cnCIDRStrs))
	copy(out, cnCIDRStrs)
	return out
}

func appendBuiltinCNRanges(dst []ipRange) []ipRange {
	initCNCIDRs()
	return append(dst, cnRanges...)
}
