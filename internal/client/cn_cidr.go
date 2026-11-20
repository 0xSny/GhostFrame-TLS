package client

import (
	"bytes"
	"compress/zlib"
	_ "embed"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
)

//go:embed cn_ipv4.zlib
var cnIPv4Zlib []byte

//go:embed cn_ipv6.zlib
var cnIPv6Zlib []byte

type ipv6Range struct {
	netHi  uint64
	netLo  uint64
	maskHi uint64
	maskLo uint64
}

func (r ipv6Range) contains(ip16 net.IP) bool {
	if len(ip16) < 16 {
		return false
	}
	hi := binary.BigEndian.Uint64(ip16[0:8])
	lo := binary.BigEndian.Uint64(ip16[8:16])
	return (hi&r.maskHi) == r.netHi && (lo&r.maskLo) == r.netLo
}

var (
	cnOnce       sync.Once
	cnRanges     []ipRange
	cnIPv6Once   sync.Once
	cnIPv6Ranges []ipv6Range
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
		}
		cnRanges = ranges
	})
}

// CNPublicIPv4CIDRs returns the embedded APNIC Mainland China IPv4 CIDR table on demand
// for kernel-level nftables/ipset fast-path bypass without keeping 8,600+ string pointers in memory.
func CNPublicIPv4CIDRs() []string {
	if len(cnIPv4Zlib) == 0 {
		return nil
	}
	zr, err := zlib.NewReader(bytes.NewReader(cnIPv4Zlib))
	if err != nil {
		return nil
	}
	defer zr.Close()
	raw, err := io.ReadAll(io.LimitReader(zr, 4<<20))
	if err != nil || len(raw) < 5 {
		return nil
	}
	n := len(raw) / 5
	out := make([]string, 0, n)
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
		out = append(out, fmt.Sprintf("%d.%d.%d.%d/%d",
			byte(lo>>24), byte(lo>>16), byte(lo>>8), byte(lo), pref))
	}
	return out
}

func appendBuiltinCNRanges(dst []ipRange) []ipRange {
	initCNCIDRs()
	return append(dst, cnRanges...)
}

func initCNIPv6CIDRs() {
	cnIPv6Once.Do(func() {
		if len(cnIPv6Zlib) == 0 {
			return
		}
		zr, err := zlib.NewReader(bytes.NewReader(cnIPv6Zlib))
		if err != nil {
			return
		}
		defer zr.Close()
		raw, err := io.ReadAll(io.LimitReader(zr, 4<<20))
		if err != nil || len(raw) < 17 {
			return
		}
		n := len(raw) / 17
		ranges := make([]ipv6Range, 0, n)
		for i := 0; i < n; i++ {
			off := i * 17
			pref := int(raw[off+16])
			if pref > 128 {
				continue
			}
			hi := binary.BigEndian.Uint64(raw[off : off+8])
			lo := binary.BigEndian.Uint64(raw[off+8 : off+16])
			var maskHi, maskLo uint64
			if pref == 0 {
				maskHi, maskLo = 0, 0
			} else if pref <= 64 {
				maskHi = ^uint64(0) << (64 - pref)
				maskLo = 0
			} else {
				maskHi = ^uint64(0)
				maskLo = ^uint64(0) << (128 - pref)
			}
			ranges = append(ranges, ipv6Range{
				netHi:  hi & maskHi,
				netLo:  lo & maskLo,
				maskHi: maskHi,
				maskLo: maskLo,
			})
		}
		cnIPv6Ranges = ranges
	})
}

func appendBuiltinCNIPv6Ranges(dst []ipv6Range) []ipv6Range {
	initCNIPv6CIDRs()
	return append(dst, cnIPv6Ranges...)
}
