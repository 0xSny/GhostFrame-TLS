package client

import (
	"net"
	"testing"
)

func FuzzParseDNSResponse(f *testing.F) {
	f.Add(buildTestDNSAnswer(101, 120, net.IPv4(1, 2, 3, 4)))
	// DNS compression pointer self-loop attack vector (0xC0 0x0C at offset 12)
	f.Add([]byte{0x00, 0x01, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _, _ = ParseDNSResponse(data)
	})
}
