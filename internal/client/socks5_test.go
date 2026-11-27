package client

import (
	"io"
	"net"
	"path/filepath"
	"testing"
)

func TestSOCKS5MethodNegotiationRFC1928(t *testing.T) {
	SetNoSysProxy(true)
	eng, err := NewEngine(filepath.Join(t.TempDir(), "cfg.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()

	socks := NewSOCKS5Server("127.0.0.1:0", eng)
	if err := socks.Start(); err != nil {
		t.Fatal(err)
	}
	defer socks.Close()

	cases := []struct {
		name     string
		greeting []byte
		want     [2]byte
	}{
		{
			name:     "no_auth_only",
			greeting: []byte{0x05, 0x01, 0x00},
			want:     [2]byte{0x05, 0x00},
		},
		{
			name:     "mixed_methods_with_no_auth",
			greeting: []byte{0x05, 0x03, 0x02, 0x01, 0x00},
			want:     [2]byte{0x05, 0x00},
		},
		{
			name:     "disjoint_methods_rejected",
			greeting: []byte{0x05, 0x02, 0x01, 0x02},
			want:     [2]byte{0x05, 0xFF},
		},
		{
			name:     "empty_methods_rejected",
			greeting: []byte{0x05, 0x00},
			want:     [2]byte{0x05, 0xFF},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := net.Dial("tcp", socks.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()

			if _, err := c.Write(tc.greeting); err != nil {
				t.Fatal(err)
			}
			var rep [2]byte
			if _, err := io.ReadFull(c, rep[:]); err != nil {
				t.Fatalf("ReadFull greeting reply failed: %v", err)
			}
			if rep != tc.want {
				t.Fatalf("reply mismatch: got %x want %x", rep, tc.want)
			}
			if tc.want[1] == 0xFF {
				var extra [1]byte
				if n, rerr := c.Read(extra[:]); n != 0 || rerr != io.EOF {
					t.Fatalf("expected connection closed after 0xFF rejection, got n=%d err=%v", n, rerr)
				}
			}
		})
	}
}
