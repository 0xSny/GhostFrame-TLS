package gft

import "testing"

func FuzzExtractTLSClientHelloSNI(f *testing.F) {
	f.Add(buildTestTLSClientHello("cdn.cloudflare.com"))
	f.Add([]byte{0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00})
	f.Add([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ExtractTLSClientHelloSNI(data)
	})
}

func FuzzEncodeDecodeAddrAndLink(f *testing.F) {
	if ab, err := EncodeAddr("example.com:443"); err == nil {
		f.Add(ab)
	}
	l := &Link{
		V: 3, Host: "1.2.3.4", Port: 443, SNI: "ftp.jaist.ac.jp",
		PSK: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
	}
	f.Add([]byte(l.Encode()))
	f.Add([]byte{0x01, 127, 0, 0, 1, 0x01, 0xBB})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _ = DecodeAddr(data)
		_, _ = ParseLink(string(data))
	})
}
