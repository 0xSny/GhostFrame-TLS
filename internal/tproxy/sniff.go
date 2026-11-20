package tproxy

import (
	"bytes"
	"encoding/binary"
	"net"
	"strings"
	"time"

	"ghostframe/internal/gft"
)

// SniffTCPDomain peeks the first record/request from c (up to timeout, default 25ms)
// to extract a TLS ClientHello SNI or HTTP Host header without consuming any bytes
// from the returned rewound net.Conn.
func SniffTCPDomain(c net.Conn, timeout time.Duration) (string, net.Conn) {
	if c == nil {
		return "", nil
	}
	if timeout <= 0 {
		timeout = 25 * time.Millisecond
	}
	rc := gft.NewRewindConn(c)
	deadline := time.Now().Add(timeout)
	var buf [2048]byte
	total := 0
	var domain string
	defer func() { _ = c.SetReadDeadline(time.Time{}) }()

	for total < len(buf) {
		_ = c.SetReadDeadline(deadline)
		n, err := rc.Read(buf[total:])
		if n > 0 {
			total += n
			if buf[0] == 0x16 {
				if sni, ok := gft.ExtractTLSClientHelloSNI(buf[:total]); ok {
					domain = sni
					break
				}
				if total >= 5 {
					recLen := int(binary.BigEndian.Uint16(buf[3:5]))
					if total >= 5+recLen {
						break
					}
				}
			} else if looksLikeHTTPMethod(buf[:total]) {
				if host, ok := extractHTTPHost(buf[:total]); ok {
					domain = host
					break
				}
				if bytes.Contains(buf[:total], []byte("\r\n\r\n")) {
					break
				}
			} else {
				// Binary or server-speaks-first protocol (SSH, MTProto, SMTP, etc.): exit immediately.
				break
			}
		}
		if err != nil {
			break
		}
		if time.Now().After(deadline) {
			break
		}
	}

	if total == 0 {
		return "", c
	}
	rc.Rewind()
	return strings.ToLower(strings.TrimSpace(domain)), rc
}

var httpMethods = [][]byte{
	[]byte("GET "),
	[]byte("POST "),
	[]byte("HEAD "),
	[]byte("PUT "),
	[]byte("DELETE "),
	[]byte("OPTIONS "),
	[]byte("PATCH "),
	[]byte("CONNECT "),
}

func looksLikeHTTPMethod(b []byte) bool {
	if len(b) < 3 {
		return true // wait a few more bytes for HTTP verb
	}
	for _, m := range httpMethods {
		if len(b) <= len(m) {
			if bytes.HasPrefix(m, b) {
				return true
			}
		} else if bytes.HasPrefix(b, m) {
			return true
		}
	}
	return false
}

func extractHTTPHost(b []byte) (string, bool) {
	lines := bytes.Split(b, []byte("\n"))
	for i := 1; i < len(lines); i++ {
		ln := bytes.TrimSpace(lines[i])
		if len(ln) == 0 {
			break
		}
		if len(ln) > 5 && bytes.EqualFold(ln[:5], []byte("host:")) {
			val := strings.TrimSpace(string(ln[5:]))
			if val == "" {
				return "", false
			}
			if h, _, err := net.SplitHostPort(val); err == nil {
				val = h
			}
			val = strings.Trim(strings.TrimSpace(val), "[]")
			if net.ParseIP(val) != nil {
				return "", false
			}
			return strings.ToLower(val), val != ""
		}
	}
	return "", false
}
