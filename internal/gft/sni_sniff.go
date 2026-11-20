package gft

import (
	"encoding/binary"
	"net"
	"strings"
	"time"
)

// IsTLSSniffPort reports whether port is a standard TLS port eligible for 30ms ClientHello SNI sniffing.
func IsTLSSniffPort(port int) bool {
	switch port {
	case 443, 8443, 2053, 2083, 2087, 2096:
		return true
	default:
		return false
	}
}

// SniffTLSSNI performs a bounded non-destructive read (default 30ms) on c looking for a TLS
// ClientHello SNI hostname, returning any extracted SNI along with a rewound net.Conn holding all read bytes.
func SniffTLSSNI(c net.Conn, timeout time.Duration) (string, net.Conn) {
	if c == nil {
		return "", nil
	}
	if timeout <= 0 {
		timeout = 30 * time.Millisecond
	}
	rc := NewRewindConn(c)
	deadline := time.Now().Add(timeout)
	var buf [2048]byte
	total := 0
	var sni string
	defer func() { _ = c.SetReadDeadline(time.Time{}) }()

	for total < len(buf) {
		_ = c.SetReadDeadline(deadline)
		n, err := rc.Read(buf[total:])
		if n > 0 {
			total += n
			if buf[0] != 0x16 {
				// Non-TLS protocol: return peeked bytes immediately without waiting.
				break
			}
			if host, ok := ExtractTLSClientHelloSNI(buf[:total]); ok {
				sni = host
				break
			}
			if total >= 5 {
				recLen := int(binary.BigEndian.Uint16(buf[3:5]))
				if total >= 5+recLen {
					break
				}
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
	return sni, rc
}

// ExtractTLSClientHelloSNI safely parses a TLS Record + ClientHello SNI extension without panics or OOB reads.
func ExtractTLSClientHelloSNI(b []byte) (string, bool) {
	// Need at least 5B TLS record header + 4B handshake header.
	if len(b) < 9 || b[0] != 0x16 || b[1] != 0x03 {
		return "", false
	}
	// Handshake type must be ClientHello (0x01).
	if b[5] != 0x01 {
		return "", false
	}
	hsLen := int(uint32(b[6])<<16 | uint32(b[7])<<8 | uint32(b[8]))
	recLen := int(binary.BigEndian.Uint16(b[3:5]))
	end := len(b)
	if 5+recLen < end {
		end = 5 + recLen
	}
	if 9+hsLen < end {
		end = 9 + hsLen
	}
	if end <= 9 {
		return "", false
	}
	hs := b[9:end]
	// ClientVersion(2) + Random(32) = 34 bytes
	off := 34
	if off+1 > len(hs) {
		return "", false
	}
	sidLen := int(hs[off])
	off += 1 + sidLen
	if off+2 > len(hs) {
		return "", false
	}
	csLen := int(binary.BigEndian.Uint16(hs[off : off+2]))
	off += 2 + csLen
	if off+1 > len(hs) {
		return "", false
	}
	cmLen := int(hs[off])
	off += 1 + cmLen
	if off+2 > len(hs) {
		return "", false
	}
	extTotal := int(binary.BigEndian.Uint16(hs[off : off+2]))
	off += 2
	extEnd := off + extTotal
	if extEnd > len(hs) {
		extEnd = len(hs)
	}
	for off+4 <= extEnd {
		extType := binary.BigEndian.Uint16(hs[off : off+2])
		extLen := int(binary.BigEndian.Uint16(hs[off+2 : off+4]))
		off += 4
		if extLen < 0 || off+extLen > extEnd {
			break
		}
		if extType == 0x0000 { // server_name
			if extLen < 2 {
				return "", false
			}
			listLen := int(binary.BigEndian.Uint16(hs[off : off+2]))
			p := off + 2
			limit := off + 2 + listLen
			if limit > off+extLen {
				limit = off + extLen
			}
			for p+3 <= limit {
				nameType := hs[p]
				nameLen := int(binary.BigEndian.Uint16(hs[p+1 : p+3]))
				p += 3
				if nameLen < 0 || p+nameLen > limit {
					return "", false
				}
				if nameType == 0x00 && nameLen > 0 && nameLen <= 253 {
					sni := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(string(hs[p:p+nameLen])), "."))
					if isValidSNIHost(sni) {
						return sni, true
					}
					return "", false
				}
				p += nameLen
			}
			return "", false
		}
		off += extLen
	}
	return "", false
}

func isValidSNIHost(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		isValid := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_'
		if !isValid {
			return false
		}
	}
	return strings.Contains(s, ".")
}
