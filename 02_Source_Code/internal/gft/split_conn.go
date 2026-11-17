package gft

import (
	"crypto/rand"
	"encoding/binary"
	"net"
	"sync/atomic"
	"time"
)

// RecordSplitConn splits ONLY the first TLS ClientHello record across the SNI
// hostname into 2-3 valid TLS Handshake records with tiny jitter, then passes
// all subsequent reads/writes directly through with zero overhead.
type RecordSplitConn struct {
	net.Conn
	done atomic.Bool
}

// NewRecordSplitConn wraps conn so the first ClientHello TLS record is fragmented.
func NewRecordSplitConn(conn net.Conn) *RecordSplitConn {
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}
	return &RecordSplitConn{Conn: conn}
}

func (c *RecordSplitConn) Write(p []byte) (int, error) {
	if c.done.Load() {
		return c.Conn.Write(p)
	}
	if !c.done.CompareAndSwap(false, true) {
		return c.Conn.Write(p)
	}
	if len(p) < 10 || p[0] != 0x16 || p[1] != 0x03 {
		return c.Conn.Write(p)
	}
	recLen := int(binary.BigEndian.Uint16(p[3:5]))
	if recLen < 32 || 5+recLen > len(p) {
		return c.Conn.Write(p)
	}
	verHi, verLo := p[1], p[2]
	body := p[5 : 5+recLen]
	rest := p[5+recLen:]

	cut1, cut2 := chooseSplitPoints(body)
	var cuts []int
	if cut1 > 0 && cut1 < len(body) {
		cuts = append(cuts, cut1)
	}
	if cut2 > cut1 && cut2 < len(body) {
		cuts = append(cuts, cut2)
	}
	if len(cuts) == 0 {
		return c.Conn.Write(p)
	}

	var hdr [5]byte
	hdr[0] = 0x16
	hdr[1] = verHi
	hdr[2] = verLo

	prev := 0
	for _, end := range cuts {
		seg := body[prev:end]
		if err := c.writeRecord(&hdr, seg); err != nil {
			return 0, err
		}
		prev = end
		jitterSleep(0, 5)
	}
	if err := c.writeRecord(&hdr, body[prev:]); err != nil {
		return 0, err
	}
	if len(rest) > 0 {
		if err := writeAll(c.Conn, rest); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

func (c *RecordSplitConn) writeRecord(hdr *[5]byte, payload []byte) error {
	binary.BigEndian.PutUint16(hdr[3:5], uint16(len(payload)))
	buf := make([]byte, 5+len(payload))
	copy(buf[:5], hdr[:])
	copy(buf[5:], payload)
	return writeAll(c.Conn, buf)
}

func writeAll(c net.Conn, b []byte) error {
	for len(b) > 0 {
		n, err := c.Write(b)
		if err != nil {
			return err
		}
		b = b[n:]
	}
	return nil
}

func chooseSplitPoints(body []byte) (int, int) {
	sniStart, sniEnd, ok := locateClientHelloSNI(body)
	var mid int
	if ok && sniEnd > sniStart {
		mid = (sniStart + sniEnd) / 2
	} else {
		mid = len(body) / 3
	}
	mid += randSignedJitter(4)
	if mid < 12 {
		mid = 12
	}
	if mid >= len(body)-12 {
		mid = len(body) / 2
	}
	cut2 := 0
	if len(body)-mid > 120 {
		cut2 = mid + (len(body)-mid)/2 + randSignedJitter(4)
		if cut2 <= mid+8 || cut2 >= len(body)-8 {
			cut2 = 0
		}
	}
	return mid, cut2
}

// locateClientHelloSNI finds the server_name byte range within a ClientHello handshake message.
func locateClientHelloSNI(body []byte) (int, int, bool) {
	// Handshake header (4): type(1)=0x01, len(3)
	// Version (2) + Random (32) + SessionIDLen (1) = 39
	if len(body) < 40 || body[0] != 0x01 {
		return 0, 0, false
	}
	pos := 38
	sidLen := int(body[pos])
	pos += 1 + sidLen
	if pos+2 > len(body) {
		return 0, 0, false
	}
	csLen := int(binary.BigEndian.Uint16(body[pos : pos+2]))
	pos += 2 + csLen
	if pos+1 > len(body) {
		return 0, 0, false
	}
	compLen := int(body[pos])
	pos += 1 + compLen
	if pos+2 > len(body) {
		return 0, 0, false
	}
	extTotal := int(binary.BigEndian.Uint16(body[pos : pos+2]))
	pos += 2
	extEnd := pos + extTotal
	if extEnd > len(body) {
		extEnd = len(body)
	}
	for pos+4 <= extEnd {
		extType := binary.BigEndian.Uint16(body[pos : pos+2])
		extLen := int(binary.BigEndian.Uint16(body[pos+2 : pos+4]))
		pos += 4
		if pos+extLen > extEnd {
			break
		}
		if extType == 0x0000 && extLen >= 5 {
			// ServerNameList len (2), NameType (1), HostName len (2), HostName
			nameLen := int(binary.BigEndian.Uint16(body[pos+3 : pos+5]))
			start := pos + 5
			if start+nameLen <= pos+extLen && nameLen > 0 {
				return start, start + nameLen, true
			}
			return pos, pos + extLen, true
		}
		pos += extLen
	}
	return 0, 0, false
}

func randSignedJitter(maxAbs int) int {
	if maxAbs <= 0 {
		return 0
	}
	var b [1]byte
	_, _ = rand.Read(b[:])
	span := 2*maxAbs + 1
	return int(b[0])%span - maxAbs
}

func jitterSleep(minMs, maxMs int) {
	if maxMs <= minMs {
		if minMs > 0 {
			time.Sleep(time.Duration(minMs) * time.Millisecond)
		}
		return
	}
	ms := randRange(minMs, maxMs)
	if ms > 0 {
		time.Sleep(time.Duration(ms) * time.Millisecond)
	}
}
