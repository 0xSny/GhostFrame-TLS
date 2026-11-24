package sni

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	utls "github.com/refraction-networking/utls"
)

// helloRetryRequestRandom is the RFC 8446 §4.1.3 SHA-256("HelloRetryRequest") sentinel random.
var helloRetryRequestRandom = [32]byte{
	0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
	0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
	0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
	0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
}

// CamouflageProfile captures passive TLS 1.3 ServerHello, CCS, Flight 2 record sizing,
// and post-handshake NewSessionTicket record sizing observed from CamouflageTarget.
type CamouflageProfile struct {
	CipherSuite          uint16    `json:"cipher_suite"`
	KeyShareGroup        uint16    `json:"key_share_group"`
	ServerHelloExtOrder  []uint16  `json:"server_hello_ext_order"`
	SendCCS              bool      `json:"send_ccs"`
	Flight2RecordLens    []int     `json:"flight2_record_lens"`
	PostTicketRecordLens []int     `json:"post_ticket_record_lens"`
	ALPN                 string    `json:"alpn"`
	FetchedAt            time.Time `json:"fetched_at"`
}

// ProbeCamouflageProfile connects to targetHostPort using uTLS HelloChrome_Auto
// (32-byte non-empty SessionId, ALPN ["h2","http/1.1"]) and passively records
// the origin's TLS 1.3 ServerHello, CCS, Flight 2 0x17 record lengths, and
// post-handshake NewSessionTicket record lengths over a 120ms window.
func ProbeCamouflageProfile(ctx context.Context, targetHostPort, sniName string) (*CamouflageProfile, error) {
	return ProbeCamouflageProfileWithNetwork(ctx, "tcp", targetHostPort, sniName)
}

// ProbeCamouflageProfileWithNetwork is like ProbeCamouflageProfile, allowing callers
// to specify the TCP dial network (e.g. "tcp4" when IPv6 is disabled).
func ProbeCamouflageProfileWithNetwork(ctx context.Context, network, targetHostPort, sniName string) (*CamouflageProfile, error) {
	if strings.TrimSpace(network) == "" {
		network = "tcp"
	}
	target := strings.TrimSpace(targetHostPort)
	if target == "" {
		return nil, errors.New("sni: empty camouflage target")
	}
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		host = target
		target = net.JoinHostPort(target, "443")
	}
	if strings.TrimSpace(sniName) == "" && net.ParseIP(host) == nil {
		sniName = host
	}

	dialer := &net.Dialer{Timeout: 3 * time.Second}
	raw, err := dialer.DialContext(ctx, network, target)
	if err != nil {
		return nil, fmt.Errorf("sni: dial camouflage target %s: %w", target, err)
	}
	defer raw.Close()

	if dl, ok := ctx.Deadline(); ok {
		_ = raw.SetDeadline(dl)
	} else {
		_ = raw.SetDeadline(time.Now().Add(4 * time.Second))
	}

	tap := newProfileTapConn(raw)
	cache := &countingSessionCache{}
	ucfg := &utls.Config{
		ServerName:         sniName,
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"},
		ClientSessionCache: cache,
	}
	uc := utls.UClient(tap, ucfg, utls.HelloChrome_Auto)
	if err := uc.BuildHandshakeState(); err != nil {
		return nil, fmt.Errorf("sni: build utls ClientHello: %w", err)
	}
	if len(uc.HandshakeState.Hello.SessionId) != 32 {
		sid := make([]byte, 32)
		_, _ = rand.Read(sid)
		uc.HandshakeState.Hello.SessionId = sid
		uc.HandshakeState.Hello.Raw = nil
	}

	if err := uc.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("sni: camouflage handshake failed: %w", err)
	}
	tap.markFlight3Started()

	// Drain post-handshake NewSessionTicket records inside a 120ms window without sending HTTP traffic.
	_ = raw.SetReadDeadline(time.Now().Add(120 * time.Millisecond))
	var drain [4096]byte
	for {
		n, rerr := uc.Read(drain[:])
		if rerr != nil || n > 0 {
			break
		}
	}

	prof := tap.snapshot()
	if prof.CipherSuite == 0 {
		return nil, errors.New("sni: camouflage target did not return a TLS 1.3 ServerHello")
	}
	// Trim any post-handshake HTTP/2 preface / SETTINGS application records captured after the tickets.
	nTickets := int(cache.tickets.Load())
	if nTickets <= 0 {
		prof.PostTicketRecordLens = nil
	} else if nTickets < len(prof.PostTicketRecordLens) {
		prof.PostTicketRecordLens = prof.PostTicketRecordLens[:nTickets]
	}
	prof.ALPN = uc.ConnectionState().NegotiatedProtocol
	prof.FetchedAt = time.Now()
	return prof, nil
}

type countingSessionCache struct {
	tickets atomic.Int32
}

func (c *countingSessionCache) Get(_ string) (*utls.ClientSessionState, bool) {
	return nil, false
}

func (c *countingSessionCache) Put(_ string, cs *utls.ClientSessionState) {
	if cs != nil {
		c.tickets.Add(1)
	}
}

type profileTapConn struct {
	net.Conn
	sawServerHello atomic.Bool
	flight3Started atomic.Bool

	mu       sync.Mutex
	rawBuf   []byte
	hsBuf    []byte
	prof     CamouflageProfile
	gotSH    bool
	sawHRR   bool
}

func newProfileTapConn(c net.Conn) *profileTapConn {
	return &profileTapConn{Conn: c}
}

func (t *profileTapConn) markFlight3Started() {
	t.flight3Started.Store(true)
}

func (t *profileTapConn) Write(p []byte) (int, error) {
	if t.sawServerHello.Load() {
		t.flight3Started.Store(true)
	}
	return t.Conn.Write(p)
}

func (t *profileTapConn) Read(p []byte) (int, error) {
	n, err := t.Conn.Read(p)
	if n > 0 {
		t.observe(p[:n])
	}
	return n, err
}

func (t *profileTapConn) observe(chunk []byte) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.rawBuf = append(t.rawBuf, chunk...)
	for len(t.rawBuf) >= 5 {
		recLen := int(binary.BigEndian.Uint16(t.rawBuf[3:5]))
		if len(t.rawBuf) < 5+recLen {
			break
		}
		recType := t.rawBuf[0]
		payload := t.rawBuf[5 : 5+recLen]

		switch recType {
		case 0x16: // Handshake (ServerHello)
			t.hsBuf = append(t.hsBuf, payload...)
			t.tryParseServerHelloLocked()
		case 0x14: // ChangeCipherSpec
			t.prof.SendCCS = true
		case 0x17: // Encrypted Handshake / Post-Handshake Ticket / AppData
			if t.flight3Started.Load() {
				t.prof.PostTicketRecordLens = append(t.prof.PostTicketRecordLens, recLen)
			} else {
				t.prof.Flight2RecordLens = append(t.prof.Flight2RecordLens, recLen)
			}
		}
		t.rawBuf = t.rawBuf[5+recLen:]
	}
}

func (t *profileTapConn) tryParseServerHelloLocked() {
	for len(t.hsBuf) >= 4 {
		hsType := t.hsBuf[0]
		hsLen := int(t.hsBuf[1])<<16 | int(t.hsBuf[2])<<8 | int(t.hsBuf[3])
		if len(t.hsBuf) < 4+hsLen {
			return
		}
		body := t.hsBuf[4 : 4+hsLen]
		t.hsBuf = t.hsBuf[4+hsLen:]
		if hsType != 0x02 || len(body) < 38 {
			continue
		}
		if bytes.Equal(body[2:34], helloRetryRequestRandom[:]) {
			t.sawHRR = true
			continue
		}
		if t.gotSH {
			continue
		}
		sidLen := int(body[34])
		off := 35 + sidLen
		if off+3 > len(body) {
			continue
		}
		cipher := binary.BigEndian.Uint16(body[off : off+2])
		off += 3 // cipher_suite(2) + legacy_compression_method(1)
		var extOrder []uint16
		var ksGroup uint16
		if off+2 <= len(body) {
			extTotal := int(binary.BigEndian.Uint16(body[off : off+2]))
			off += 2
			end := off + extTotal
			if end > len(body) {
				end = len(body)
			}
			for off+4 <= end {
				extType := binary.BigEndian.Uint16(body[off : off+2])
				extLen := int(binary.BigEndian.Uint16(body[off+2 : off+4]))
				off += 4
				if off+extLen > end {
					break
				}
				extData := body[off : off+extLen]
				extOrder = append(extOrder, extType)
				if extType == 0x0033 && len(extData) >= 2 {
					ksGroup = binary.BigEndian.Uint16(extData[0:2])
				}
				off += extLen
			}
		}
		t.prof.CipherSuite = cipher
		t.prof.KeyShareGroup = ksGroup
		t.prof.ServerHelloExtOrder = extOrder
		t.gotSH = true
		t.sawServerHello.Store(true)
	}
}

func (t *profileTapConn) snapshot() *CamouflageProfile {
	t.mu.Lock()
	defer t.mu.Unlock()
	cp := t.prof
	cp.ServerHelloExtOrder = append([]uint16(nil), t.prof.ServerHelloExtOrder...)
	cp.Flight2RecordLens = append([]int(nil), t.prof.Flight2RecordLens...)
	cp.PostTicketRecordLens = append([]int(nil), t.prof.PostTicketRecordLens...)
	return &cp
}
