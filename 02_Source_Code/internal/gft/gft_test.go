package gft

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

// TestRewindConn: after reading k bytes (k in several boundary values) and rewinding,
// the consumer must see the exact original byte sequence - nothing lost, nothing duplicated.
func TestRewindConn(t *testing.T) {
	const total = 4096
	for _, k := range []int{0, 1, 2, 55, 56, 56 + 0, 56 + 17, 56 + 63, 57, 1000, total} {
		orig := make([]byte, total)
		_, _ = rand.Read(orig)
		cli, srv := net.Pipe()
		go func() {
			_, _ = cli.Write(orig)
			_ = cli.Close()
		}()
		rc := NewRewindConn(srv)
		head := make([]byte, k)
		if _, err := io.ReadFull(rc, head); err != nil {
			t.Fatalf("k=%d: initial read: %v", k, err)
		}
		if !bytes.Equal(head, orig[:k]) {
			t.Fatalf("k=%d: head mismatch", k)
		}
		rc.Rewind()
		got, err := io.ReadAll(rc)
		if err != nil {
			t.Fatalf("k=%d: readall: %v", k, err)
		}
		if !bytes.Equal(got, orig) {
			t.Fatalf("k=%d: byte sequence differs (got %d bytes, want %d)", k, len(got), len(orig))
		}
		t.Logf("k=%-5d OK: replayed %d bytes identical to original", k, len(got))
	}
}

// TestRewindSmallReads ensures replay works when the consumer uses tiny buffers.
func TestRewindSmallReads(t *testing.T) {
	orig := make([]byte, 300)
	_, _ = rand.Read(orig)
	cli, srv := net.Pipe()
	go func() { _, _ = cli.Write(orig); _ = cli.Close() }()
	rc := NewRewindConn(srv)
	_, _ = io.ReadFull(rc, make([]byte, 120))
	rc.Rewind()
	var got []byte
	b := make([]byte, 7)
	for {
		n, err := rc.Read(b)
		got = append(got, b[:n]...)
		if err != nil {
			break
		}
	}
	if !bytes.Equal(got, orig) {
		t.Fatal("small-read replay mismatch")
	}
}

func TestKnock(t *testing.T) {
	psk := make([]byte, 32)
	_, _ = rand.Read(psk)
	now := time.Now()

	t.Run("correct", func(t *testing.T) {
		v := NewKnockVerifier(psk)
		k := BuildKnock(psk, now)
		pad, res := v.Check(k, now)
		if res != KnockOK || pad != len(k)-KnockLen {
			t.Fatalf("want OK pad=%d, got %v pad=%d", len(k)-KnockLen, res, pad)
		}
		t.Logf("correct knock accepted (pad=%d)", pad)
	})
	t.Run("wrong_hmac", func(t *testing.T) {
		v := NewKnockVerifier(psk)
		bad := make([]byte, 32)
		_, _ = rand.Read(bad)
		k := BuildKnock(bad, now)
		if _, res := v.Check(k, now); res != KnockBadHMAC {
			t.Fatalf("want hmac, got %v", res)
		}
		k2 := BuildKnock(psk, now)
		k2[30] ^= 0x01
		if _, res := v.Check(k2, now); res != KnockBadHMAC {
			t.Fatalf("tampered: want hmac, got %v", res)
		}
		t.Log("wrong/tampered HMAC rejected with reason=hmac")
	})
	t.Run("expired", func(t *testing.T) {
		v := NewKnockVerifier(psk)
		k := BuildKnock(psk, now.Add(-91*time.Second))
		if _, res := v.Check(k, now); res != KnockExpired {
			t.Fatalf("past: want expired, got %v", res)
		}
		k = BuildKnock(psk, now.Add(91*time.Second))
		if _, res := v.Check(k, now); res != KnockExpired {
			t.Fatalf("future: want expired, got %v", res)
		}
		k = BuildKnock(psk, now.Add(-89*time.Second))
		if _, res := v.Check(k, now); res != KnockOK {
			t.Fatalf("89s skew should pass, got %v", res)
		}
		t.Log("±91s rejected as expired; 89s skew accepted")
	})
	t.Run("replay", func(t *testing.T) {
		v := NewKnockVerifier(psk)
		k := BuildKnock(psk, now)
		if _, res := v.Check(k, now); res != KnockOK {
			t.Fatalf("first use: %v", res)
		}
		if _, res := v.Check(k, now.Add(5*time.Second)); res != KnockReplay {
			t.Fatalf("second use: want replay, got %v", res)
		}
		// after TTL the nonce expires from cache, but then the timestamp is outside the window anyway
		v.Sweep(now.Add(KnockReplayTTL + time.Second))
		if v.CacheSize() != 0 {
			t.Fatalf("sweep did not clear cache: %d", v.CacheSize())
		}
		t.Log("replayed knock rejected with reason=replay; cache swept after TTL")
	})
}

// TestServerKnockTimeoutAndRewind: half knock -> timeout; bytes are replayable.
func TestServerKnockHalfThenRewind(t *testing.T) {
	psk := make([]byte, 32)
	v := NewKnockVerifier(psk)
	cli, srv := net.Pipe()
	half := []byte("GET / HT") // 8 bytes, < 56
	go func() { _, _ = cli.Write(half) }()
	rc := NewRewindConn(srv)
	start := time.Now()
	res := v.ServerKnock(rc)
	if res != KnockTimeoutFail {
		t.Fatalf("want timeout, got %v", res)
	}
	if d := time.Since(start); d < 2900*time.Millisecond {
		t.Fatalf("returned too early: %v", d)
	}
	_ = rc.SetReadDeadline(time.Time{})
	rc.Rewind()
	go func() { _, _ = cli.Write([]byte("TP/1.1")); _ = cli.Close() }()
	got, _ := io.ReadAll(rc)
	if string(got) != "GET / HTTP/1.1" {
		t.Fatalf("got %q", got)
	}
	t.Logf("half knock timed out after %v, fallback saw %q", time.Since(start).Round(time.Millisecond), got)
}

// TestMuxEcho: two sessions over a pipe, echo through a stream with a large transfer (flow control).
func TestMuxEcho(t *testing.T) {
	a, b := net.Pipe()
	ps := NewParamStore(DefaultParams())
	srv := NewSession(b, false, ps, func(s *Stream, target string, first []byte) {
		defer s.Close()
		if target != "example.org:80" {
			t.Errorf("target %q", target)
		}
		buf := make([]byte, 8192)
		for {
			n, err := s.Read(buf)
			if n > 0 {
				if _, werr := s.Write(buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	})
	cli := NewSession(a, true, ps, nil)
	go srv.Run()
	go cli.Run()
	defer cli.Close()
	defer srv.Close()
	st, err := cli.OpenStream("example.org:80", nil)
	if err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 3<<20)
	_, _ = rand.Read(data)
	go func() { _, _ = st.Write(data); _ = st.CloseWrite() }()
	got, err := io.ReadAll(st)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("echo mismatch: %d vs %d", len(got), len(data))
	}
	t.Logf("echoed %d bytes through mux with flow control", len(got))
}

type memPacket struct {
	data []byte
	from net.Addr
}

type memPacketConn struct {
	local   net.Addr
	in      chan memPacket
	peer    *memPacketConn
	closed  chan struct{}
	once    sync.Once
	rMu     sync.Mutex
	rDeadln time.Time
}

func newMemPacketPair() (*memPacketConn, *memPacketConn) {
	a := &memPacketConn{
		local:  &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40001},
		in:     make(chan memPacket, 256),
		closed: make(chan struct{}),
	}
	b := &memPacketConn{
		local:  &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40002},
		in:     make(chan memPacket, 256),
		closed: make(chan struct{}),
	}
	a.peer = b
	b.peer = a
	return a, b
}

func (m *memPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		m.rMu.Lock()
		dl := m.rDeadln
		m.rMu.Unlock()
		var timerCh <-chan time.Time
		if !dl.IsZero() {
			d := time.Until(dl)
			if d <= 0 {
				return 0, nil, context.DeadlineExceeded
			}
			t := time.NewTimer(d)
			defer t.Stop()
			timerCh = t.C
		}
		select {
		case pkt := <-m.in:
			n := copy(p, pkt.data)
			return n, pkt.from, nil
		case <-m.closed:
			return 0, nil, net.ErrClosed
		case <-timerCh:
			return 0, nil, context.DeadlineExceeded
		}
	}
}

func (m *memPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	select {
	case <-m.closed:
		return 0, net.ErrClosed
	default:
	}
	cp := append([]byte(nil), p...)
	select {
	case m.peer.in <- memPacket{data: cp, from: m.local}:
	case <-m.peer.closed:
	default:
	}
	return len(p), nil
}

func (m *memPacketConn) Close() error {
	m.once.Do(func() { close(m.closed) })
	return nil
}
func (m *memPacketConn) LocalAddr() net.Addr                { return m.local }
func (m *memPacketConn) SetDeadline(t time.Time) error      { return m.SetReadDeadline(t) }
func (m *memPacketConn) SetWriteDeadline(_ time.Time) error { return nil }
func (m *memPacketConn) SetReadDeadline(t time.Time) error {
	m.rMu.Lock()
	m.rDeadln = t
	m.rMu.Unlock()
	return nil
}

// TestQUICStreamAndKnock verifies real quic-go TLS 1.3 handshake + Pinning + Knock + Mux
// over an in-memory PacketConn pair (independent of OS loopback UDP firewall rules).
func TestQUICStreamAndKnock(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     []string{"blog.example.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}

	psk := make([]byte, 32)
	_, _ = rand.Read(psk)
	link := &Link{
		V:         1,
		Host:      "127.0.0.1",
		Port:      40002,
		SNI:       "blog.example.test",
		PSK:       base64.StdEncoding.EncodeToString(psk),
		Pin:       PinOf(leaf),
		Transport: "quic",
	}

	srvPC, cliPC := newMemPacketPair()
	defer srvPC.Close()
	defer cliPC.Close()

	srvTLS := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"h3"},
	}
	qln, err := quic.Listen(srvPC, srvTLS, DefaultQUICConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer qln.Close()

	ps := NewParamStore(DefaultParams())
	verifier := NewKnockVerifier(psk)

	go func() {
		qc, err := qln.Accept(context.Background())
		if err != nil {
			return
		}
		st, err := qc.AcceptStream(context.Background())
		if err != nil {
			return
		}
		qsc := &QUICStreamConn{Stream: st, Conn: qc}
		rc := NewRewindConn(qsc)
		if res := verifier.ServerKnock(rc); res != KnockOK {
			_ = qsc.Close()
			return
		}
		rc.StopRecording()
		srv := NewSession(qsc, false, ps, func(s *Stream, target string, first []byte) {
			defer s.Close()
			if len(first) > 0 {
				_, _ = s.Write(first)
			}
			buf := make([]byte, 1024)
			for {
				n, err := s.Read(buf)
				if n > 0 {
					_, _ = s.Write(buf[:n])
				}
				if err != nil {
					return
				}
			}
		})
		_ = srv.Run()
	}()

	cliTLS, err := TLSConfigFor(link)
	if err != nil {
		t.Fatal(err)
	}
	cliTLS.NextProtos = []string{"h3"}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	qc, err := quic.Dial(ctx, cliPC, srvPC.LocalAddr(), cliTLS, DefaultQUICConfig())
	if err != nil {
		t.Fatalf("quic.Dial: %v", err)
	}
	defer qc.CloseWithError(0, "")

	st, err := qc.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	qsc := &QUICStreamConn{Stream: st, Conn: qc}
	if _, err := qsc.Write(BuildKnock(psk, time.Now())); err != nil {
		t.Fatal(err)
	}

	cli := NewSession(qsc, true, ps, nil)
	go func() { _ = cli.Run() }()
	defer cli.Close()

	s, err := cli.OpenStream("example.org:443", []byte("quic-0rtt|"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Write([]byte("ok")); err != nil {
		t.Fatal(err)
	}
	want := "quic-0rtt|ok"
	got := make([]byte, len(want))
	if _, err := io.ReadFull(s, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	_ = s.Close()

	// Verify bad Pin fails on TLSConfigFor
	bad := *link
	bad.Pin = strings.Repeat("00", 32)
	badCfg, _ := TLSConfigFor(&bad)
	if err := badCfg.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}); err == nil {
		t.Fatal("bad pin must be rejected")
	}
	t.Log("QUIC + Pinning + Knock + 0-RTT Mux OK")
}
