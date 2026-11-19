package gft

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	utls "github.com/refraction-networking/utls"
)

func TestGFT3LinkRoundTrip(t *testing.T) {
	l := &Link{
		V:         3,
		Host:      "example.com",
		Port:      443,
		SNI:       "cdn.example.com",
		PSK:       "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		Verify:    "spki",
		Pin:       "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		FP:        "chrome",
		Transport: "auto",
		SplitSNI:  true,
		HopRange:  "20000-30000",
		Remark:    "ApexNode",
	}
	enc := l.Encode()
	if !bytes.HasPrefix([]byte(enc), []byte("gft3://")) {
		t.Fatalf("expected gft3:// prefix, got %s", enc)
	}
	dec, err := ParseLink(enc)
	if err != nil {
		t.Fatal(err)
	}
	lo, hi, ok := dec.ParseHopRange()
	if !ok || lo != 20000 || hi != 30000 || !dec.SplitSNI || dec.EffectiveTransport() != "auto" {
		t.Fatalf("unexpected decoded v3 fields: %+v", dec)
	}
}

func makeTestCertAndPin(t *testing.T, sni string) (tls.Certificate, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     time.Now().Add(30 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{sni},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	kder, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder})
	tcert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return tcert, SPKIOf(leaf)
}

type spyWriteConn struct {
	net.Conn
	mu     sync.Mutex
	writes [][]byte
}

func (s *spyWriteConn) Write(p []byte) (int, error) {
	cp := make([]byte, len(p))
	copy(cp, p)
	s.mu.Lock()
	s.writes = append(s.writes, cp)
	s.mu.Unlock()
	return s.Conn.Write(p)
}

func TestRecordSplitAndStegoSessionIDAndMirrorInspector(t *testing.T) {
	cert, pin := makeTestCertAndPin(t, "ftp.jaist.ac.jp")
	psk := make([]byte, 32)
	_, _ = rand.Read(psk)
	verifier := NewStegoVerifier(psk)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	doneSrv := make(chan error, 1)
	go func() {
		b, aerr := ln.Accept()
		if aerr != nil {
			doneSrv <- aerr
			return
		}
		rc := NewRewindConn(b)
		if !MirrorInspector(rc, verifier) {
			doneSrv <- errors.New("mirror inspector failed valid client")
			return
		}
		tc := tls.Server(rc, &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13,
			NextProtos:   []string{"h2", "http/1.1"},
		})
		if err := tc.Handshake(); err != nil {
			doneSrv <- err
			return
		}
		salt, err := verifier.VerifyClientAuthFrame(tc)
		if err != nil {
			doneSrv <- err
			return
		}
		ack, err := BuildServerAuthAck(psk, salt, DefaultParams())
		if err != nil {
			doneSrv <- err
			return
		}
		_, err = tc.Write(ack)
		if err != nil {
			doneSrv <- err
			return
		}
		_ = tc.Close()
		doneSrv <- nil
	}()

	a, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	spy := &spyWriteConn{Conn: a}
	split := NewRecordSplitConn(spy)

	ucfg := &utls.Config{
		ServerName:         "ftp.jaist.ac.jp",
		MinVersion:         utls.VersionTLS13,
		NextProtos:         []string{"h2", "http/1.1"},
		InsecureSkipVerify: true,
	}
	_ = pin
	uc := utls.UClient(split, ucfg, utls.HelloChrome_Auto)
	if err := InjectStegoSessionID(uc, psk, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := uc.Handshake(); err != nil {
		t.Fatal(err)
	}
	authFrame, salt, err := BuildClientAuthFrame(psk, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := uc.Write(authFrame); err != nil {
		t.Fatal(err)
	}
	params, err := ReadServerAuthAck(uc, psk, salt)
	if err != nil {
		t.Fatal(err)
	}
	if params.HbMinMs != DefaultParams().HbMinMs {
		t.Fatalf("unexpected params from ack: %+v", params)
	}
	_ = uc.Close()
	if err := <-doneSrv; err != nil {
		t.Fatal(err)
	}

	// Verify ClientHello was split into >=2 TLS records across SNI
	spy.mu.Lock()
	var clientHelloRecs int
	for _, w := range spy.writes {
		if len(w) >= 5 && w[0] == 0x16 && w[1] == 0x03 {
			clientHelloRecs++
		} else {
			break
		}
	}
	spy.mu.Unlock()
	if clientHelloRecs < 2 {
		t.Fatalf("expected split ClientHello (>=2 records), got %d", clientHelloRecs)
	}
}

func TestMirrorInspectorRejectsProbeAndRewindsLossless(t *testing.T) {
	psk := make([]byte, 32)
	_, _ = rand.Read(psk)
	verifier := NewStegoVerifier(psk)

	// 1. Plaintext HTTP probe
	c1, s1 := net.Pipe()
	go func() {
		_, _ = c1.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
		_ = c1.Close()
	}()
	rc := NewRewindConn(s1)
	if MirrorInspector(rc, verifier) {
		t.Fatal("must reject plaintext HTTP probe")
	}
	raw, _ := io.ReadAll(rc)
	if string(raw) != "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n" {
		t.Fatalf("rewound probe mismatch: %q", raw)
	}

	// 2. Replay attack with identical SessionID + ClientRandom
	var cr [32]byte
	_, _ = rand.Read(cr[:])
	sid, err := MakeStegoSessionID(psk, cr[:], time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !verifier.VerifySessionID(sid[:], cr[:]) {
		t.Fatal("first verification should succeed")
	}
	if verifier.VerifySessionID(sid[:], cr[:]) {
		t.Fatal("replayed session id must be rejected")
	}
	var tampered [32]byte
	copy(tampered[:], cr[:])
	tampered[0] ^= 0xff
	sid2, _ := MakeStegoSessionID(psk, cr[:], time.Now())
	if verifier.VerifySessionID(sid2[:], tampered[:]) {
		t.Fatal("session id bound to wrong ClientRandom must be rejected")
	}
}

// memPacketConnPair creates an in-memory UDP-like PacketConn pair immune to OS firewall rules.
type memAddr string

func (a memAddr) Network() string { return "udp" }
func (a memAddr) String() string  { return string(a) }

type memPkt struct {
	data []byte
	from net.Addr
}

type memPacketConn struct {
	local  memAddr
	peer   *memPacketConn
	recv   chan memPkt
	closed chan struct{}
	once   sync.Once
	mu     sync.Mutex
	rDead  time.Time
}

func newMemPacketPair() (*memPacketConn, *memPacketConn) {
	a := &memPacketConn{local: memAddr("127.0.0.1:10001"), recv: make(chan memPkt, 256), closed: make(chan struct{})}
	b := &memPacketConn{local: memAddr("127.0.0.1:10443"), recv: make(chan memPkt, 256), closed: make(chan struct{})}
	a.peer = b
	b.peer = a
	return a, b
}

func (m *memPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	m.mu.Lock()
	dl := m.rDead
	m.mu.Unlock()
	var timer <-chan time.Time
	if !dl.IsZero() {
		d := time.Until(dl)
		if d <= 0 {
			return 0, nil, net.ErrClosed
		}
		t := time.NewTimer(d)
		defer t.Stop()
		timer = t.C
	}
	select {
	case pkt := <-m.recv:
		n := copy(p, pkt.data)
		return n, pkt.from, nil
	case <-m.closed:
		return 0, nil, net.ErrClosed
	case <-timer:
		return 0, nil, context.DeadlineExceeded
	}
}

func (m *memPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	select {
	case <-m.closed:
		return 0, net.ErrClosed
	default:
	}
	cp := make([]byte, len(p))
	copy(cp, p)
	select {
	case m.peer.recv <- memPkt{data: cp, from: m.local}:
		return len(p), nil
	default:
		return len(p), nil
	}
}

func (m *memPacketConn) Close() error {
	m.once.Do(func() { close(m.closed) })
	return nil
}

func (m *memPacketConn) LocalAddr() net.Addr              { return m.local }
func (m *memPacketConn) SetDeadline(t time.Time) error     { return m.SetReadDeadline(t) }
func (m *memPacketConn) SetWriteDeadline(t time.Time) error { return nil }
func (m *memPacketConn) SetReadDeadline(t time.Time) error {
	m.mu.Lock()
	m.rDead = t
	m.mu.Unlock()
	return nil
}

func TestAuthPacketConnFiltersUnknownAndAcceptsStego(t *testing.T) {
	psk := make([]byte, 32)
	_, _ = rand.Read(psk)
	verifier := NewStegoVerifier(psk)

	cRaw, sRaw := newMemPacketPair()
	defer cRaw.Close()
	defer sRaw.Close()

	authSrv := NewAuthPacketConn(sRaw, verifier)

	// Send random scan junk + bad QUIC initial + valid stego Initial
	_, _ = cRaw.WriteTo([]byte("DNS SCAN PROBE"), sRaw.LocalAddr())
	badCID := make([]byte, 16)
	_, _ = cRaw.WriteTo(BuildTestQUICInitialPacket(badCID, badCID, 1200), sRaw.LocalAddr())

	goodCID, err := MakeStegoQUICCID(psk, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	validPkt := BuildTestQUICInitialPacket(make([]byte, 8), goodCID[:], 1200)
	_, _ = cRaw.WriteTo(validPkt, sRaw.LocalAddr())

	buf := make([]byte, 2048)
	_ = authSrv.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, addr, err := authSrv.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1200 || addr == nil {
		t.Fatalf("unexpected read result n=%d addr=%v", n, addr)
	}
	if authSrv.Dropped() != 2 {
		t.Fatalf("expected 2 silent drops, got %d", authSrv.Dropped())
	}
}

func TestQUICEngineStreamDatagramAndRTT(t *testing.T) {
	psk := make([]byte, 32)
	_, _ = rand.Read(psk)
	cert, pin := makeTestCertAndPin(t, "ftp.jaist.ac.jp")
	link := &Link{
		V:         3,
		Host:      "127.0.0.1",
		Port:      10443,
		SNI:       "ftp.jaist.ac.jp",
		PSK:       "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		Verify:    "spki",
		Pin:       pin,
		Transport: "quic",
	}
	psk, _ = link.PSKBytes()
	verifier := NewStegoVerifier(psk)
	ps := NewParamStore(DefaultParams())

	cRaw, sRaw := newMemPacketPair()
	defer cRaw.Close()
	defer sRaw.Close()

	authSrv := NewAuthPacketConn(sRaw, verifier)
	srvTransport := &quic.Transport{Conn: authSrv}
	defer srvTransport.Close()

	ln, err := srvTransport.Listen(&tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"h3"},
	}, QUICConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		qconn, err := ln.Accept(ctx)
		if err != nil {
			return
		}
		_ = ServeQUICConn(ctx, qconn, verifier, ps, func(st DataStream, target string, first []byte) {
			defer st.Close()
			if len(first) > 0 {
				_, _ = st.Write(first)
			}
			_, _ = io.Copy(st, st)
		}, func(sink UDPReplySink, id uint16, target string, data []byte) {
			_ = sink.SendUDPReply(id, target, append([]byte("pong:"), data...))
		}, nil)
	}()

	qs, _, err := DialQUICWithPacketConn(ctx, cRaw, false, sRaw.LocalAddr(), 10443, link, ps, 4*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer qs.Close()
	defer cRaw.Close()
	defer sRaw.Close()

	// 1. Stream 0-RTT echo
	st, err := qs.OpenStream("example.org:443", []byte("hi|"))
	if err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 128*1024)
	_, _ = rand.Read(payload)
	go func() {
		_, _ = st.Write(payload)
		_ = st.CloseWrite()
	}()
	got, err := io.ReadAll(st)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got[:3], []byte("hi|")) || !bytes.Equal(got[3:], payload) {
		t.Fatalf("quic stream mismatch got %d", len(got))
	}

	// 2. RFC 9221 Datagram UDP
	u, err := qs.OpenUDP()
	if err != nil {
		t.Fatal(err)
	}
	if err := u.SendTo("1.1.1.1:53", []byte("dns")); err != nil {
		t.Fatal(err)
	}
	select {
	case pkt := <-u.Recv():
		if string(pkt.Data) != "pong:dns" {
			t.Fatalf("unexpected quic udp reply: %q", pkt.Data)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("quic udp reply timeout")
	}
	_ = u.Close()

	// 3. In-band RTT probe
	rtt, err := qs.ProbeRTT(2 * time.Second)
	if err != nil || rtt <= 0 {
		t.Fatalf("expected positive quic probe rtt, got %v err=%v", rtt, err)
	}
}

func TestApexSchedulerZeroMsFailoverToTCP(t *testing.T) {
	ps := NewParamStore(DefaultParams())
	link := &Link{
		V:         3,
		Host:      "example.com",
		Port:      443,
		SNI:       "example.com",
		PSK:       "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		Verify:    "ca",
		Transport: "auto",
	}
	sched := NewApexScheduler(link, ps, 2, nil)
	sched.SetDialJitterForTest(0, 0, 100)
	var mu sync.Mutex
	var srvConns []net.Conn
	defer func() {
		sched.Close()
		mu.Lock()
		for _, c := range srvConns {
			_ = c.Close()
		}
		mu.Unlock()
	}()

	// Mock TCP works; QUIC fails (simulates UDP blocked by GFW)
	sched.pool.dialFn = func(ctx context.Context, _ *Link, store *ParamStore, _ uint16, _ time.Duration) (*Session, time.Duration, error) {
		c, s := net.Pipe()
		srv := NewSession(s, false, store, func(st *Stream, target string, first []byte) {
			defer st.Close()
			_, _ = st.Write(append([]byte("tcp:"), first...))
		})
		go srv.Run()
		mu.Lock()
		srvConns = append(srvConns, s)
		mu.Unlock()
		cli := NewSession(c, true, store, nil)
		go cli.Run()
		return cli, 5 * time.Millisecond, nil
	}
	sched.quicDialFn = func(ctx context.Context, _ *Link, _ *ParamStore, _ int, _ time.Duration) (*QUICSession, time.Duration, error) {
		return nil, 0, errors.New("udp blocked")
	}

	if err := sched.Start(2 * time.Second); err != nil {
		t.Fatal(err)
	}
	st, err := sched.OpenStream("example.org:443", []byte("ok"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	buf := make([]byte, 32)
	n, _ := st.Read(buf)
	if string(buf[:n]) != "tcp:ok" {
		t.Fatalf("expected 0ms failover to TCP stream, got %q", buf[:n])
	}
	if stStats := sched.Stats(); stStats.Mode != "TCP-Fallback" {
		t.Fatalf("expected TCP-Fallback mode, got %+v", stStats)
	}
	_ = binary.BigEndian
}

func TestQUICUDPOversized1350And16KB(t *testing.T) {
	cert, pin := makeTestCertAndPin(t, "ftp.jaist.ac.jp")
	link := &Link{
		V:         3,
		Host:      "127.0.0.1",
		Port:      10443,
		SNI:       "ftp.jaist.ac.jp",
		PSK:       "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		Verify:    "spki",
		Pin:       pin,
		Transport: "quic",
	}
	psk, _ := link.PSKBytes()
	verifier := NewStegoVerifier(psk)
	ps := NewParamStore(DefaultParams())

	cRaw, sRaw := newMemPacketPair()
	defer cRaw.Close()
	defer sRaw.Close()

	authSrv := NewAuthPacketConn(sRaw, verifier)
	srvTransport := &quic.Transport{Conn: authSrv}
	defer srvTransport.Close()

	ln, err := srvTransport.Listen(&tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"h3"},
	}, QUICConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		qconn, err := ln.Accept(ctx)
		if err != nil {
			return
		}
		_ = ServeQUICConn(ctx, qconn, verifier, ps, nil,
			func(sink UDPReplySink, id uint16, target string, data []byte) {
				// Echo exact payload back so both directions test fragmentation and stream fallback.
				_ = sink.SendUDPReply(id, target, data)
			}, nil)
	}()

	qs, _, err := DialQUICWithPacketConn(ctx, cRaw, false, sRaw.LocalAddr(), 10443, link, ps, 4*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer qs.Close()
	defer cRaw.Close()
	defer sRaw.Close()

	u, err := qs.OpenUDP()
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()

	// Test sizes spanning:
	// - 300B: single QUIC datagram (0x01)
	// - 1350B: fragmented RFC 9221 QUIC datagram (0x03) - typical QUIC/H3 packet
	// - 4500B: multi-fragment RFC 9221 QUIC datagram (0x03)
	// - 16384B: QUIC multiplexed UDP stream fallback (quicStreamUDP = 0x03)
	for _, sz := range []int{300, 1350, 4500, 16384} {
		payload := make([]byte, sz)
		_, _ = rand.Read(payload)
		if err := u.SendTo("1.1.1.1:443", payload); err != nil {
			t.Fatalf("SendTo(%dB) error: %v", sz, err)
		}
		select {
		case pkt := <-u.Recv():
			if len(pkt.Data) != sz || !bytes.Equal(pkt.Data, payload) {
				t.Fatalf("echo mismatch for %dB packet: got %dB", sz, len(pkt.Data))
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("timeout waiting for %dB UDP echo reply", sz)
		}
	}
}

func TestApexSchedulerRapidStartCloseNoWaitGroupRace(t *testing.T) {
	ps := NewParamStore(DefaultParams())
	link := &Link{
		V:         3,
		Host:      "127.0.0.1",
		Port:      1,
		SNI:       "ftp.jaist.ac.jp",
		PSK:       "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		Verify:    "ca",
		Transport: "auto",
	}
	for i := 0; i < 20; i++ {
		sched := NewApexScheduler(link, ps, 1, nil)
		sched.SetDialJitterForTest(0, 0, 100)
		// Force r1 (tcp) immediate failure and r2 (quic) immediate mock success so Start launches async r2 wait goroutine
		sched.pool.dialFn = func(_ context.Context, _ *Link, _ *ParamStore, _ uint16, _ time.Duration) (*Session, time.Duration, error) {
			time.Sleep(15 * time.Millisecond)
			return nil, 0, errors.New("mock tcp fail")
		}
		cRaw, sRaw := newMemPacketPair()
		cert, pin := makeTestCertAndPin(t, "ftp.jaist.ac.jp")
		link.Verify = "spki"
		link.Pin = pin
		srvTr := &quic.Transport{Conn: sRaw}
		ln, lerr := srvTr.Listen(&tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13, NextProtos: []string{"h3"}}, QUICConfig())
		if lerr != nil {
			_ = cRaw.Close()
			_ = sRaw.Close()
			t.Fatal(lerr)
		}
		go func() {
			qc, err := ln.Accept(context.Background())
			if err == nil {
				go func() { _ = ServeQUICConn(context.Background(), qc, NewStegoVerifier(make([]byte, 32)), ps, nil, nil, nil) }()
			}
		}()
		var dialedOnce atomic.Bool
		sched.SetQUICDialHookForTest(func(ctx context.Context, dl *Link, dps *ParamStore, _ int, timeout time.Duration, clientID [8]byte) (*QUICSession, time.Duration, error) {
			if !dialedOnce.CompareAndSwap(false, true) {
				return nil, 0, errors.New("single test pair already claimed")
			}
			return DialQUICWithPacketConnAndID(ctx, cRaw, true, sRaw.LocalAddr(), 443, dl, dps, timeout, clientID)
		})
		_ = sched.Start(time.Second)
		sched.Close()
		_ = ln.Close()
		_ = sRaw.Close()
		_ = srvTr.Close()
	}
}

func TestApexSchedulerStripedQUICPoolAndSplitLimiters(t *testing.T) {
	if QUICConfig().InitialPacketSize != 1250 {
		t.Fatalf("expected InitialPacketSize=1250, got %d", QUICConfig().InitialPacketSize)
	}

	cert, pin := makeTestCertAndPin(t, "ftp.jaist.ac.jp")
	link := &Link{
		V:         3,
		Host:      "127.0.0.1",
		Port:      443,
		SNI:       "ftp.jaist.ac.jp",
		PSK:       "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		Verify:    "spki",
		Pin:       pin,
		Transport: "quic",
		HopRange:  "20000-40000",
	}
	psk, _ := link.PSKBytes()
	verifier := NewStegoVerifier(psk)
	ps := NewParamStore(DefaultParams())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var cleanMu sync.Mutex
	var cleanClosers []func()
	defer func() {
		cleanMu.Lock()
		for _, fn := range cleanClosers {
			fn()
		}
		cleanMu.Unlock()
	}()

	sched := NewApexScheduler(link, ps, 2, nil)
	sched.SetDialJitterForTest(0, 0, 100)
	// Drain tcpLimiter tokens completely to prove quicLimiter stays isolated and fast
	sched.tcpLimiter.mu.Lock()
	sched.tcpLimiter.tokens = 0
	sched.tcpLimiter.rate = 0.01
	sched.tcpLimiter.mu.Unlock()

	var pickedPortsMu sync.Mutex
	var pickedPorts []int
	sched.SetQUICDialHookForTest(func(dialCtx context.Context, dl *Link, dps *ParamStore, hopPort int, timeout time.Duration, clientID [8]byte) (*QUICSession, time.Duration, error) {
		pickedPortsMu.Lock()
		pickedPorts = append(pickedPorts, hopPort)
		pickedPortsMu.Unlock()

		cRaw, sRaw := newMemPacketPair()
		srvTr := &quic.Transport{Conn: NewAuthPacketConn(sRaw, verifier)}
		ln, lerr := srvTr.Listen(&tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13,
			NextProtos:   []string{"h3"},
		}, QUICConfig())
		if lerr != nil {
			_ = cRaw.Close()
			_ = sRaw.Close()
			return nil, 0, lerr
		}
		go func() {
			qc, aerr := ln.Accept(ctx)
			if aerr != nil {
				return
			}
			_ = ServeQUICConn(ctx, qc, verifier, ps, func(st DataStream, target string, first []byte) {
				defer st.Close()
				_, _ = st.Write(first)
			}, nil, nil)
		}()
		cleanMu.Lock()
		cleanClosers = append(cleanClosers, func() {
			_ = ln.Close()
			_ = sRaw.Close()
			_ = cRaw.Close()
			_ = srvTr.Close()
		})
		cleanMu.Unlock()

		return DialQUICWithPacketConnAndID(dialCtx, cRaw, true, sRaw.LocalAddr(), hopPort, dl, dps, timeout, clientID)
	})

	t0 := time.Now()
	if err := sched.Start(3 * time.Second); err != nil {
		t.Fatalf("striped QUIC Start failed: %v", err)
	}
	defer sched.Close()
	if time.Since(t0) > 2*time.Second {
		t.Fatalf("QUIC dial was unexpectedly delayed by exhausted tcpLimiter (%v)", time.Since(t0))
	}

	stStats := sched.Stats()
	if stStats.ActiveConns != DefaultQUICPoolSize {
		t.Fatalf("expected %d active striped QUIC conns, got %d", DefaultQUICPoolSize, stStats.ActiveConns)
	}
	pickedPortsMu.Lock()
	for _, p := range pickedPorts {
		if p < 20000 || p > 40000 {
			t.Fatalf("picked hop port %d outside 20000-40000", p)
		}
	}
	pickedPortsMu.Unlock()

	// Verify streams spread across multiple QUIC sessions via least-loaded + RR
	used := make(map[*QUICSession]int)
	for i := 0; i < 6; i++ {
		q := sched.activeQUICForSend()
		if q == nil {
			t.Fatal("expected active QUIC session")
		}
		used[q]++
	}
	if len(used) != DefaultQUICPoolSize {
		t.Fatalf("expected load spread across %d QUIC sessions, used %d", DefaultQUICPoolSize, len(used))
	}
}
