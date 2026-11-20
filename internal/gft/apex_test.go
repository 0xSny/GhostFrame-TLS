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
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ghostframe/internal/gftrtc"
	"ghostframe/internal/netbind"

	utls "github.com/refraction-networking/utls"
)

type testUDPAddr string

func (a testUDPAddr) Network() string { return "udp" }
func (a testUDPAddr) String() string  { return string(a) }

type testUDPPkt struct {
	data []byte
	from net.Addr
}

type testUDPSwitch struct {
	srvAddr  testUDPAddr
	srvConn  *testUDPEnd
	mu       sync.RWMutex
	clients  map[string]*testUDPEnd
	nextPort atomic.Int32
}

func newTestUDPSwitch(hubAddr string) *testUDPSwitch {
	sw := &testUDPSwitch{
		srvAddr: testUDPAddr(hubAddr),
		clients: make(map[string]*testUDPEnd),
	}
	sw.nextPort.Store(30000)
	sw.srvConn = &testUDPEnd{sw: sw, addr: sw.srvAddr, isSrv: true, recv: make(chan testUDPPkt, 1024), closed: make(chan struct{})}
	return sw
}

func (sw *testUDPSwitch) newClientEnd() *testUDPEnd {
	p := sw.nextPort.Add(1)
	addr := testUDPAddr(net.JoinHostPort("127.0.0.1", strconvItoa(int(p))))
	ce := &testUDPEnd{sw: sw, addr: addr, recv: make(chan testUDPPkt, 1024), closed: make(chan struct{})}
	sw.mu.Lock()
	sw.clients[string(addr)] = ce
	sw.mu.Unlock()
	return ce
}

func (sw *testUDPSwitch) closeAll() {
	_ = sw.srvConn.Close()
	sw.mu.RLock()
	for _, ce := range sw.clients {
		_ = ce.Close()
	}
	sw.mu.RUnlock()
}

func strconvItoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [12]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

type testUDPEnd struct {
	sw     *testUDPSwitch
	addr   testUDPAddr
	isSrv  bool
	recv   chan testUDPPkt
	closed chan struct{}
	once   sync.Once
	mu     sync.Mutex
	rDead  time.Time
}

func (e *testUDPEnd) ReadFrom(p []byte) (int, net.Addr, error) {
	e.mu.Lock()
	dl := e.rDead
	e.mu.Unlock()
	var timer <-chan time.Time
	if !dl.IsZero() {
		d := time.Until(dl)
		if d <= 0 {
			return 0, nil, context.DeadlineExceeded
		}
		t := time.NewTimer(d)
		defer t.Stop()
		timer = t.C
	}
	select {
	case pkt := <-e.recv:
		return copy(p, pkt.data), pkt.from, nil
	case <-e.closed:
		return 0, nil, net.ErrClosed
	case <-timer:
		return 0, nil, context.DeadlineExceeded
	}
}

func (e *testUDPEnd) WriteTo(p []byte, dst net.Addr) (int, error) {
	select {
	case <-e.closed:
		return 0, net.ErrClosed
	default:
	}
	var target *testUDPEnd
	if e.isSrv {
		e.sw.mu.RLock()
		if dst != nil {
			target = e.sw.clients[dst.String()]
		}
		e.sw.mu.RUnlock()
	} else {
		target = e.sw.srvConn
	}
	if target != nil {
		cp := make([]byte, len(p))
		copy(cp, p)
		select {
		case target.recv <- testUDPPkt{data: cp, from: e.addr}:
		default:
		}
	}
	return len(p), nil
}

func (e *testUDPEnd) Close() error {
	e.once.Do(func() { close(e.closed) })
	return nil
}
func (e *testUDPEnd) LocalAddr() net.Addr              { return e.addr }
func (e *testUDPEnd) SetDeadline(t time.Time) error    { return e.SetReadDeadline(t) }
func (e *testUDPEnd) SetWriteDeadline(time.Time) error { return nil }
func (e *testUDPEnd) SetReadDeadline(t time.Time) error {
	e.mu.Lock()
	e.rDead = t
	e.mu.Unlock()
	return nil
}

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
		HopRange:  "20000-40000",
		UpMbps:    30,
		DownMbps:  100,
		Remark:    "ApexNode",
	}
	enc := l.Encode()
	if !bytes.HasPrefix([]byte(enc), []byte("ksl4://")) {
		t.Fatalf("expected ksl4:// prefix, got %s", enc)
	}
	dec, err := ParseLink(enc)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseLink("gft3://" + enc[len("ksl4://"):]); err != nil {
		t.Fatalf("legacy gft3:// backward compatibility failed: %v", err)
	}
	lo, hi, ok := dec.ParseHopRange()
	if !ok || lo != 20000 || hi != 40000 || !dec.SplitSNI || dec.EffectiveTransport() != "auto" || dec.UpMbps != 30 || dec.DownMbps != 100 {
		t.Fatalf("unexpected decoded v3 fields: %+v", dec)
	}

	// Legacy "quic" transport seamlessly normalizes to "rtc"
	legacy := &Link{V: 3, Host: "example.com", Port: 443, SNI: "cdn.example.com", PSK: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", Verify: "ca", Transport: "quic"}
	if legacy.EffectiveTransport() != "rtc" {
		t.Fatalf("expected legacy 'quic' normalized to 'rtc', got %q", legacy.EffectiveTransport())
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

type memStreamConn struct {
	mu     sync.Mutex
	buf    []byte
	closed bool
	rDead  time.Time
	sig    chan struct{}
	done   chan struct{}
	peer   *memStreamConn
	local  net.Addr
	remote net.Addr
}

func newMemStreamPair() (net.Conn, net.Conn) {
	a := &memStreamConn{sig: make(chan struct{}, 1), done: make(chan struct{}), local: testTCPAddr("127.0.0.1:10001"), remote: testTCPAddr("127.0.0.1:10002")}
	b := &memStreamConn{sig: make(chan struct{}, 1), done: make(chan struct{}), local: testTCPAddr("127.0.0.1:10002"), remote: testTCPAddr("127.0.0.1:10001")}
	a.peer, b.peer = b, a
	return a, b
}

type testTCPAddr string

func (a testTCPAddr) Network() string { return "tcp" }
func (a testTCPAddr) String() string  { return string(a) }

func (m *memStreamConn) Read(p []byte) (int, error) {
	for {
		m.mu.Lock()
		if len(m.buf) > 0 {
			n := copy(p, m.buf)
			m.buf = m.buf[n:]
			m.mu.Unlock()
			return n, nil
		}
		if m.closed {
			m.mu.Unlock()
			return 0, io.EOF
		}
		dead := m.rDead
		m.mu.Unlock()

		var timer <-chan time.Time
		var tObj *time.Timer
		if !dead.IsZero() {
			d := time.Until(dead)
			if d <= 0 {
				return 0, osDeadlineErr{}
			}
			tObj = time.NewTimer(d)
			timer = tObj.C
		}
		select {
		case <-m.sig:
			if tObj != nil {
				tObj.Stop()
			}
		case <-m.done:
			if tObj != nil {
				tObj.Stop()
			}
		case <-timer:
			return 0, osDeadlineErr{}
		}
	}
}

type osDeadlineErr struct{}

func (osDeadlineErr) Error() string   { return "i/o timeout" }
func (osDeadlineErr) Timeout() bool   { return true }
func (osDeadlineErr) Temporary() bool { return true }

func (m *memStreamConn) Write(p []byte) (int, error) {
	m.mu.Lock()
	c := m.closed
	m.mu.Unlock()
	if c {
		return 0, net.ErrClosed
	}
	m.peer.mu.Lock()
	if m.peer.closed {
		m.peer.mu.Unlock()
		return 0, net.ErrClosed
	}
	m.peer.buf = append(m.peer.buf, p...)
	m.peer.mu.Unlock()
	select {
	case m.peer.sig <- struct{}{}:
	default:
	}
	return len(p), nil
}

func (m *memStreamConn) Close() error {
	m.mu.Lock()
	already := m.closed
	m.closed = true
	m.mu.Unlock()
	if !already {
		close(m.done)
		m.peer.mu.Lock()
		m.peer.closed = true
		m.peer.mu.Unlock()
		select {
		case m.peer.sig <- struct{}{}:
		default:
		}
	}
	return nil
}

func (m *memStreamConn) LocalAddr() net.Addr  { return m.local }
func (m *memStreamConn) RemoteAddr() net.Addr { return m.remote }
func (m *memStreamConn) SetDeadline(t time.Time) error {
	return m.SetReadDeadline(t)
}
func (m *memStreamConn) SetReadDeadline(t time.Time) error {
	m.mu.Lock()
	m.rDead = t
	m.mu.Unlock()
	select {
	case m.sig <- struct{}{}:
	default:
	}
	return nil
}
func (m *memStreamConn) SetWriteDeadline(time.Time) error { return nil }

func TestRecordSplitAndStegoSessionIDAndMirrorInspector(t *testing.T) {
	cert, pin := makeTestCertAndPin(t, "ftp.jaist.ac.jp")
	psk := make([]byte, 32)
	_, _ = rand.Read(psk)
	verifier := NewStegoVerifier(psk)

	a, b := newMemStreamPair()
	defer a.Close()
	defer b.Close()

	doneSrv := make(chan error, 1)
	go func() {
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
		_ = a.Close()
		var srvErr error
		select {
		case srvErr = <-doneSrv:
		case <-time.After(time.Second):
			srvErr = errors.New("server goroutine timed out")
		}
		t.Fatalf("client handshake=%v (srvErr=%v)", err, srvErr)
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

func TestRTCEngineStreamDatagramAndRTT(t *testing.T) {
	link := &Link{
		V:         3,
		Host:      "127.0.0.1",
		Port:      10443,
		SNI:       "ftp.jaist.ac.jp",
		PSK:       "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		Verify:    "ca",
		Transport: "rtc",
	}
	psk, _ := link.PSKBytes()
	ps := NewParamStore(DefaultParams())

	sw := newTestUDPSwitch("127.0.0.1:10443")
	defer sw.closeAll()

	ln, err := gftrtc.NewListener(sw.srvConn, false, psk, 0, MarshalParams(DefaultParams()))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		for {
			srvSess, aerr := ln.Accept(ctx)
			if aerr != nil {
				return
			}
			srvSess.SetHandlers(func(st *gftrtc.RTCStream, _ string, first []byte) {
				defer st.Close()
				if len(first) > 0 {
					_, _ = st.Write(first)
				}
				_, _ = io.Copy(st, st)
			}, func(sink gftrtc.UDPReplySink, id uint16, target string, data []byte) {
				_ = sink.SendUDPReply(id, target, append([]byte("pong:"), data...))
			}, nil)
		}
	}()

	ce := sw.newClientEnd()
	rs, _, err := DialRTCWithPacketConn(ctx, ce, true, sw.srvAddr, 10443, link, ps, 4*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer rs.Close()

	st, err := rs.OpenStream("example.org:443", []byte("hi|"))
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
		t.Fatalf("rtc stream mismatch got %d", len(got))
	}

	u, err := rs.OpenUDP()
	if err != nil {
		t.Fatal(err)
	}
	if err := u.SendTo("1.1.1.1:53", []byte("dns")); err != nil {
		t.Fatal(err)
	}
	select {
	case pkt := <-u.Recv():
		if string(pkt.Data) != "pong:dns" {
			t.Fatalf("unexpected rtc udp reply: %q", pkt.Data)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("rtc udp reply timeout")
	}
	_ = u.Close()

	rtt, err := rs.ProbeRTT(2 * time.Second)
	if err != nil || rtt <= 0 {
		t.Fatalf("expected positive rtc probe rtt, got %v err=%v", rtt, err)
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
	sched.SetRTCDialHookForTest(func(ctx context.Context, _ *Link, _ *ParamStore, _ int, _ time.Duration, _ [8]byte) (*gftrtc.RTCSession, time.Duration, error) {
		return nil, 0, errors.New("udp blocked")
	})

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
	psk, _ := link.PSKBytes()
	for i := 0; i < 15; i++ {
		sched := NewApexScheduler(link, ps, 1, nil)
		sched.SetDialJitterForTest(0, 0, 100)
		sched.pool.dialFn = func(_ context.Context, _ *Link, _ *ParamStore, _ uint16, _ time.Duration) (*Session, time.Duration, error) {
			time.Sleep(15 * time.Millisecond)
			return nil, 0, errors.New("mock tcp fail")
		}
		sw := newTestUDPSwitch("127.0.0.1:443")
		ln, _ := gftrtc.NewListener(sw.srvConn, false, psk, 0, nil)
		go func() {
			for {
				ss, err := ln.Accept(context.Background())
				if err != nil {
					return
				}
				ss.SetHandlers(nil, nil, nil)
			}
		}()
		var dialedOnce atomic.Bool
		sched.SetRTCDialHookForTest(func(ctx context.Context, dl *Link, dps *ParamStore, _ int, timeout time.Duration, clientID [8]byte) (*gftrtc.RTCSession, time.Duration, error) {
			if !dialedOnce.CompareAndSwap(false, true) {
				return nil, 0, errors.New("single test pair already claimed")
			}
			return DialRTCWithPacketConnAndID(ctx, sw.newClientEnd(), true, sw.srvAddr, 443, dl, dps, timeout, clientID)
		})
		_ = sched.Start(time.Second)
		sched.Close()
		_ = ln.Close()
		sw.closeAll()
	}
}

func TestApexSchedulerStripedRTCPoolHopAndSplitLimiters(t *testing.T) {
	link := &Link{
		V:         3,
		Host:      "127.0.0.1",
		Port:      443,
		SNI:       "ftp.jaist.ac.jp",
		PSK:       "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		Verify:    "ca",
		Transport: "rtc",
		HopRange:  "20000-40000",
	}
	psk, _ := link.PSKBytes()
	ps := NewParamStore(DefaultParams())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sw := newTestUDPSwitch("127.0.0.1:443")
	defer sw.closeAll()
	ln, err := gftrtc.NewListener(sw.srvConn, false, psk, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		for {
			ss, aerr := ln.Accept(ctx)
			if aerr != nil {
				return
			}
			ss.SetHandlers(func(st *gftrtc.RTCStream, _ string, first []byte) {
				defer st.Close()
				_, _ = st.Write(first)
			}, nil, nil)
		}
	}()

	sched := NewApexScheduler(link, ps, 2, nil)
	sched.SetDialJitterForTest(0, 0, 100)
	// Drain tcpLimiter tokens completely to prove rtcLimiter stays isolated and fast
	sched.tcpLimiter.mu.Lock()
	sched.tcpLimiter.tokens = 0
	sched.tcpLimiter.rate = 0.01
	sched.tcpLimiter.mu.Unlock()

	var pickedPortsMu sync.Mutex
	var pickedPorts []int
	sched.SetRTCDialHookForTest(func(dialCtx context.Context, dl *Link, dps *ParamStore, hopPort int, timeout time.Duration, clientID [8]byte) (*gftrtc.RTCSession, time.Duration, error) {
		pickedPortsMu.Lock()
		pickedPorts = append(pickedPorts, hopPort)
		pickedPortsMu.Unlock()
		return DialRTCWithPacketConnAndID(dialCtx, sw.newClientEnd(), true, sw.srvAddr, hopPort, dl, dps, timeout, clientID)
	})
	var hopCount atomic.Int32
	sched.SetRTCHopHookForTest(func(sess *gftrtc.RTCSession, nextPort int) error {
		hopCount.Add(1)
		return sess.HopWithPacketConn(sw.newClientEnd(), true, sw.srvAddr, nextPort)
	})
	sched.SetHopTimingsForTest(60*time.Millisecond, 60*time.Millisecond, 200*time.Millisecond, 25*time.Millisecond)

	t0 := time.Now()
	if err := sched.Start(3 * time.Second); err != nil {
		t.Fatalf("striped RTC Start failed: %v", err)
	}
	defer sched.Close()
	if time.Since(t0) > 2*time.Second {
		t.Fatalf("RTC dial was unexpectedly delayed by exhausted tcpLimiter (%v)", time.Since(t0))
	}

	stStats := sched.Stats()
	if stStats.ActiveConns != DefaultRTCPoolSize {
		t.Fatalf("expected %d active striped RTC conns, got %d", DefaultRTCPoolSize, stStats.ActiveConns)
	}
	pickedPortsMu.Lock()
	for _, p := range pickedPorts {
		if p < 20000 || p > 40000 {
			t.Fatalf("picked hop port %d outside 20000-40000", p)
		}
	}
	pickedPortsMu.Unlock()

	used := make(map[*gftrtc.RTCSession]int)
	for i := 0; i < 6; i++ {
		r := sched.activeRTCForSend()
		if r == nil {
			t.Fatal("expected active RTC session")
		}
		used[r]++
	}
	if len(used) != DefaultRTCPoolSize {
		t.Fatalf("expected load spread across %d RTC sessions, used %d", DefaultRTCPoolSize, len(used))
	}

	// Verify 0ms in-place port hop fires cleanly without breaking active sessions
	time.Sleep(150 * time.Millisecond)
	if hopCount.Load() == 0 {
		t.Fatalf("expected 0ms dynamic socket hop to fire")
	}
}

func TestSplitBandwidthAcrossDualRTCSessions(t *testing.T) {
	if SplitBandwidthMbps(0, 2) != 0 {
		t.Fatalf("expected 0 Mbps preserved for Auto-Probe")
	}
	if got := SplitBandwidthMbps(30, 2); got != 15 {
		t.Fatalf("expected 30/2=15, got %d", got)
	}
	if got := SplitBandwidthMbps(1, 4); got != 1 {
		t.Fatalf("expected min floor 1 Mbps, got %d", got)
	}

	sw := newTestUDPSwitch("127.0.0.1:443")
	defer sw.closeAll()

	link := &Link{
		V:         3,
		Host:      "127.0.0.1",
		Port:      443,
		SNI:       "ftp.jaist.ac.jp",
		PSK:       "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		Verify:    "ca",
		Transport: "rtc",
		HopRange:  "20000-40000",
		UpMbps:    30,
		DownMbps:  100,
	}
	psk, _ := link.PSKBytes()

	ln, err := gftrtc.NewListener(sw.srvConn, false, psk, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		for {
			ss, aerr := ln.Accept(ctx)
			if aerr != nil {
				return
			}
			go func() { <-ss.Done() }()
		}
	}()

	ps := NewParamStore(DefaultParams())
	sched := NewApexScheduler(link, ps, 1, nil)
	sched.SetDialJitterForTest(0, 0, 100)

	var seenUp, seenDown []int
	var seenMu sync.Mutex
	sched.SetRTCDialHookForTest(func(dialCtx context.Context, dl *Link, dps *ParamStore, hopPort int, timeout time.Duration, clientID [8]byte) (*gftrtc.RTCSession, time.Duration, error) {
		seenMu.Lock()
		seenUp = append(seenUp, dl.UpMbps)
		seenDown = append(seenDown, dl.DownMbps)
		seenMu.Unlock()
		return DialRTCWithPacketConnAndID(dialCtx, sw.newClientEnd(), true, sw.srvAddr, hopPort, dl, dps, timeout, clientID)
	})
	defer sched.Close()

	if err := sched.Start(3 * time.Second); err != nil {
		t.Fatalf("sched.Start failed: %v", err)
	}

	seenMu.Lock()
	if len(seenUp) != DefaultRTCPoolSize || seenUp[0] != 15 || seenDown[0] != 50 {
		seenMu.Unlock()
		t.Fatalf("expected split 15/50 Mbps per session, got up=%v down=%v", seenUp, seenDown)
	}
	seenMu.Unlock()

	sched.UpdateBandwidth(40, 120)
	sched.mu.Lock()
	for i, sl := range sched.rtcSlots {
		st := sl.sess.Stats()
		if st.PacingMbps < 19.0 || st.PacingMbps > 21.0 {
			sched.mu.Unlock()
			t.Fatalf("slot %d expected ~20 Mbps pacing after UpdateBandwidth(40,120), got %.2f", i, st.PacingMbps)
		}
	}
	sched.mu.Unlock()
}

func TestTCPCircuitBreakerCooldownAndInstantRTCFailoverWake(t *testing.T) {
	sw := newTestUDPSwitch("127.0.0.1:443")
	defer sw.closeAll()

	link := &Link{
		V:         3,
		Host:      "127.0.0.1",
		Port:      443,
		SNI:       "ftp.jaist.ac.jp",
		PSK:       "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		Verify:    "ca",
		Transport: "auto",
	}
	psk, _ := link.PSKBytes()

	ln, err := gftrtc.NewListener(sw.srvConn, false, psk, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		for {
			ss, aerr := ln.Accept(ctx)
			if aerr != nil {
				return
			}
			go func() { <-ss.Done() }()
		}
	}()

	ps := NewParamStore(DefaultParams())
	sched := NewApexScheduler(link, ps, 1, nil)
	sched.SetDialJitterForTest(0, 0, 100)
	sched.SetTCPBackoffForTest(15*time.Millisecond, 3*time.Second, 6*time.Second)
	sched.SetHopTimingsForTest(10*time.Second, 10*time.Second, 10*time.Second, 30*time.Millisecond)

	var tcpAttempts atomic.Int32
	sched.pool.dialFn = func(ctx context.Context, _ *Link, _ *ParamStore, _ uint16, _ time.Duration) (*Session, time.Duration, error) {
		tcpAttempts.Add(1)
		return nil, 0, errors.New("tcp port 443 blocked")
	}
	sched.SetRTCDialHookForTest(func(dialCtx context.Context, dl *Link, dps *ParamStore, hopPort int, timeout time.Duration, clientID [8]byte) (*gftrtc.RTCSession, time.Duration, error) {
		return DialRTCWithPacketConnAndID(dialCtx, sw.newClientEnd(), true, sw.srvAddr, hopPort, dl, dps, timeout, clientID)
	})
	defer sched.Close()

	if err := sched.Start(time.Second); err != nil {
		t.Fatalf("sched.Start failed: %v", err)
	}

	// Wait through 3 fast retries so circuit-breaker opens cooldown (3s)
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) && tcpAttempts.Load() < 3 {
		time.Sleep(10 * time.Millisecond)
	}
	if tcpAttempts.Load() < 3 {
		t.Fatalf("expected >=3 initial TCP attempts, got %d", tcpAttempts.Load())
	}
	countAtCooldown := tcpAttempts.Load()
	time.Sleep(180 * time.Millisecond)
	if tcpAttempts.Load() != countAtCooldown {
		t.Fatalf("expected circuit breaker to pause TCP dials during 3s cooldown, grew %d -> %d", countAtCooldown, tcpAttempts.Load())
	}

	// Close all RTC sessions and replace dial hook with failing hook so maintainLoop sees 0 healthy RTC sessions
	sched.SetRTCDialHookForTest(func(_ context.Context, _ *Link, _ *ParamStore, _ int, _ time.Duration, _ [8]byte) (*gftrtc.RTCSession, time.Duration, error) {
		return nil, 0, errors.New("rtc dead")
	})
	sched.mu.Lock()
	for _, sl := range sched.rtcSlots {
		sl.sess.Close()
	}
	sched.mu.Unlock()

	// TCP circuit breaker MUST wake up immediately (< 350ms, well before 3s cooldown!)
	wakeDeadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(wakeDeadline) && tcpAttempts.Load() == countAtCooldown {
		time.Sleep(15 * time.Millisecond)
	}
	if tcpAttempts.Load() == countAtCooldown {
		t.Fatalf("expected immediate TCP failover wakeup when all RTC sessions died")
	}
}

func TestNAT64DialV3StealthSynthesizes64ff9b(t *testing.T) {
	restore := netbind.SetNAT64TestHooks(
		func() bool { return true },
		func(ctx context.Context, host string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("64:ff9b::192.0.0.170")}, nil
		},
		nil,
	)
	defer restore()

	l := &Link{
		V:      4,
		Host:   "198.51.100.42",
		Port:   443,
		SNI:    "mirrors.mit.edu",
		PSK:    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		Verify: "ca",
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Millisecond)
	defer cancel()
	_, _, _, err := DialV3StealthWithID(ctx, l, 120*time.Millisecond, DefaultClientID)
	if err == nil {
		t.Fatalf("expected dial to unroutable test NAT64 target to fail")
	}
	if !strings.Contains(err.Error(), "64:ff9b::c633:642a") {
		t.Fatalf("expected DialV3StealthWithID to dial synthesized 64:ff9b::c633:642a, got err=%v", err)
	}
}

func TestEmergencyProbeFixedPortRebind(t *testing.T) {
	link := &Link{
		V:         4,
		Host:      "127.0.0.1",
		Port:      443,
		SNI:       "cdn.example.com",
		PSK:       "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		Verify:    "ca",
		Transport: "auto",
		HopRange:  "", // fixed port, no hopping range
	}
	// Create a live local RTC pair whose ProbeRTT will fail after closing server side
	cPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer cPC.Close()
	sPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	sPort := sPC.LocalAddr().(*net.UDPAddr).Port
	link.Port = sPort

	ps := NewParamStore(DefaultParams())
	sched := NewApexScheduler(link, ps, 1, nil)
	defer sched.Close()

	psk, _ := link.PSKBytes()
	ln, err := gftrtc.NewListener(sPC, true, psk, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	acceptedCh := make(chan *gftrtc.RTCSession, 1)
	go func() {
		srvSess, aerr := ln.Accept(context.Background())
		if aerr == nil && srvSess != nil {
			acceptedCh <- srvSess
		} else {
			acceptedCh <- nil
		}
	}()
	sess, _, err := gftrtc.DialWithPacketConn(context.Background(), cPC, false, sPC.LocalAddr(), gftrtc.DialOptions{
		Host:    "127.0.0.1",
		Port:    sPort,
		PSK:     psk,
		Timeout: time.Second,
	})
	if err != nil {
		ln.Close()
		t.Fatalf("DialWithPacketConn failed: %v", err)
	}
	defer sess.Close()
	if srvSess := <-acceptedCh; srvSess != nil {
		defer srvSess.Close()
	}
	ln.Close() // now ProbeRTT will time out cleanly

	sched.mu.Lock()
	sched.rtcSlots = []*rtcSlot{{sess: sess, channelIdx: 0}}
	var hoppedPort atomic.Int32
	sched.rtcHopFn = func(_ *gftrtc.RTCSession, newPort int) error {
		hoppedPort.Store(int32(newPort))
		return nil
	}
	sched.mu.Unlock()

	if closedAny := sched.handleEmergencyProbeAndHop(40*time.Millisecond, true); closedAny {
		t.Fatalf("expected fixed-port MBB rebind to recover without closing session")
	}
	if int(hoppedPort.Load()) != sPort {
		t.Fatalf("expected emergency rebind on fixed port %d, got %d", sPort, hoppedPort.Load())
	}
}
