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

	"ghostframe/internal/gftrtc"

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
	if !bytes.HasPrefix([]byte(enc), []byte("gft3://")) {
		t.Fatalf("expected gft3:// prefix, got %s", enc)
	}
	dec, err := ParseLink(enc)
	if err != nil {
		t.Fatal(err)
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
