package gft

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"io"
	"math/big"
	"net"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ghostframe/internal/sni"
)

type wireTapSnapshot struct {
	CipherSuite       uint16
	KeyShareGroup     uint16
	ExtOrder          []uint16
	SawCCS            bool
	Flight2Lens       []int
	PostTicketLens    []int
	HandshakeFinished bool
}

type serverWireTap struct {
	net.Conn
	inPostHandshake atomic.Bool
	doneHandshake   atomic.Bool

	mu      sync.Mutex
	snap    wireTapSnapshot
	hsAcc   []byte
	gotSH   bool
}

func (w *serverWireTap) Read(p []byte) (int, error) {
	n, err := w.Conn.Read(p)
	if n > 0 && w.gotSH && !w.doneHandshake.Load() {
		w.inPostHandshake.Store(true)
	}
	return n, err
}

func (w *serverWireTap) Write(p []byte) (int, error) {
	if !w.doneHandshake.Load() {
		w.observeOutbound(p)
	}
	return w.Conn.Write(p)
}

func (w *serverWireTap) observeOutbound(buf []byte) {
	w.mu.Lock()
	defer w.mu.Unlock()

	off := 0
	for off+5 <= len(buf) {
		recType := buf[off]
		recLen := int(binary.BigEndian.Uint16(buf[off+3 : off+5]))
		if off+5+recLen > len(buf) {
			break
		}
		payload := buf[off+5 : off+5+recLen]
		switch recType {
		case 0x16:
			w.hsAcc = append(w.hsAcc, payload...)
			w.parseSHLocked()
		case 0x14:
			w.snap.SawCCS = true
		case 0x17:
			if w.inPostHandshake.Load() {
				w.snap.PostTicketLens = append(w.snap.PostTicketLens, recLen)
			} else {
				w.snap.Flight2Lens = append(w.snap.Flight2Lens, recLen)
			}
		}
		off += 5 + recLen
	}
}

func (w *serverWireTap) parseSHLocked() {
	if w.gotSH || len(w.hsAcc) < 4 {
		return
	}
	hsType := w.hsAcc[0]
	hsLen := int(w.hsAcc[1])<<16 | int(w.hsAcc[2])<<8 | int(w.hsAcc[3])
	if len(w.hsAcc) < 4+hsLen {
		return
	}
	body := w.hsAcc[4 : 4+hsLen]
	if hsType != 0x02 || len(body) < 38 {
		return
	}
	sidLen := int(body[34])
	off := 35 + sidLen
	if off+3 > len(body) {
		return
	}
	w.snap.CipherSuite = binary.BigEndian.Uint16(body[off : off+2])
	off += 3
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
			w.snap.ExtOrder = append(w.snap.ExtOrder, extType)
			if extType == tlsExtKeyShare && len(extData) >= 2 {
				w.snap.KeyShareGroup = binary.BigEndian.Uint16(extData[0:2])
			}
			off += extLen
		}
	}
	w.gotSH = true
}

func (w *serverWireTap) snapshot() wireTapSnapshot {
	w.mu.Lock()
	defer w.mu.Unlock()
	cp := w.snap
	cp.ExtOrder = append([]uint16(nil), w.snap.ExtOrder...)
	cp.Flight2Lens = append([]int(nil), w.snap.Flight2Lens...)
	cp.PostTicketLens = append([]int(nil), w.snap.PostTicketLens...)
	return cp
}

func generateTestShadowCert(t *testing.T, sniName string) ([]byte, *ecdsa.PrivateKey, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     []string{sniName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pinSum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return der, key, hex.EncodeToString(pinSum[:])
}

func runShadowTLSRoundTrip(t *testing.T, fp string, prof *sni.CamouflageProfile, transferBytes int) wireTapSnapshot {
	t.Helper()
	const sniName = "ftp.jaist.ac.jp"
	certDER, key, pinHex := generateTestShadowCert(t, sniName)

	psk := make([]byte, 32)
	_, _ = rand.Read(psk)
	stego := NewStegoVerifier(psk)
	ps := NewParamStore(DefaultParams())

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	var wg sync.WaitGroup
	var tapRef atomic.Pointer[serverWireTap]
	srvErrCh := make(chan error, 1)

	wg.Add(1)
	go func() {
		defer wg.Done()
		raw, aerr := ln.Accept()
		if aerr != nil {
			srvErrCh <- aerr
			return
		}
		tap := &serverWireTap{Conn: raw}
		tapRef.Store(tap)

		rc := NewRewindConn(tap)
		if !MirrorInspector(rc, stego) {
			_ = raw.Close()
			srvErrCh <- io.ErrUnexpectedEOF
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		tlsConn, _, serr := PerformShadowTLS13Server(ctx, rc, certDER, key, prof)
		if serr != nil {
			_ = raw.Close()
			srvErrCh <- serr
			return
		}
		tap.doneHandshake.Store(true)

		authRC := NewRewindConn(tlsConn)
		salt, _, verr := stego.VerifyClientAuthFrameWithID(authRC)
		if verr != nil {
			_ = tlsConn.Close()
			srvErrCh <- verr
			return
		}
		authRC.StopRecording()
		ack, err := BuildServerAuthAck(psk, salt, ps.Get())
		if err != nil {
			_ = tlsConn.Close()
			srvErrCh <- err
			return
		}
		if _, err := authRC.Write(ack); err != nil {
			_ = tlsConn.Close()
			srvErrCh <- err
			return
		}

		srvSess := NewSession(authRC, false, ps, func(st *Stream, target string, first []byte) {
			defer st.Close()
			if len(first) > 0 {
				if _, werr := st.Write(first); werr != nil {
					return
				}
			}
			_, _ = io.Copy(st, st)
		})
		_ = srvSess.Run()
	}()

	link := &Link{
		V:         4,
		Host:      "127.0.0.1",
		Port:      port,
		SNI:       sniName,
		PSK:       encodeBase64Raw(psk),
		Verify:    "spki",
		Pin:       pinHex,
		FP:        fp,
		Transport: "tcp",
		SplitSNI:  false,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	sess, _, err := DialSessionWithID(ctx, link, ps, 0, 5*time.Second, DefaultClientID)
	if err != nil {
		t.Fatalf("fp=%s DialSessionWithID failed: %v", fp, err)
	}
	defer sess.Close()

	pingCh := make(chan time.Duration, 1)
	sess.SetOnPing(func(d time.Duration) {
		select {
		case pingCh <- d:
		default:
		}
	})
	if err := sess.SendPingReq(); err != nil {
		t.Fatalf("fp=%s SendPingReq failed: %v", fp, err)
	}
	select {
	case <-pingCh:
	case <-time.After(3 * time.Second):
		t.Fatalf("fp=%s timed out waiting for CmdPing ack", fp)
	}

	if transferBytes > 0 {
		st, err := sess.OpenStream("shadow-echo.test:443", nil)
		if err != nil {
			t.Fatalf("fp=%s OpenStream failed: %v", fp, err)
		}
		txPayload := bytes.Repeat([]byte("KESTREL-SHADOWTLS13-4MB-DATA!"), transferBytes/29+1)[:transferBytes]
		rxBuf := make([]byte, transferBytes)

		writeErrCh := make(chan error, 1)
		go func() {
			defer st.CloseWrite()
			_, werr := st.Write(txPayload)
			writeErrCh <- werr
		}()

		if _, err := io.ReadFull(st, rxBuf); err != nil {
			t.Fatalf("fp=%s ReadFull 4MB failed: %v", fp, err)
		}
		if werr := <-writeErrCh; werr != nil {
			t.Fatalf("fp=%s Write 4MB failed: %v", fp, werr)
		}
		_ = st.Close()
		if !bytes.Equal(rxBuf, txPayload) {
			t.Fatalf("fp=%s 4MB bidirectional echo mismatch", fp)
		}
	}

	sess.Close()
	wg.Wait()
	select {
	case serr := <-srvErrCh:
		t.Fatalf("fp=%s server error: %v", fp, serr)
	default:
	}

	tap := tapRef.Load()
	if tap == nil {
		t.Fatalf("fp=%s server wire tap missing", fp)
	}
	return tap.snapshot()
}

func encodeBase64Raw(b []byte) string {
	const alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	// Standard encoding without importing encoding/base64 separately, or use standard padding.
	var out []byte
	for i := 0; i < len(b); i += 3 {
		v := uint32(b[i]) << 16
		n := 1
		if i+1 < len(b) {
			v |= uint32(b[i+1]) << 8
			n = 2
		}
		if i+2 < len(b) {
			v |= uint32(b[i+2])
			n = 3
		}
		out = append(out, alpha[(v>>18)&63], alpha[(v>>12)&63])
		if n >= 2 {
			out = append(out, alpha[(v>>6)&63])
		} else {
			out = append(out, '=')
		}
		if n >= 3 {
			out = append(out, alpha[v&63])
		} else {
			out = append(out, '=')
		}
	}
	return string(out)
}

func TestShadowTLS13OpenSSLFingerprintAnd4MBDataAllClients(t *testing.T) {
	openSSLProfile := &sni.CamouflageProfile{
		CipherSuite:          tlsCipherAES256GCM, // 0x1302
		KeyShareGroup:        tlsGroupX25519,     // 0x001d
		ServerHelloExtOrder:  []uint16{tlsExtKeyShare, tlsExtSupportedVersions},
		SendCCS:              true,
		Flight2RecordLens:    []int{39, 2860, 281, 69},
		PostTicketRecordLens: []int{265, 265},
		ALPN:                 "h2",
	}

	for _, fp := range []string{"chrome", "ios", "firefox", "edge"} {
		t.Run("fp_"+fp, func(t *testing.T) {
			snap := runShadowTLSRoundTrip(t, fp, openSSLProfile, 4*1024*1024)
			if snap.CipherSuite != openSSLProfile.CipherSuite {
				t.Fatalf("CipherSuite mismatch: got 0x%04x want 0x%04x", snap.CipherSuite, openSSLProfile.CipherSuite)
			}
			if snap.KeyShareGroup != openSSLProfile.KeyShareGroup {
				t.Fatalf("KeyShareGroup mismatch: got 0x%04x want 0x%04x", snap.KeyShareGroup, openSSLProfile.KeyShareGroup)
			}
			if !reflect.DeepEqual(snap.ExtOrder, openSSLProfile.ServerHelloExtOrder) {
				t.Fatalf("ServerHelloExtOrder (JA3S/JA4S) mismatch: got %x want %x", snap.ExtOrder, openSSLProfile.ServerHelloExtOrder)
			}
			if !snap.SawCCS {
				t.Fatal("expected ChangeCipherSpec record before Flight 2")
			}
			if !reflect.DeepEqual(snap.Flight2Lens, openSSLProfile.Flight2RecordLens) {
				t.Fatalf("Flight2RecordLens mismatch: got %v want %v", snap.Flight2Lens, openSSLProfile.Flight2RecordLens)
			}
			if !reflect.DeepEqual(snap.PostTicketLens, openSSLProfile.PostTicketRecordLens) {
				t.Fatalf("PostTicketRecordLens mismatch: got %v want %v", snap.PostTicketLens, openSSLProfile.PostTicketRecordLens)
			}
		})
	}
}

func TestShadowTLS13CipherSuitesAndMLKEMAndFallback(t *testing.T) {
	// 1. AES-128-GCM (0x1301) with [0x002b, 0x0033] ext order.
	prof1301 := &sni.CamouflageProfile{
		CipherSuite:          tlsCipherAES128GCM,
		KeyShareGroup:        tlsGroupX25519,
		ServerHelloExtOrder:  []uint16{tlsExtSupportedVersions, tlsExtKeyShare},
		SendCCS:              false,
		Flight2RecordLens:    []int{45, 920, 128},
		PostTicketRecordLens: []int{240},
		ALPN:                 "h2",
	}
	snap1 := runShadowTLSRoundTrip(t, "chrome", prof1301, 512*1024)
	if snap1.CipherSuite != tlsCipherAES128GCM || snap1.SawCCS || !reflect.DeepEqual(snap1.Flight2Lens, prof1301.Flight2RecordLens) {
		t.Fatalf("0x1301 profile mismatch: %+v", snap1)
	}

	// 2. ChaCha20-Poly1305 (0x1303) + X25519MLKEM768 (0x11ec) with Chrome client.
	prof1303 := &sni.CamouflageProfile{
		CipherSuite:          tlsCipherChaCha20,
		KeyShareGroup:        tlsGroupX25519MLKEM,
		ServerHelloExtOrder:  []uint16{tlsExtKeyShare, tlsExtSupportedVersions},
		SendCCS:              true,
		Flight2RecordLens:    []int{40, 1100, 150},
		PostTicketRecordLens: []int{260},
		ALPN:                 "http/1.1",
	}
	snap3 := runShadowTLSRoundTrip(t, "chrome", prof1303, 512*1024)
	if snap3.CipherSuite != tlsCipherChaCha20 || snap3.KeyShareGroup != tlsGroupX25519MLKEM {
		t.Fatalf("0x1303/MLKEM profile mismatch: %+v", snap3)
	}

	// 3. Pre-write RewindConn fallback when profile has unsupported extension (e.g. 0x002c cookie/HRR).
	profFallback := &sni.CamouflageProfile{
		CipherSuite:         tlsCipherAES128GCM,
		KeyShareGroup:       tlsGroupX25519,
		ServerHelloExtOrder: []uint16{0x002c, tlsExtSupportedVersions, tlsExtKeyShare},
	}
	snapFB := runShadowTLSRoundTrip(t, "chrome", profFallback, 128*1024)
	if snapFB.CipherSuite == 0 || snapFB.KeyShareGroup == 0 {
		t.Fatalf("expected stdlib tls.Server fallback handshake to succeed cleanly, got %+v", snapFB)
	}
}

func TestShadowTLSRecordLayerZeroAlloc(t *testing.T) {
	prof := &sni.CamouflageProfile{
		CipherSuite:         tlsCipherAES128GCM,
		KeyShareGroup:       tlsGroupX25519,
		ServerHelloExtOrder: []uint16{tlsExtSupportedVersions, tlsExtKeyShare},
		Flight2RecordLens:   []int{45, 920, 128},
		ALPN:                "h2",
	}
	certDER, key, pinHex := generateTestShadowCert(t, "ftp.jaist.ac.jp")
	psk := make([]byte, 32)
	_, _ = rand.Read(psk)
	stego := NewStegoVerifier(psk)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	srvConnCh := make(chan net.Conn, 1)
	go func() {
		raw, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		rc := NewRewindConn(raw)
		if !MirrorInspector(rc, stego) {
			_ = raw.Close()
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		sc, _, serr := PerformShadowTLS13Server(ctx, rc, certDER, key, prof)
		if serr != nil {
			_ = raw.Close()
			return
		}
		srvConnCh <- sc
	}()

	link := &Link{
		V:         4,
		Host:      "127.0.0.1",
		Port:      ln.Addr().(*net.TCPAddr).Port,
		SNI:       "ftp.jaist.ac.jp",
		PSK:       encodeBase64Raw(psk),
		Verify:    "spki",
		Pin:       pinHex,
		FP:        "chrome",
		Transport: "tcp",
		SplitSNI:  false,
	}
	cliConn, _, _, err := DialV3StealthWithID(context.Background(), link, 5*time.Second, DefaultClientID)
	if err != nil {
		t.Fatalf("DialV3StealthWithID failed: %v", err)
	}
	defer cliConn.Close()

	srvConn := <-srvConnCh
	defer srvConn.Close()

	// Drain client's 112-byte ClientAuthFrame sent by DialV3StealthWithID.
	if _, _, err := stego.VerifyClientAuthFrameWithID(srvConn); err != nil {
		t.Fatalf("VerifyClientAuthFrameWithID failed: %v", err)
	}

	// Warm up sync.Pool on Write path without concurrent background goroutines polluting MemStats.
	msg := make([]byte, 1024)
	sink := make([]byte, 1024)
	if _, err := srvConn.Write(msg); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(cliConn, sink); err != nil {
		t.Fatal(err)
	}

	const writeRuns = 25
	if !testRaceEnabled {
		writeAllocs := testing.AllocsPerRun(writeRuns, func() {
			if _, werr := srvConn.Write(msg); werr != nil {
				t.Fatal(werr)
			}
		})
		if writeAllocs > 1 {
			t.Fatalf("expected <=1 heap allocs per shadowTLSConn.Write using pooled buffers, got %.2f", writeAllocs)
		}
		// Drain writes queued during warmup + writeRuns runs (AllocsPerRun executes fn 1 + writeRuns times).
		for i := 0; i < 1+writeRuns; i++ {
			if _, rerr := io.ReadFull(cliConn, sink); rerr != nil {
				t.Fatal(rerr)
			}
		}
	} else {
		for i := 0; i < writeRuns; i++ {
			if _, werr := srvConn.Write(msg); werr != nil {
				t.Fatal(werr)
			}
		}
		for i := 0; i < writeRuns; i++ {
			if _, rerr := io.ReadFull(cliConn, sink); rerr != nil {
				t.Fatal(rerr)
			}
		}
	}

	const readRuns = 25
	for i := 0; i < 2+readRuns; i++ {
		if _, werr := cliConn.Write(msg); werr != nil {
			t.Fatal(werr)
		}
	}
	if _, rerr := io.ReadFull(srvConn, sink); rerr != nil {
		t.Fatal(rerr)
	}

	if !testRaceEnabled {
		readAllocs := testing.AllocsPerRun(readRuns, func() {
			if _, rerr := io.ReadFull(srvConn, sink); rerr != nil {
				t.Fatal(rerr)
			}
		})
		if readAllocs > 1 {
			t.Fatalf("expected <=1 heap allocs per shadowTLSConn.Read using pooled buffers, got %.2f", readAllocs)
		}
	} else {
		for i := 0; i < 1+readRuns; i++ {
			if _, rerr := io.ReadFull(srvConn, sink); rerr != nil {
				t.Fatal(rerr)
			}
		}
	}
}

func TestProbeCamouflageProfileAgainstShadowTLS13PostTickets(t *testing.T) {
	want := &sni.CamouflageProfile{
		CipherSuite:          tlsCipherAES256GCM,
		KeyShareGroup:        tlsGroupX25519,
		ServerHelloExtOrder:  []uint16{tlsExtKeyShare, tlsExtSupportedVersions},
		SendCCS:              true,
		Flight2RecordLens:    []int{39, 1200, 128, 69},
		PostTicketRecordLens: []int{265, 265},
		ALPN:                 "h2",
	}
	certDER, key, _ := generateTestShadowCert(t, "origin.shadow.test")

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		raw, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		defer raw.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		sc, _, serr := PerformShadowTLS13Server(ctx, raw, certDER, key, want)
		if serr != nil {
			return
		}
		defer sc.Close()
		var buf [64]byte
		_ = sc.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
		_, _ = sc.Read(buf[:])
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	got, err := sni.ProbeCamouflageProfile(ctx, ln.Addr().String(), "origin.shadow.test")
	if err != nil {
		t.Fatalf("ProbeCamouflageProfile failed: %v", err)
	}
	<-done

	if got.CipherSuite != want.CipherSuite || got.KeyShareGroup != want.KeyShareGroup ||
		!reflect.DeepEqual(got.ServerHelloExtOrder, want.ServerHelloExtOrder) ||
		got.SendCCS != want.SendCCS ||
		!reflect.DeepEqual(got.Flight2RecordLens, want.Flight2RecordLens) ||
		!reflect.DeepEqual(got.PostTicketRecordLens, want.PostTicketRecordLens) ||
		got.ALPN != want.ALPN {
		t.Fatalf("round-trip profile mismatch:\n got: %+v\nwant: %+v", got, want)
	}
}

func TestProbeCamouflageProfileTrimsPostTicketHTTP2Preface(t *testing.T) {
	want := &sni.CamouflageProfile{
		CipherSuite:          tlsCipherAES256GCM,
		KeyShareGroup:        tlsGroupX25519,
		ServerHelloExtOrder:  []uint16{tlsExtKeyShare, tlsExtSupportedVersions},
		SendCCS:              true,
		Flight2RecordLens:    []int{39, 1200, 128, 69},
		PostTicketRecordLens: []int{265, 265},
		ALPN:                 "h2",
	}
	certDER, key, _ := generateTestShadowCert(t, "origin.shadow.test")

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		raw, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		defer raw.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		sc, _, serr := PerformShadowTLS13Server(ctx, raw, certDER, key, want)
		if serr != nil {
			return
		}
		defer sc.Close()
		// Simulate an upstream origin sending an HTTP/2 server SETTINGS preface immediately after tickets.
		h2Settings := []byte{0x00, 0x00, 0x06, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x64}
		_, _ = sc.Write(h2Settings)
		var buf [64]byte
		_ = sc.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		_, _ = sc.Read(buf[:])
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	got, err := sni.ProbeCamouflageProfile(ctx, ln.Addr().String(), "origin.shadow.test")
	if err != nil {
		t.Fatalf("ProbeCamouflageProfile failed: %v", err)
	}
	<-done

	if !reflect.DeepEqual(got.PostTicketRecordLens, want.PostTicketRecordLens) {
		t.Fatalf("expected HTTP/2 SETTINGS record stripped from PostTicketRecordLens, got %v want %v",
			got.PostTicketRecordLens, want.PostTicketRecordLens)
	}
}

func TestShadowTLS13CrossFingerprintKeyShareFallback(t *testing.T) {
	// Profile sampled from Chrome (0x11ec X25519MLKEM768) should negotiate cleanly with ios/firefox
	// clients that only offer classical X25519/P256 without falling back to stdlib tls.Server.
	chromeSampledProfile := &sni.CamouflageProfile{
		CipherSuite:          tlsCipherChaCha20,
		KeyShareGroup:        tlsGroupX25519MLKEM,
		ServerHelloExtOrder:  []uint16{tlsExtKeyShare, tlsExtSupportedVersions},
		SendCCS:              true,
		Flight2RecordLens:    []int{40, 1100, 150},
		PostTicketRecordLens: []int{260},
		ALPN:                 "h2",
	}

	for _, fp := range []string{"ios", "firefox"} {
		t.Run("fp_"+fp, func(t *testing.T) {
			snap := runShadowTLSRoundTrip(t, fp, chromeSampledProfile, 128*1024)
			if snap.CipherSuite != chromeSampledProfile.CipherSuite {
				t.Fatalf("CipherSuite mismatch: got 0x%04x want 0x%04x", snap.CipherSuite, chromeSampledProfile.CipherSuite)
			}
			if snap.KeyShareGroup != tlsGroupX25519 && snap.KeyShareGroup != tlsGroupP256 {
				t.Fatalf("expected negotiated X25519 or P256 group, got 0x%04x", snap.KeyShareGroup)
			}
			if !reflect.DeepEqual(snap.ExtOrder, chromeSampledProfile.ServerHelloExtOrder) {
				t.Fatalf("ServerHelloExtOrder mismatch: got %x want %x", snap.ExtOrder, chromeSampledProfile.ServerHelloExtOrder)
			}
			if !snap.SawCCS {
				t.Fatal("expected ChangeCipherSpec record before Flight 2")
			}
			if !reflect.DeepEqual(snap.Flight2Lens, chromeSampledProfile.Flight2RecordLens) {
				t.Fatalf("Flight2RecordLens mismatch: got %v want %v", snap.Flight2Lens, chromeSampledProfile.Flight2RecordLens)
			}
		})
	}
}
