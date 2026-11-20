package gft

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ghostframe/internal/gftrtc"
)

func buildTestTLSClientHello(sni string) []byte {
	var ext []byte
	if sni != "" {
		nameBytes := []byte(sni)
		sniEntryLen := 1 + 2 + len(nameBytes)
		extLen := 2 + sniEntryLen
		ext = make([]byte, 4+extLen)
		binary.BigEndian.PutUint16(ext[0:2], 0x0000)
		binary.BigEndian.PutUint16(ext[2:4], uint16(extLen))
		binary.BigEndian.PutUint16(ext[4:6], uint16(sniEntryLen))
		ext[6] = 0x00
		binary.BigEndian.PutUint16(ext[7:9], uint16(len(nameBytes)))
		copy(ext[9:], nameBytes)
	}
	var body []byte
	body = append(body, 0x03, 0x03)             // ClientVersion TLS 1.2
	body = append(body, make([]byte, 32)...)    // Random
	body = append(body, 0x00)                   // SessionID len
	body = append(body, 0x00, 0x02, 0x13, 0x01) // CipherSuites
	body = append(body, 0x01, 0x00)             // CompressionMethods
	body = binary.BigEndian.AppendUint16(body, uint16(len(ext)))
	body = append(body, ext...)

	hs := make([]byte, 4+len(body))
	hs[0] = 0x01
	hs[1] = byte(len(body) >> 16)
	hs[2] = byte(len(body) >> 8)
	hs[3] = byte(len(body))
	copy(hs[4:], body)

	rec := make([]byte, 5+len(hs))
	rec[0] = 0x16
	rec[1] = 0x03
	rec[2] = 0x01
	binary.BigEndian.PutUint16(rec[3:5], uint16(len(hs)))
	copy(rec[5:], hs)
	return rec
}

func TestSNISniffAndRewindLossless(t *testing.T) {
	ch := buildTestTLSClientHello("api.youtube.com")
	trailing := []byte("FOLLOWING-APPLICATION-BYTES-1234567890")
	full := append(append([]byte(nil), ch...), trailing...)

	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	go func() {
		mid := 12
		_, _ = c1.Write(ch[:mid])
		time.Sleep(4 * time.Millisecond)
		_, _ = c1.Write(ch[mid:])
		_, _ = c1.Write(trailing)
		_ = c1.Close()
	}()

	sni, rc := SniffTLSSNI(c2, 100*time.Millisecond)
	if sni != "api.youtube.com" {
		t.Fatalf("expected sniffed SNI api.youtube.com, got %q", sni)
	}
	replayed, err := io.ReadAll(rc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(replayed, full) {
		t.Fatalf("lossless rewind mismatch: got %dB want %dB", len(replayed), len(full))
	}

	// Non-TLS banner must exit early without waiting full timeout and preserve every byte
	n1, n2 := net.Pipe()
	defer n1.Close()
	defer n2.Close()
	banner := []byte("SSH-2.0-OpenSSH_9.6\r\n")
	go func() {
		_, _ = n1.Write(banner)
		_ = n1.Close()
	}()
	t0 := time.Now()
	sni2, rc2 := SniffTLSSNI(n2, 300*time.Millisecond)
	if time.Since(t0) > 150*time.Millisecond {
		t.Fatalf("non-TLS sniff waited too long: %v", time.Since(t0))
	}
	if sni2 != "" {
		t.Fatalf("expected empty SNI for SSH banner, got %q", sni2)
	}
	gotBanner, _ := io.ReadAll(rc2)
	if !bytes.Equal(gotBanner, banner) {
		t.Fatalf("non-TLS rewind mismatch: %q vs %q", gotBanner, banner)
	}
}

func TestLazyHopPolicyAndWake(t *testing.T) {
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
				if len(first) > 0 {
					_, _ = st.Write(first)
				}
				_, _ = io.Copy(st, st)
			}, nil, nil)
		}
	}()

	sched := NewApexScheduler(link, ps, 1, nil)
	sched.SetDialJitterForTest(0, 0, 100)
	sched.SetRTCDialHookForTest(func(dialCtx context.Context, dl *Link, dps *ParamStore, hopPort int, timeout time.Duration, clientID [8]byte) (*gftrtc.RTCSession, time.Duration, error) {
		return DialRTCWithPacketConnAndID(dialCtx, sw.newClientEnd(), true, sw.srvAddr, hopPort, dl, dps, timeout, clientID)
	})
	var hops atomic.Int32
	sched.SetRTCHopHookForTest(func(sess *gftrtc.RTCSession, nextPort int) error {
		hops.Add(1)
		return sess.HopWithPacketConn(sw.newClientEnd(), true, sw.srvAddr, nextPort)
	})

	sched.SetHopTimingsForTest(40*time.Millisecond, 50*time.Millisecond, 200*time.Millisecond, 20*time.Millisecond)
	// Require 64 KB/s rate for periodic hop -> while idle, hops MUST pause!
	sched.SetLazyHopPolicyForTest(true, 64*1024, 512*1024, 0)

	if err := sched.Start(3 * time.Second); err != nil {
		t.Fatal(err)
	}
	defer sched.Close()

	time.Sleep(180 * time.Millisecond)
	if hops.Load() != 0 {
		t.Fatalf("expected 0 periodic hops while idle (<64KB/s), got %d", hops.Load())
	}
	if st := sched.Stats(); st.HopState != "Paused(Idle)" {
		t.Fatalf("expected HopState=Paused(Idle), got %q", st.HopState)
	}

	// Pump > 600KB across stream -> trips >= 512KB active hop quota cleanly & logs zero routine hop noise
	st, err := sched.OpenStream("active.example:443", nil)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 640*1024)
	if _, err := st.Write(buf); err != nil {
		t.Fatal(err)
	}
	_ = st.Close()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if hops.Load() > 0 && sched.Stats().HopCount > 0 {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if hops.Load() == 0 || sched.Stats().HopCount == 0 {
		t.Fatalf("expected active traffic hop quota to fire, hops=%d stats.HopCount=%d", hops.Load(), sched.Stats().HopCount)
	}
	sched.OnSystemWake()
}

func TestSessionPoolAcquireCoalescesEmergencyDial(t *testing.T) {
	ps := NewParamStore(DefaultParams())
	pool := NewSessionPool(nil, ps, 2, nil)
	defer pool.Close()

	var dials atomic.Int32
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	sharedSess := NewSession(c1, true, ps, nil)
	defer sharedSess.Close()

	pool.dialFn = func(ctx context.Context, _ *Link, _ *ParamStore, _ uint16, _ time.Duration) (*Session, time.Duration, error) {
		dials.Add(1)
		time.Sleep(120 * time.Millisecond)
		return sharedSess, 15 * time.Millisecond, nil
	}

	const workers = 12
	var wg sync.WaitGroup
	results := make([]*Session, workers)
	errs := make([]error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx], errs[idx] = pool.Acquire()
		}(i)
	}
	wg.Wait()

	if dials.Load() != 1 {
		t.Fatalf("expected concurrent Acquire() calls to coalesce into 1 dial, got %d", dials.Load())
	}
	for i := 0; i < workers; i++ {
		if errs[i] != nil {
			t.Fatalf("worker %d Acquire error: %v", i, errs[i])
		}
		if results[i] != sharedSess {
			t.Fatalf("worker %d got unexpected session instance", i)
		}
	}
}

var _ = sync.Mutex{}
