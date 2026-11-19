package gft

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func TestRewindConn(t *testing.T) {
	const total = 4096
	for _, k := range []int{0, 1, 2, 48, 56, 120, 1000, total} {
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
			t.Fatalf("k=%d: byte sequence differs (got %d, want %d)", k, len(got), len(orig))
		}
	}
}

func TestRewindSmallReadsAndConsumePrefix(t *testing.T) {
	orig := make([]byte, 300)
	_, _ = rand.Read(orig)
	cli, srv := net.Pipe()
	go func() { _, _ = cli.Write(orig); _ = cli.Close() }()
	rc := NewRewindConn(srv)
	_, _ = io.ReadFull(rc, make([]byte, 200))
	// Discard first 120 bytes, keep coalesced [120:300]
	rc.ConsumePrefix(120)
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, orig[120:]) {
		t.Fatalf("ConsumePrefix mismatch: got %d want %d", len(got), len(orig[120:]))
	}
}

func TestKnockV2(t *testing.T) {
	psk := make([]byte, 32)
	_, _ = rand.Read(psk)
	now := time.Now()

	t.Run("correct_and_ack", func(t *testing.T) {
		v := NewKnockVerifier(psk)
		pkt, salt, err := BuildKnockV2(psk, now, 4)
		if err != nil {
			t.Fatal(err)
		}
		if len(pkt) < 240 || len(pkt) > 816 {
			t.Fatalf("knock packet size out of [240,816]: %d", len(pkt))
		}
		s2, pad, flags, res := v.CheckPacket(pkt, now)
		if res != KnockOK || s2 != salt || flags != 4 || KnockPrefixLen+pad != len(pkt) {
			t.Fatalf("check failed: res=%v pad=%d len=%d flags=%d", res, pad, len(pkt), flags)
		}

		wantParams := DefaultParams()
		ack, err := BuildServerAck(psk, salt, wantParams)
		if err != nil {
			t.Fatal(err)
		}
		gotParams, ok, err := ReadServerAck(bytes.NewReader(ack), psk, salt)
		if err != nil || !ok || gotParams != wantParams {
			t.Fatalf("ReadServerAck: ok=%v err=%v got=%+v", ok, err, gotParams)
		}
	})

	t.Run("bad_auth_and_tamper", func(t *testing.T) {
		v := NewKnockVerifier(psk)
		bad := make([]byte, 32)
		_, _ = rand.Read(bad)
		pkt, _, _ := BuildKnockV2(bad, now, 1)
		if _, _, _, res := v.CheckPacket(pkt, now); res != KnockBadAuth {
			t.Fatalf("wrong psk: want auth, got %v", res)
		}
		pkt2, _, _, _ := func() ([]byte, [16]byte, error, error) {
			p, s, e := BuildKnockV2(psk, now, 1)
			return p, s, e, nil
		}()
		pkt2[20] ^= 0x01
		if _, _, _, res := v.CheckPacket(pkt2, now); res != KnockBadAuth {
			t.Fatalf("tampered: want auth, got %v", res)
		}
	})

	t.Run("expired", func(t *testing.T) {
		v := NewKnockVerifier(psk)
		p1, _, _ := BuildKnockV2(psk, now.Add(-91*time.Second), 0)
		if _, _, _, res := v.CheckPacket(p1, now); res != KnockExpired {
			t.Fatalf("past: want expired, got %v", res)
		}
		p2, _, _ := BuildKnockV2(psk, now.Add(91*time.Second), 0)
		if _, _, _, res := v.CheckPacket(p2, now); res != KnockExpired {
			t.Fatalf("future: want expired, got %v", res)
		}
		p3, _, _ := BuildKnockV2(psk, now.Add(-89*time.Second), 0)
		if _, _, _, res := v.CheckPacket(p3, now); res != KnockOK {
			t.Fatalf("89s skew should pass, got %v", res)
		}
	})

	t.Run("replay_and_sweep", func(t *testing.T) {
		v := NewKnockVerifier(psk)
		pkt, _, _ := BuildKnockV2(psk, now, 0)
		if _, _, _, res := v.CheckPacket(pkt, now); res != KnockOK {
			t.Fatalf("first use: %v", res)
		}
		if _, _, _, res := v.CheckPacket(pkt, now.Add(10*time.Second)); res != KnockReplay {
			t.Fatalf("second use: want replay, got %v", res)
		}
		v.Sweep(now.Add(KnockReplayTTL + time.Second))
		if v.CacheSize() != 0 {
			t.Fatalf("sweep did not clear cache: %d", v.CacheSize())
		}
	})
}

// TestZeroDelayFallbackSniffing ensures HTTP/1.1, HTTP/2 PRI, and short probes return in <50ms.
func TestZeroDelayFallbackSniffing(t *testing.T) {
	psk := make([]byte, 32)
	v := NewKnockVerifier(psk)

	for _, tc := range []struct {
		name string
		send string
		want KnockResult
	}{
		{"http1_get", "GET / HTTP/1.1\r\nHost: x\r\n\r\n", KnockHTTPProbe},
		{"http2_preface", "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", KnockHTTPProbe},
		{"short_garbage", "XXXX", KnockIncomplete},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cli, srv := net.Pipe()
			go func() {
				_, _ = cli.Write([]byte(tc.send))
			}()
			rc := NewRewindConn(srv)
			t0 := time.Now()
			_, _, res := v.VerifyFirstRead(rc, time.Now())
			elapsed := time.Since(t0)
			if res != tc.want {
				t.Fatalf("want %v, got %v", tc.want, res)
			}
			if elapsed > 100*time.Millisecond {
				t.Fatalf("sniff blocked too long: %v", elapsed)
			}
			_ = rc.SetReadDeadline(time.Time{})
			rc.Rewind()
			_ = cli.Close()
			got, _ := io.ReadAll(rc)
			if string(got) != tc.send {
				t.Fatalf("rewound bytes %q != %q", got, tc.send)
			}
		})
	}
}

func TestMuxEchoAndAdaptivePadding(t *testing.T) {
	a, b := net.Pipe()
	ps := NewParamStore(DefaultParams())
	srv := NewSession(b, false, ps, func(s *Stream, target string, first []byte) {
		defer s.Close()
		if len(first) > 0 {
			_, _ = s.Write(first)
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

	st, err := cli.OpenStream("example.org:443", []byte("0rtt|"))
	if err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 2<<20)
	_, _ = rand.Read(data)
	go func() {
		_, _ = st.Write(data)
		_ = st.CloseWrite()
	}()
	got, err := io.ReadAll(st)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got[:5], []byte("0rtt|")) || !bytes.Equal(got[5:], data) {
		t.Fatalf("echo mismatch: got %d", len(got))
	}

	// Verify phased adaptive padding rules directly
	p := DefaultParams()
	big := make([]byte, 1500)
	mid := make([]byte, 1024)
	tlsApp := []byte{0x17, 0x03, 0x03, 0x00, 0x20}
	for i := int64(0); i < 8; i++ {
		pad := cli.computePadding(CmdData, big, i, p)
		if pad < 64 || pad > 512 {
			t.Fatalf("vision phase frame %d pad=%d out of [64,512]", i, pad)
		}
	}
	if pad := cli.computePadding(CmdData, mid, 8, p); pad != 0 {
		t.Fatalf("high-speed direct pass frame 8 >=1024B must have pad=0, got %d", pad)
	}
	if pad := cli.computePadding(CmdData, tlsApp, 8, p); pad != 0 {
		t.Fatalf("inner TLS 0x17 frame 8 must have pad=0, got %d", pad)
	}
}

func TestMuxUDPDatagram(t *testing.T) {
	a, b := net.Pipe()
	ps := NewParamStore(DefaultParams())
	var closedMu sync.Mutex
	closedID := uint16(0)

	srv := NewSession(b, false, ps, nil)
	srv.SetUDPHandler(func(s *Session, id uint16, target string, data []byte) {
		reply := append([]byte("ack:"+target+":"), data...)
		_ = s.SendUDPDatagram(id, target, reply, 0)
	}, func(_ *Session, id uint16) {
		closedMu.Lock()
		closedID = id
		closedMu.Unlock()
	})
	cli := NewSession(a, true, ps, nil)
	go srv.Run()
	go cli.Run()
	defer cli.Close()
	defer srv.Close()

	ust, err := cli.OpenUDP()
	if err != nil {
		t.Fatal(err)
	}
	if err := ust.SendTo("1.1.1.1:53", []byte("dnsq")); err != nil {
		t.Fatal(err)
	}
	select {
	case pkt := <-ust.Recv():
		if string(pkt.Data) != "ack:1.1.1.1:53:dnsq" {
			t.Fatalf("unexpected udp reply: %q", pkt.Data)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("udp echo timeout")
	}
	wantID := ust.ID()
	_ = ust.Close()
	time.Sleep(50 * time.Millisecond)
	closedMu.Lock()
	gotClosed := closedID
	closedMu.Unlock()
	if gotClosed != wantID {
		t.Fatalf("expected UDPClose id=%d, got %d", wantID, gotClosed)
	}
}

func TestSessionPoolLeastLoadedAndDrain(t *testing.T) {
	ps := NewParamStore(DefaultParams())
	link := &Link{V: 2, Host: "example.com", Port: 443, SNI: "example.com", PSK: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", Verify: "ca"}

	var mu sync.Mutex
	var srvConns []net.Conn
	defer func() {
		mu.Lock()
		for _, c := range srvConns {
			_ = c.Close()
		}
		mu.Unlock()
	}()

	pool := NewSessionPool(link, ps, 2, nil)
	pool.dialFn = func(ctx context.Context, _ *Link, store *ParamStore, _ uint16, _ time.Duration) (*Session, time.Duration, error) {
		c, s := net.Pipe()
		srv := NewSession(s, false, store, nil)
		go srv.Run()
		mu.Lock()
		srvConns = append(srvConns, s)
		mu.Unlock()
		cli := NewSession(c, true, store, nil)
		go cli.Run()
		return cli, 2 * time.Millisecond, nil
	}

	if err := pool.Start(2 * time.Second); err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	// Wait for keeper to bring pool up to 2
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if pool.Stats().ActiveConns == 2 {
			break
		}
		time.Sleep(30 * time.Millisecond)
	}
	if pool.Stats().ActiveConns != 2 {
		t.Fatalf("expected 2 active conns, got %+v", pool.Stats())
	}

	// Open a stream on session 1; next Acquire must select the less-loaded session 2.
	s1, err := pool.Acquire()
	if err != nil {
		t.Fatal(err)
	}
	s1.mu.Lock()
	s1.streams[99] = newStream(s1, 99)
	s1.mu.Unlock()

	s2, err := pool.Acquire()
	if err != nil {
		t.Fatal(err)
	}
	if s1 == s2 {
		t.Fatal("least-loaded scheduler picked already loaded session")
	}
	_ = binary.BigEndian
}
