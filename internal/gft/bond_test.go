package gft

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestMultiTCPBondGroupStriping8MBAndOutOfOrderEOF(t *testing.T) {
	const numConns = 4
	ps := NewParamStore(DefaultParams())

	srvGrp := NewBondGroup(func(st DataStream, target string, first []byte) {
		defer st.Close()
		if len(first) > 0 {
			if _, err := st.Write(first); err != nil {
				return
			}
		}
		_ = CopyBuf(st, st, nil)
	})
	cliGrp := NewBondGroup(nil)

	var srvSessions []*Session
	var cliSessions []*Session
	for i := 0; i < numConns; i++ {
		cConn, sConn := net.Pipe()
		srv := NewSession(sConn, false, ps, nil)
		cli := NewSession(cConn, true, ps, nil)
		srvGrp.AddSession(srv)
		cliGrp.AddSession(cli)
		srvSessions = append(srvSessions, srv)
		cliSessions = append(cliSessions, cli)
		go func() { _ = srv.Run() }()
		go func() { _ = cli.Run() }()
		_ = srv.SendBondCap()
	}
	defer func() {
		cliGrp.CloseAll(ErrSessionClosed)
		srvGrp.CloseAll(ErrSessionClosed)
		for _, s := range cliSessions {
			s.Close()
		}
		for _, s := range srvSessions {
			s.Close()
		}
	}()

	// Wait briefly until CmdBondCap propagates on all 4 client sessions
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		allReady := true
		for _, c := range cliSessions {
			if !c.SupportsBond() {
				allReady = false
				break
			}
		}
		if allReady {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	for i, c := range cliSessions {
		if !c.SupportsBond() {
			t.Fatalf("client session %d did not receive CmdBondCap", i)
		}
	}

	const payloadSize = 8 * 1024 * 1024
	payload := make([]byte, payloadSize)
	_, _ = rand.Read(payload)
	wantHash := sha256.Sum256(payload)

	st, err := cliGrp.OpenStream(1001, "bonded.example:443", payload[:512])
	if err != nil {
		t.Fatalf("OpenStream failed: %v", err)
	}

	errCh := make(chan error, 1)
	go func() {
		_, werr := st.Write(payload[512:])
		_ = st.CloseWrite()
		errCh <- werr
	}()

	got := make([]byte, payloadSize)
	if _, rerr := io.ReadFull(st, got); rerr != nil {
		t.Fatalf("ReadFull bonded echo failed: %v", rerr)
	}
	var tail [1]byte
	if n, rerr := st.Read(tail[:]); n != 0 || rerr != io.EOF {
		t.Fatalf("expected clean EOF after exact payload, got n=%d err=%v", n, rerr)
	}
	_ = st.Close()
	if werr := <-errCh; werr != nil {
		t.Fatalf("writer failed: %v", werr)
	}

	gotHash := sha256.Sum256(got)
	if gotHash != wantHash {
		t.Fatalf("bonded echo SHA-256 mismatch!")
	}

	// Verify traffic actually striped across multiple underlying TCP connections (>1 socket carried >512KB)
	activeCarriers := 0
	for i, s := range srvSessions {
		if s.DownBytes.Load() > 512*1024 && s.UpBytes.Load() > 512*1024 {
			activeCarriers++
		}
		t.Logf("carrier #%d up=%d down=%d", i, s.UpBytes.Load(), s.DownBytes.Load())
	}
	if activeCarriers < 2 {
		t.Fatalf("expected chunks striped across >=2 carriers, got %d", activeCarriers)
	}
}

type blockingWriteConn struct {
	net.Conn
	blockWrites atomic.Bool
	unblockCh   chan struct{}
	once        sync.Once
}

func (b *blockingWriteConn) Write(p []byte) (int, error) {
	if b.blockWrites.Load() {
		<-b.unblockCh
	}
	return b.Conn.Write(p)
}

func (b *blockingWriteConn) Unblock() {
	b.blockWrites.Store(false)
	b.once.Do(func() { close(b.unblockCh) })
}

func TestSessionPoolPingPrefersNonBlockedSocketAndRealTimeEcho(t *testing.T) {
	ps := NewParamStore(DefaultParams())
	l := &Link{V: 3, Host: "127.0.0.1", Port: 443}
	pool := NewSessionPool(l, ps, 2, nil)
	defer pool.Close()

	// Session 0: simulates a saturated bulk upload/download whose Write is blocked
	c0, s0 := net.Pipe()
	bwc := &blockingWriteConn{Conn: c0, unblockCh: make(chan struct{})}
	defer bwc.Unblock()
	srv0 := NewSession(s0, false, ps, nil)
	cli0 := NewSession(bwc, true, ps, nil)
	go func() { _ = srv0.Run() }()
	go func() { _ = cli0.Run() }()
	defer srv0.Close()
	defer cli0.Close()

	// Session 1: clean idle socket
	c1, s1 := net.Pipe()
	srv1 := NewSession(s1, false, ps, nil)
	cli1 := NewSession(c1, true, ps, nil)
	go func() { _ = srv1.Run() }()
	go func() { _ = cli1.Run() }()
	defer srv1.Close()
	defer cli1.Close()

	pool.mu.Lock()
	pool.entries = []*poolEntry{
		{id: 1, sess: cli0, createdAt: time.Now(), maxAge: time.Hour},
		{id: 2, sess: cli1, createdAt: time.Now(), maxAge: time.Hour},
	}
	pool.mu.Unlock()

	// Saturate cli0 so its pendingWriteBytes > 0 and Write blocks
	bwc.blockWrites.Store(true)
	go func() {
		_ = cli0.writeFrame(CmdData, 0, 1, bytes.Repeat([]byte{'A'}, 4096), 10)
	}()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if cli0.PendingWriteBytes() > 0 {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	if cli0.PendingWriteBytes() <= 0 {
		t.Fatal("expected cli0 pendingWriteBytes > 0 while Write blocked")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ms, err := pool.PingNow(ctx)
	if err != nil {
		t.Fatalf("PingNow failed when fast idle session cli1 was available: %v", err)
	}
	if ms <= 0 || ms > 500 {
		t.Fatalf("expected fast live RTT on idle socket, got %dms", ms)
	}
}

func TestBondGroupEarlyDataBeforeBondOpenAcrossSockets(t *testing.T) {
	ps := NewParamStore(DefaultParams())
	gotCh := make(chan string, 1)
	srvGrp := NewBondGroup(func(st DataStream, target string, first []byte) {
		defer st.Close()
		buf := make([]byte, 64)
		n, _ := io.ReadFull(st, buf[:len("HELLO-EARLY")])
		gotCh <- target + ":" + string(first) + string(buf[:n])
	})
	c1, s1 := net.Pipe()
	c2, s2 := net.Pipe()
	srv1 := NewSession(s1, false, ps, nil)
	srv2 := NewSession(s2, false, ps, nil)
	defer srv1.Close()
	defer srv2.Close()
	defer c1.Close()
	defer c2.Close()
	srvGrp.AddSession(srv1)
	srvGrp.AddSession(srv2)

	// Simulate CmdBondData(seq=0) arriving on srv2 BEFORE CmdBondOpen arrives on srv1.
	var dataPl [12 + len("HELLO-EARLY")]byte
	binary.BigEndian.PutUint64(dataPl[:8], 777)
	binary.BigEndian.PutUint32(dataPl[8:12], 0)
	copy(dataPl[12:], "HELLO-EARLY")
	if err := srvGrp.HandleFrame(srv2, CmdBondData, 0, dataPl[:]); err != nil {
		t.Fatalf("early HandleFrame CmdBondData failed: %v", err)
	}

	addr, err := EncodeAddr("example.org:443")
	if err != nil {
		t.Fatal(err)
	}
	openPl := make([]byte, 8+len(addr))
	binary.BigEndian.PutUint64(openPl[:8], 777)
	copy(openPl[8:], addr)
	if err := srvGrp.HandleFrame(srv1, CmdBondOpen, 0, openPl); err != nil {
		t.Fatalf("HandleFrame CmdBondOpen failed: %v", err)
	}

	select {
	case got := <-gotCh:
		if got != "example.org:443:HELLO-EARLY" {
			t.Fatalf("unexpected early bonded payload: %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for early-buffered bonded stream")
	}
}
