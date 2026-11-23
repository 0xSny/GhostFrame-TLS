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

type dropBondDataConn struct {
	net.Conn
	dropAfter atomic.Int32
	writes    atomic.Int32
}

func (d *dropBondDataConn) Write(p []byte) (int, error) {
	if limit := d.dropAfter.Load(); limit > 0 {
		if d.writes.Add(1) > limit {
			// Silently swallow CmdBondData payload frames on this stalled carrier without dropping
			// coalesced control frames (such as CmdBondClose FIN) in the same writeLoop batch.
			var kept []byte
			off := 0
			sawBondData := false
			for off+HeaderLen <= len(p) {
				plen := int(binary.BigEndian.Uint16(p[off+4 : off+6]))
				pad := int(binary.BigEndian.Uint16(p[off+6 : off+8]))
				flen := HeaderLen + plen + pad
				if off+flen > len(p) {
					break
				}
				if p[off] == CmdBondData {
					sawBondData = true
				} else {
					kept = append(kept, p[off:off+flen]...)
				}
				off += flen
			}
			if off == len(p) && sawBondData {
				if len(kept) > 0 {
					if _, err := d.Conn.Write(kept); err != nil {
						return 0, err
					}
				}
				return len(p), nil
			}
			if len(p) >= HeaderLen && p[0] == CmdBondData {
				return len(p), nil
			}
		}
	}
	return d.Conn.Write(p)
}

func TestBondNackCrossSocketStallRecoveryAndPenalty(t *testing.T) {
	ps := NewParamStore(DefaultParams())
	srvGrp := NewBondGroup(func(st DataStream, target string, first []byte) {
		defer st.Close()
		_ = CopyBuf(st, st, nil)
	})
	cliGrp := NewBondGroup(nil)

	var dropConn *dropBondDataConn
	var srvSess0 *Session
	var all []*Session
	for i := 0; i < 4; i++ {
		cConn, sConn := net.Pipe()
		var srvC net.Conn = sConn
		if i == 0 {
			dropConn = &dropBondDataConn{Conn: sConn}
			srvC = dropConn
		}
		srv := NewSession(srvC, false, ps, nil)
		cli := NewSession(cConn, true, ps, nil)
		if i == 0 {
			srvSess0 = srv
		}
		srvGrp.AddSession(srv)
		cliGrp.AddSession(cli)
		all = append(all, srv, cli)
		go func() { _ = srv.Run() }()
		go func() { _ = cli.Run() }()
		_ = srv.SendBondCap()
	}
	defer func() {
		cliGrp.CloseAll(ErrSessionClosed)
		srvGrp.CloseAll(ErrSessionClosed)
		for _, s := range all {
			s.Close()
		}
	}()

	// Arm silent packet swallow on carrier 0 after initial capability handshake.
	time.Sleep(50 * time.Millisecond)
	dropConn.dropAfter.Store(1)

	st, err := cliGrp.OpenStream(2002, "nack.example:443", nil)
	if err != nil {
		t.Fatalf("OpenStream failed: %v", err)
	}
	payload := make([]byte, 512*1024)
	_, _ = rand.Read(payload)
	wantHash := sha256.Sum256(payload)

	go func() {
		_, _ = st.Write(payload)
		_ = st.CloseWrite()
	}()

	got := make([]byte, len(payload))
	done := make(chan error, 1)
	go func() {
		_, rerr := io.ReadFull(st, got)
		done <- rerr
	}()

	select {
	case rerr := <-done:
		if rerr != nil {
			t.Fatalf("ReadFull failed under silent carrier drop: %v", rerr)
		}
	case <-time.After(4 * time.Second):
		t.Fatalf("timed out waiting for CmdBondNack cross-socket recovery: %s", st.DebugState())
	}
	if sha256.Sum256(got) != wantHash {
		t.Fatal("SHA-256 mismatch after CmdBondNack recovery")
	}
	if !srvSess0.BondPenaltyActive(time.Now().UnixNano()) {
		t.Fatal("expected stalled carrier srvSess0 to carry bondPenaltyUntil after CmdBondNack")
	}
}

func TestSessionPoolEvictsBlackholedSocketViaProbeAllHealth(t *testing.T) {
	ps := NewParamStore(DefaultParams())
	l := &Link{V: 3, Host: "127.0.0.1", Port: 443}
	pool := NewSessionPool(l, ps, 2, nil)
	defer pool.Close()

	// Slot 0: dead/silent responder (reads everything, never replies with PingResp)
	c0, s0 := net.Pipe()
	go func() {
		_, _ = io.Copy(io.Discard, s0)
	}()
	cli0 := NewSession(c0, true, ps, nil)
	go func() { _ = cli0.Run() }()
	defer c0.Close()
	defer s0.Close()

	// Slot 1: healthy responder
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

	pool.probeAllHealth()
	select {
	case <-cli0.Done():
		t.Fatal("cli0 should tolerate 1 ping timeout before eviction")
	default:
	}

	pool.probeAllHealth()
	select {
	case <-cli0.Done():
	case <-time.After(500 * time.Millisecond):
		t.Fatal("expected cli0 to be evicted after 2 consecutive ping timeouts")
	}
	select {
	case <-cli1.Done():
		t.Fatal("healthy cli1 must remain open")
	default:
	}
}
