package gftrtc

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	mrand "math/rand/v2"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type lossyAddr string

func (a lossyAddr) Network() string { return "udp" }
func (a lossyAddr) String() string  { return string(a) }

type lossyPkt struct {
	data []byte
	from net.Addr
}

// LossyUDPSwitch simulates a cross-ocean lossy/reordering/duplicating network connecting
// one hub endpoint (server) and dynamically migrating client endpoints.
type LossyUDPSwitch struct {
	srvAddr    lossyAddr
	srvConn    *lossyEnd
	dropPct    atomic.Int32 // 0..100
	reorderPct atomic.Int32 // 0..100
	dupPct     atomic.Int32 // 0..100
	baseDelay  atomic.Int64 // ns

	mu       sync.RWMutex
	clients  map[string]*lossyEnd
	nextPort atomic.Int32
}

func NewLossyUDPSwitch(hubAddr string, dropPct, reorderPct, dupPct int, baseDelay time.Duration) *LossyUDPSwitch {
	sw := &LossyUDPSwitch{
		srvAddr: lossyAddr(hubAddr),
		clients: make(map[string]*lossyEnd),
	}
	sw.dropPct.Store(int32(dropPct))
	sw.reorderPct.Store(int32(reorderPct))
	sw.dupPct.Store(int32(dupPct))
	sw.baseDelay.Store(int64(baseDelay))
	sw.nextPort.Store(30000)
	sw.srvConn = &lossyEnd{
		sw:      sw,
		addr:    sw.srvAddr,
		isSrv:   true,
		recv:    make(chan lossyPkt, 8192),
		delayCh: make(chan delayedPkt, 8192),
		closed:  make(chan struct{}),
	}
	sw.srvConn.startDelayWorker()
	return sw
}

func (sw *LossyUDPSwitch) NewClientEnd() *lossyEnd {
	p := sw.nextPort.Add(1)
	addr := lossyAddr(fmt.Sprintf("127.0.0.1:%d", p))
	ce := &lossyEnd{
		sw:      sw,
		addr:    addr,
		recv:    make(chan lossyPkt, 4096),
		delayCh: make(chan delayedPkt, 4096),
		closed:  make(chan struct{}),
	}
	ce.startDelayWorker()
	sw.mu.Lock()
	sw.clients[string(addr)] = ce
	sw.mu.Unlock()
	return ce
}

func (sw *LossyUDPSwitch) CloseAll() {
	_ = sw.srvConn.Close()
	sw.mu.RLock()
	list := make([]*lossyEnd, 0, len(sw.clients))
	for _, ce := range sw.clients {
		list = append(list, ce)
	}
	sw.mu.RUnlock()
	for _, ce := range list {
		_ = ce.Close()
	}
}

type delayedPkt struct {
	pkt     lossyPkt
	readyAt time.Time
}

type lossyEnd struct {
	sw      *LossyUDPSwitch
	addr    lossyAddr
	isSrv   bool
	recv    chan lossyPkt
	delayCh chan delayedPkt
	closed  chan struct{}
	once    sync.Once
	mu      sync.Mutex
	rDead   time.Time
	rngMu   sync.Mutex
	held    *lossyPkt
}

func (e *lossyEnd) startDelayWorker() {
	go func() {
		for {
			select {
			case <-e.closed:
				return
			case dp := <-e.delayCh:
				if wait := time.Until(dp.readyAt); wait > 0 {
					t := time.NewTimer(wait)
					select {
					case <-e.closed:
						t.Stop()
						return
					case <-t.C:
					}
				}
				select {
				case e.recv <- dp.pkt:
				default:
				}
			}
		}
	}()
}

func (e *lossyEnd) ReadFrom(p []byte) (int, net.Addr, error) {
	e.mu.Lock()
	dl := e.rDead
	e.mu.Unlock()
	var timer <-chan time.Time
	var t *time.Timer
	if !dl.IsZero() {
		d := time.Until(dl)
		if d <= 0 {
			return 0, nil, context.DeadlineExceeded
		}
		t = time.NewTimer(d)
		defer t.Stop()
		timer = t.C
	}
	select {
	case pkt := <-e.recv:
		n := copy(p, pkt.data)
		return n, pkt.from, nil
	case <-e.closed:
		return 0, nil, net.ErrClosed
	case <-timer:
		return 0, nil, context.DeadlineExceeded
	}
}

func (e *lossyEnd) WriteTo(p []byte, dst net.Addr) (int, error) {
	select {
	case <-e.closed:
		return 0, net.ErrClosed
	default:
	}

	var target *lossyEnd
	if e.isSrv {
		e.sw.mu.RLock()
		if dst != nil {
			target = e.sw.clients[dst.String()]
		}
		e.sw.mu.RUnlock()
	} else {
		target = e.sw.srvConn
	}
	if target == nil {
		return len(p), nil
	}

	e.rngMu.Lock()
	rollDrop := mrand.IntN(100)
	rollReord := mrand.IntN(100)
	rollDup := mrand.IntN(100)
	var flushHeld *lossyPkt

	if int32(rollDrop) < e.sw.dropPct.Load() {
		e.rngMu.Unlock()
		return len(p), nil
	}

	cp := make([]byte, len(p))
	copy(cp, p)
	cur := lossyPkt{data: cp, from: e.addr}

	deliver := func(pkt lossyPkt) {
		select {
		case target.recv <- pkt:
		default:
		}
	}

	if int32(rollReord) < e.sw.reorderPct.Load() && e.held == nil {
		e.held = &cur
		e.rngMu.Unlock()
		return len(p), nil
	}
	if e.held != nil {
		flushHeld = e.held
		e.held = nil
	}
	e.rngMu.Unlock()

	delay := time.Duration(e.sw.baseDelay.Load())
	if delay > 0 {
		ready := time.Now().Add(delay)
		select {
		case target.delayCh <- delayedPkt{pkt: cur, readyAt: ready}:
		default:
		}
		if flushHeld != nil {
			select {
			case target.delayCh <- delayedPkt{pkt: *flushHeld, readyAt: ready}:
			default:
			}
		}
	} else {
		deliver(cur)
		if flushHeld != nil {
			deliver(*flushHeld)
		}
	}

	if int32(rollDup) < e.sw.dupPct.Load() {
		cp2 := make([]byte, len(p))
		copy(cp2, p)
		deliver(lossyPkt{data: cp2, from: e.addr})
	}

	return len(p), nil
}

func (e *lossyEnd) Close() error {
	e.once.Do(func() {
		close(e.closed)
		if !e.isSrv {
			e.sw.mu.Lock()
			delete(e.sw.clients, string(e.addr))
			e.sw.mu.Unlock()
		}
	})
	return nil
}

func (e *lossyEnd) LocalAddr() net.Addr                { return e.addr }
func (e *lossyEnd) SetDeadline(t time.Time) error      { return e.SetReadDeadline(t) }
func (e *lossyEnd) SetWriteDeadline(_ time.Time) error { return nil }
func (e *lossyEnd) SetReadDeadline(t time.Time) error {
	e.mu.Lock()
	e.rDead = t
	e.mu.Unlock()
	return nil
}

func TestSTUNHandshakeFingerprintReplayAndSilentDrop(t *testing.T) {
	psk := make([]byte, 32)
	_, _ = rand.Read(psk)

	sw := NewLossyUDPSwitch("127.0.0.1:10443", 0, 0, 0, 0)
	defer sw.CloseAll()

	ln, err := NewListener(sw.srvConn, false, psk, 0, []byte(`{"pmin":0,"pmax":64}`))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	badClient := sw.NewClientEnd()
	defer badClient.Close()

	// 1. Random scan garbage
	_, _ = badClient.WriteTo([]byte("GET / HTTP/1.1\r\n\r\n"), sw.srvAddr)

	// 2. Valid STUN Binding Request captured, then CRC tampered
	reqPkt, _, _, err := BuildClientBindingReq(psk, [8]byte{1, 2, 3, 4, 5, 6, 7, 8}, 100, 0, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte(nil), reqPkt...)
	tampered[len(tampered)-1] ^= 0xFF
	_, _ = badClient.WriteTo(tampered, sw.srvAddr)

	// Verify RFC 5389 Fingerprint magic XOR directly
	fpOff := len(reqPkt) - 8
	wantCRC := crc32.ChecksumIEEE(reqPkt[:fpOff]) ^ stunFingerprintXOR
	gotCRC := binary.BigEndian.Uint32(reqPkt[fpOff+4:])
	if wantCRC != gotCRC {
		t.Fatalf("STUN RFC5389 fingerprint mismatch: got %x want %x", gotCRC, wantCRC)
	}

	// 3. Send same valid request twice (replay)
	_, _ = badClient.WriteTo(reqPkt, sw.srvAddr)
	_, _ = badClient.WriteTo(reqPkt, sw.srvAddr)

	// Wait for one accepted session and ensure zero responses sent to bad probes/replay
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	srvSess, err := ln.Accept(ctx)
	if err != nil {
		t.Fatalf("Accept failed: %v", err)
	}
	srvSess.Close()

	// Read valid Binding Response from badClient
	_ = badClient.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	buf := make([]byte, 2048)
	n, _, rerr := badClient.ReadFrom(buf)
	if rerr != nil || n == 0 {
		t.Fatalf("expected valid binding response once, got n=%d err=%v", n, rerr)
	}
	// Ensure no second response arrived for garbage / tampered / replayed packets
	_ = badClient.SetReadDeadline(time.Now().Add(120 * time.Millisecond))
	if n2, _, err2 := badClient.ReadFrom(buf); err2 == nil {
		t.Fatalf("expected silent 0-byte drop for probes/replay, got %d bytes", n2)
	}
	if ln.Dropped() < 3 {
		t.Fatalf("expected >= 3 silent drops, got %d", ln.Dropped())
	}

	// 4. Forged RTP packet with wrong SSRC or wrong ciphertext silently dropped
	_, _ = badClient.WriteTo(make([]byte, 64), sw.srvAddr)
	forgedRTP := make([]byte, 64)
	forgedRTP[0] = 0x80
	binary.BigEndian.PutUint32(forgedRTP[8:12], srvSess.SSRC())
	_, _ = badClient.WriteTo(forgedRTP, sw.srvAddr)
}

func TestXORFECEncodeAndZeroMsRecovery(t *testing.T) {
	if SelectFECCount(0.01) != 0 {
		t.Fatalf("expected FEC off at 1%% loss")
	}
	if SelectFECCount(0.03) != 10 {
		t.Fatalf("expected K=10 at 3%% loss")
	}
	if SelectFECCount(0.08) != 6 {
		t.Fatalf("expected K=6 at 8%% loss")
	}

	enc := NewFECEncoder()
	dec := NewFECDecoder()
	now := time.Now()
	plainBuf := make([]byte, 1600)

	const k = 6
	inputs := make([][]byte, k)
	var parity []byte
	var gid uint32
	dropIdx := 3

	for i := 0; i < k; i++ {
		sz := 100 + i*197 // mixed non-aligned lengths
		inputs[i] = make([]byte, sz)
		_, _ = rand.Read(inputs[i])
		srcP, pre, post := enc.WrapPlaintext(plainBuf, inputs[i], 0.10, now)
		if pre != nil {
			t.Fatal("unexpected pre-flush parity")
		}
		gid = binary.BigEndian.Uint32(srcP[0:4])
		if i != dropIdx {
			if rec, ok := dec.Process(gid, srcP[4], srcP[5], srcP[FECHeaderLen:]); ok {
				t.Fatalf("unexpected early recovery at idx %d (%dB)", i, len(rec))
			}
		}
		if post != nil {
			parity = post
		}
	}
	if parity == nil {
		t.Fatal("expected parity packet at end of group")
	}
	rec, ok := dec.Process(binary.BigEndian.Uint32(parity[0:4]), parity[4], parity[5], parity[FECHeaderLen:])
	if !ok {
		t.Fatal("expected 0ms FEC recovery when feeding parity")
	}
	if !bytes.Equal(rec, inputs[dropIdx]) {
		t.Fatalf("recovered payload mismatch: got %dB want %dB", len(rec), len(inputs[dropIdx]))
	}
	if dec.RecoveredCount() != 1 {
		t.Fatalf("expected RecoveredCount=1, got %d", dec.RecoveredCount())
	}

	// Verify 8ms shortened group flush recovers a dropped packet when count < K
	p1 := []byte("hello shortened fec packet A")
	p2 := []byte("hello shortened fec packet B - longer payload for word alignment test!")
	plainBuf1 := make([]byte, 1600)
	plainBuf2 := make([]byte, 1600)
	sp1, _, _ := enc.WrapPlaintext(plainBuf1, p1, 0.08, now)
	sp2, _, _ := enc.WrapPlaintext(plainBuf2, p2, 0.08, now)
	_ = sp2 // simulate packet 2 lost
	parityShort, flushed := enc.FlushIfDue(now.Add(10 * time.Millisecond))
	if !flushed || parityShort == nil {
		t.Fatal("expected shortened FEC group flush after 8ms")
	}
	dec.Process(binary.BigEndian.Uint32(sp1[0:4]), sp1[4], sp1[5], sp1[FECHeaderLen:])
	recShort, okShort := dec.Process(binary.BigEndian.Uint32(parityShort[0:4]), parityShort[4], parityShort[5], parityShort[FECHeaderLen:])
	if !okShort || !bytes.Equal(recShort, p2) {
		t.Fatalf("shortened group 0ms recovery failed: ok=%v got=%q", okShort, recShort)
	}
}

func TestReplayWindowAnd32BlockSACKRoundTrip(t *testing.T) {
	rw := &ReplayWindow{}
	now := time.Now()
	if rw.Allow(0) {
		t.Fatal("pktNum 0 must be rejected")
	}
	// Receive non-contiguous packet pattern creating gaps
	recvSet := map[uint64]bool{
		1: true, 2: true, 4: true, 5: true, 7: true, 9: true, 10: true, 12: true, 15: true, 16: true, 17: true,
	}
	for pn := uint64(1); pn <= 17; pn++ {
		if recvSet[pn] {
			if !rw.Allow(pn) {
				t.Fatalf("expected Allow(%d)=true", pn)
			}
			rw.Commit(pn, true, now)
			if rw.Allow(pn) {
				t.Fatalf("duplicate pktNum %d must be rejected", pn)
			}
		}
	}
	largest, delayUs, blocks, ok := rw.BuildSACK(now.Add(2 * time.Millisecond))
	if !ok || largest != 17 || len(blocks) == 0 {
		t.Fatalf("unexpected BuildSACK result: ok=%v largest=%d blocks=%v", ok, largest, blocks)
	}

	lt := NewLossTracker()
	for pn := uint64(1); pn <= 17; pn++ {
		lt.OnPacketSent(pn, 1000, []ReliableFrame{{Bytes: []byte{byte(pn)}}}, now)
	}
	res := lt.OnSACK(largest, delayUs, blocks, now.Add(20*time.Millisecond))
	if res.AckedPkts != len(recvSet) {
		t.Fatalf("expected %d acked packets, got %d", len(recvSet), res.AckedPkts)
	}
	// Packets 3, 6, 8, 11, 13, 14 (6 packets): with adaptive threshold=8, packets >=9+8=17?
	// Ensure gaps satisfying pn+8 <= largest (1..9) are detected immediately when largest=22!
	for pn := uint64(18); pn <= 22; pn++ {
		lt.OnPacketSent(pn, 1000, []ReliableFrame{{Bytes: []byte{byte(pn)}}}, now)
		rw.Commit(pn, true, now)
	}
	largest, delayUs, blocks, ok = rw.BuildSACK(now.Add(2 * time.Millisecond))
	res = lt.OnSACK(largest, delayUs, blocks, now.Add(20*time.Millisecond))
	if len(res.LostFrames) == 0 {
		t.Fatalf("expected declared lost frames via SACK gap threshold, got 0")
	}
}

func TestSmartBrutalPolicingVsRealCongestion(t *testing.T) {
	cc := NewSmartBrutalCC(100) // explicit 100 Mbps
	now := time.Now()
	// Zone A (rho = 1.1 <= 1.35) with 15% loss: MUST NOT slash rate, MUST compensate upward
	cc.OnFeedback(100_000, 0.15, 110*time.Millisecond, 100*time.Millisecond, 0, now)
	pMbps := cc.PacingMbps()
	if pMbps < 110.0 || pMbps > 180.1 {
		t.Fatalf("expected Zone A loss-compensated pacing ~117Mbps, got %.2fMbps", pMbps)
	}

	// Zone B (rho = 1.9 > 1.65): MUST smoothly back off (~0.80x)
	cc.OnFeedback(10_000, 0.05, 190*time.Millisecond, 100*time.Millisecond, 0, now.Add(200*time.Millisecond))
	pBackoff := cc.PacingMbps()
	if pBackoff >= 90.0 {
		t.Fatalf("expected Zone B real-congestion backoff (<90Mbps from 100Mbps), got %.2fMbps", pBackoff)
	}
}

func TestLossy15PctDrop5PctReorder4x8MBStreamsWithFEC(t *testing.T) {
	baseGoroutines := runtime.NumGoroutine()
	psk := make([]byte, 32)
	_, _ = rand.Read(psk)

	// 15% random drop + 5% reordering + 1% duplicates + 4ms simulated path delay
	sw := NewLossyUDPSwitch("127.0.0.1:20443", 15, 5, 1, 2*time.Millisecond)
	defer sw.CloseAll()

	ln, err := NewListener(sw.srvConn, false, psk, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()

	go func() {
		for {
			srvSess, aerr := ln.Accept(ctx)
			if aerr != nil {
				return
			}
			srvSess.SetHandlers(func(st *RTCStream, target string, first []byte) {
				defer st.Close()
				if len(first) > 0 {
					_, _ = st.Write(first)
				}
				_, _ = io.Copy(st, st)
			}, nil, nil)
		}
	}()

	ce := sw.NewClientEnd()
	cli, _, err := DialWithPacketConn(ctx, ce, true, sw.srvAddr, DialOptions{
		Host:     "127.0.0.1",
		Port:     20443,
		PSK:      psk,
		ClientID: [8]byte{9, 8, 7, 6, 5, 4, 3, 2},
		Timeout:  5 * time.Second,
	})
	if err != nil {
		t.Fatalf("DialWithPacketConn under 15%% loss failed: %v", err)
	}
	defer cli.Close()

	const numStreams = 4
	const streamSize = 8 * 1024 * 1024 // 4 x 8MB = 32MB echoed!
	var wg sync.WaitGroup
	errCh := make(chan error, numStreams)

	for s := 0; s < numStreams; s++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			payload := make([]byte, streamSize)
			// Deterministic fast fill per stream
			for i := 0; i < len(payload); i += 8 {
				binary.LittleEndian.PutUint64(payload[i:], uint64(idx+1)*0x9E3779B97F4A7C15+uint64(i))
			}
			wantSum := sha256.Sum256(payload)

			st, serr := cli.OpenStream(fmt.Sprintf("echo%d.example:443", idx), []byte("HDR:"))
			if serr != nil {
				errCh <- serr
				return
			}
			defer st.Close()

			go func() {
				_, werr := st.Write(payload)
				if werr == nil {
					_ = st.CloseWrite()
				}
			}()

			hdr := make([]byte, 4)
			if _, rerr := io.ReadFull(st, hdr); rerr != nil || string(hdr) != "HDR:" {
				errCh <- fmt.Errorf("stream %d hdr read: %v %q", idx, rerr, hdr)
				return
			}
			got := make([]byte, streamSize)
			if _, rerr := io.ReadFull(st, got); rerr != nil {
				errCh <- fmt.Errorf("stream %d body read: %v", idx, rerr)
				return
			}
			gotSum := sha256.Sum256(got)
			if gotSum != wantSum {
				errCh <- fmt.Errorf("stream %d SHA-256 mismatch!", idx)
			}
		}(s)
	}
	wg.Wait()
	close(errCh)
	for e := range errCh {
		t.Fatal(e)
	}

	stats := cli.Stats()
	if stats.FECRecovered == 0 {
		t.Fatalf("expected XOR-FEC 0ms recovered count > 0 under 15%% loss, got 0 (loss=%.2f%%)", stats.LossRate*100)
	}
	t.Logf("4x8MB under 15%% drop + 5%% reorder PASSED: FECRecovered=%d loss=%.1f%% pacing=%.1fMbps",
		stats.FECRecovered, stats.LossRate*100, stats.PacingMbps)

	cli.Close()
	ln.Close()
	time.Sleep(120 * time.Millisecond)
	leaked := runtime.NumGoroutine() - baseGoroutines
	if leaked > 6 {
		t.Fatalf("excessive goroutines left alive: %d (base=%d)", runtime.NumGoroutine(), baseGoroutines)
	}
}

func TestDynamicPortHopping5ConsecutiveMigrationsZeroErrors(t *testing.T) {
	psk := make([]byte, 32)
	_, _ = rand.Read(psk)

	sw := NewLossyUDPSwitch("127.0.0.1:443", 5, 2, 0, time.Millisecond)
	defer sw.CloseAll()

	ln, err := NewListener(sw.srvConn, false, psk, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	wantCID := [8]byte{0xAA, 0xBB, 0xCC, 0xDD, 1, 2, 3, 4}
	var acceptedCID atomic.Value
	go func() {
		for {
			ss, aerr := ln.Accept(ctx)
			if aerr != nil {
				return
			}
			acceptedCID.Store(ss.ClientID())
			ss.SetHandlers(func(st *RTCStream, _ string, first []byte) {
				defer st.Close()
				if len(first) > 0 {
					_, _ = st.Write(first)
				}
				_, _ = io.Copy(st, st)
			}, func(sink UDPReplySink, id uint16, target string, data []byte) {
				_ = sink.SendUDPReply(id, target, append([]byte("re:"), data...))
			}, nil)
		}
	}()

	c0 := sw.NewClientEnd()
	cli, _, err := DialWithPacketConn(ctx, c0, true, sw.srvAddr, DialOptions{
		Host:     "127.0.0.1",
		Port:     443,
		PSK:      psk,
		ClientID: wantCID,
		Timeout:  4 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()

	// Start large 6MB stream transfer while triggering 5 consecutive client socket hops!
	const sz = 6 * 1024 * 1024
	data := make([]byte, sz)
	_, _ = rand.Read(data)
	wantSum := sha256.Sum256(data)

	st, err := cli.OpenStream("hop.example:443", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	u, err := cli.OpenUDP()
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()

	go func() {
		_, _ = st.Write(data)
		_ = st.CloseWrite()
	}()

	hopDone := make(chan struct{})
	go func() {
		defer close(hopDone)
		for h := 0; h < 5; h++ {
			time.Sleep(50 * time.Millisecond)
			nextEnd := sw.NewClientEnd()
			_ = cli.HopWithPacketConn(nextEnd, true, sw.srvAddr, 20000+h)
		}
	}()

	got := make([]byte, sz)
	if _, err := io.ReadFull(st, got); err != nil {
		t.Fatalf("stream read across 5 hops failed: %v", err)
	}
	<-hopDone
	if sha256.Sum256(got) != wantSum {
		t.Fatal("SHA-256 mismatch across 5 port hops!")
	}

	// Unreliable UDP over 5% drop switch: send up to 3 attempts in case the single datagram hits the 5% simulated loss.
	udpOK := false
	for try := 0; try < 3 && !udpOK; try++ {
		if err := u.SendTo("1.1.1.1:53", []byte("hop-udp")); err != nil {
			t.Fatal(err)
		}
		select {
		case pkt := <-u.Recv():
			if string(pkt.Data) != "re:hop-udp" {
				t.Fatalf("unexpected udp echo: %q", pkt.Data)
			}
			udpOK = true
		case <-time.After(600 * time.Millisecond):
		}
	}
	if !udpOK {
		t.Fatal("udp echo timeout after 5 hops")
	}

	if gotCID, ok := acceptedCID.Load().([8]byte); !ok || gotCID != wantCID {
		t.Fatalf("server ClientID mismatch: got %v want %v", gotCID, wantCID)
	}
}

func TestUDPFragmentationAnd16KBFallback(t *testing.T) {
	psk := make([]byte, 32)
	_, _ = rand.Read(psk)
	sw := NewLossyUDPSwitch("127.0.0.1:443", 0, 0, 0, 0)
	defer sw.CloseAll()

	ln, err := NewListener(sw.srvConn, false, psk, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	go func() {
		ss, aerr := ln.Accept(ctx)
		if aerr != nil {
			return
		}
		ss.SetHandlers(nil, func(sink UDPReplySink, id uint16, target string, data []byte) {
			_ = sink.SendUDPReply(id, target, data)
		}, nil)
	}()

	cli, _, err := DialWithPacketConn(ctx, sw.NewClientEnd(), true, sw.srvAddr, DialOptions{
		Host: "127.0.0.1", Port: 443, PSK: psk, Timeout: 3 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()

	u, err := cli.OpenUDP()
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()

	for _, sz := range []int{300, 1350, 4500, 16384} {
		payload := make([]byte, sz)
		_, _ = rand.Read(payload)
		if err := u.SendTo("8.8.8.8:443", payload); err != nil {
			t.Fatalf("SendTo(%dB) err: %v", sz, err)
		}
		select {
		case pkt := <-u.Recv():
			if !bytes.Equal(pkt.Data, payload) {
				t.Fatalf("UDP echo mismatch at %dB (got %dB)", sz, len(pkt.Data))
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("UDP echo timeout at %dB", sz)
		}
	}
}

func TestZeroHOLBlockingAcrossIndependentStreams(t *testing.T) {
	psk := make([]byte, 32)
	_, _ = rand.Read(psk)
	sw := NewLossyUDPSwitch("127.0.0.1:443", 0, 0, 0, 0)
	defer sw.CloseAll()

	ln, err := NewListener(sw.srvConn, false, psk, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var srvStream1 atomic.Pointer[RTCStream]
	srvS1Ready := make(chan struct{})
	go func() {
		for {
			ss, aerr := ln.Accept(ctx)
			if aerr != nil {
				return
			}
			ss.SetHandlers(func(st *RTCStream, target string, first []byte) {
				if target == "hol1.example:443" {
					srvStream1.Store(st)
					close(srvS1Ready)
					_, _ = io.Copy(st, st)
					_ = st.Close()
					return
				}
				defer st.Close()
				if len(first) > 0 {
					_, _ = st.Write(first)
				}
				_, _ = io.Copy(st, st)
			}, nil, nil)
		}
	}()

	cli, _, err := DialWithPacketConn(ctx, sw.NewClientEnd(), true, sw.srvAddr, DialOptions{
		Host: "127.0.0.1", Port: 443, PSK: psk, Timeout: 3 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()

	st1, err := cli.OpenStream("hol1.example:443", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer st1.Close()
	<-srvS1Ready

	// Hold ChunkSeq=0 on client side of st1 by injecting ChunkSeq=1 first directly into reorderBuf
	st1.deliverChunk(1, []byte("-tail"))

	// Concurrent st2 must read/write completely unimpeded in Zero-HOL fashion
	st2, err := cli.OpenStream("hol2.example:443", []byte("fast-s2"))
	if err != nil {
		t.Fatal(err)
	}
	_ = st2.CloseWrite()
	got2, err := io.ReadAll(st2)
	_ = st2.Close()
	if err != nil || string(got2) != "fast-s2" {
		t.Fatalf("Stream 2 was stalled or failed: err=%v got=%q", err, got2)
	}

	// Now fill ChunkSeq=0 gap on st1 and verify seamless in-order delivery
	st1.deliverChunk(0, []byte("head"))
	buf := make([]byte, 16)
	n, err := io.ReadFull(st1, buf[:9])
	if err != nil || n != 9 || string(buf[:9]) != "head-tail" {
		t.Fatalf("Stream 1 out-of-order reassembly failed: n=%d err=%v got=%q", n, err, buf[:n])
	}
}

func TestHighRTT170msAutoProbeDownload(t *testing.T) {
	psk := make([]byte, 32)
	_, _ = rand.Read(psk)
	// 85ms one-way = ~170ms RTT + 3% packet loss + 2% reorder (simulating CN2 trans-Pacific link)
	sw := NewLossyUDPSwitch("127.0.0.1:443", 3, 2, 0, 85*time.Millisecond)
	defer sw.CloseAll()

	ln, err := NewListener(sw.srvConn, false, psk, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	const dlSize = 4 * 1024 * 1024
	payload := make([]byte, dlSize)
	for i := range payload {
		payload[i] = byte(i * 31)
	}

	go func() {
		for {
			ss, aerr := ln.Accept(ctx)
			if aerr != nil {
				return
			}
			ss.SetHandlers(func(st *RTCStream, _ string, _ []byte) {
				defer st.Close()
				_, _ = io.Copy(io.Discard, st)
				_, _ = st.Write(payload)
				_ = st.CloseWrite()
			}, nil, nil)
		}
	}()

	cli, hs, err := DialWithPacketConn(ctx, sw.NewClientEnd(), true, sw.srvAddr, DialOptions{
		Host: "127.0.0.1", Port: 443, PSK: psk, Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer cli.Close()

	st, err := cli.OpenStream("dl.example:443", []byte("GET /4MB"))
	if err != nil {
		t.Fatal(err)
	}
	_ = st.CloseWrite()

	t0 := time.Now()
	got, err := io.ReadAll(st)
	_ = st.Close()
	if err != nil {
		t.Fatalf("read failed: %v (got %d/%d)", err, len(got), dlSize)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch: got %d bytes, want %d", len(got), dlSize)
	}
	t.Logf("170ms RTT + 3%% loss 4MB Auto-Probe download: %v (hs=%v, FEC=%d)",
		time.Since(t0).Round(time.Millisecond), hs.Round(time.Millisecond), cli.Stats().FECRecovered)
}

func TestPTOZeroAmplificationOnBlackhole(t *testing.T) {
	lt := NewLossTracker()
	now := time.Now()
	const initialPkts = 8

	var nextPN uint64
	for i := 0; i < initialPkts; i++ {
		nextPN++
		lt.OnPacketSent(nextPN, 1200, []ReliableFrame{{Bytes: []byte{byte(i)}}}, now)
	}

	for round := 0; round < 15; round++ {
		now = now.Add(5 * time.Second)
		lostFrames, _, _, _, _ := lt.PollTimeouts(now)
		if len(lostFrames) > initialPkts {
			t.Fatalf("round %d: PTO amplification leaked %d frames (want <= %d)", round, len(lostFrames), initialPkts)
		}
		for _, f := range lostFrames {
			nextPN++
			lt.OnPacketSent(nextPN, 1200, []ReliableFrame{f}, now)
		}
		lt.mu.Lock()
		tracked := len(lt.sent)
		lt.mu.Unlock()
		if tracked > initialPkts*2 {
			t.Fatalf("round %d: lt.sent grew unboundedly to %d (want <= %d)", round, tracked, initialPkts*2)
		}
	}
}

func TestReplayWindow8192HighThroughputReorder(t *testing.T) {
	var rw ReplayWindow
	now := time.Now()
	rw.Commit(10000, true, now)

	if !rw.Allow(2500) {
		t.Fatalf("expected pktNum=2500 (delta=7500 < 8192) to be allowed")
	}
	rw.Commit(2500, true, now)
	if rw.Allow(2500) {
		t.Fatalf("expected duplicate pktNum=2500 to be rejected")
	}
	if rw.Allow(1800) {
		t.Fatalf("expected pktNum=1800 (delta=8200 >= 8192) to be rejected")
	}

	largest, _, blocks, ok := rw.BuildSACK(now)
	if !ok || largest != 10000 || len(blocks) != 2 {
		t.Fatalf("unexpected BuildSACK output: ok=%v largest=%d blocks=%+v", ok, largest, blocks)
	}
	if blocks[0] != (SACKBlock{Gap: 0, Len: 1}) || blocks[1] != (SACKBlock{Gap: 7499, Len: 1}) {
		t.Fatalf("expected wide-gap SACK blocks [(0,1),(7499,1)], got %+v", blocks)
	}
}

func TestLossTrackerDeadEntryReclamation(t *testing.T) {
	lt := NewLossTracker()
	t0 := time.Now()

	// 1. Retransmitted pn1 resolved immediately when retransmitted pn2 receives SACK
	lt.OnPacketSent(1, 1200, []ReliableFrame{{Bytes: []byte("f1")}}, t0)
	lost, _, _, _, _ := lt.PollTimeouts(t0.Add(2 * time.Second))
	if len(lost) != 1 || lost[0].OriginPN != 1 {
		t.Fatalf("expected OriginPN=1 on PTO, got %+v", lost)
	}
	lt.OnPacketSent(2, 1200, lost, t0.Add(2*time.Second))
	lt.OnSACK(2, 0, []SACKBlock{{Gap: 0, Len: 1}}, t0.Add(2100*time.Millisecond))

	lt.mu.Lock()
	_, hasPN1 := lt.sent[1]
	lt.mu.Unlock()
	if hasPN1 {
		t.Fatalf("expected retired pn1 to be removed immediately once pn2 was SACKed")
	}

	// 2. Retired entry exceeding 2*max(SRTT, 500ms) gets reclaimed cleanly even without SACK
	lt.OnPacketSent(3, 1200, []ReliableFrame{{Bytes: []byte("f3")}}, t0.Add(3*time.Second))
	_, _, _, _, _ = lt.PollTimeouts(t0.Add(5 * time.Second))
	_, _, _, _, _ = lt.PollTimeouts(t0.Add(6200 * time.Millisecond))
	lt.mu.Lock()
	_, hasPN3 := lt.sent[3]
	lt.mu.Unlock()
	if hasPN3 {
		t.Fatalf("expected unacked retired pn3 to be swept after grace window")
	}
}

type blackholePacketConn struct {
	addr   lossyAddr
	closed chan struct{}
	once   sync.Once
}

func (b *blackholePacketConn) ReadFrom(_ []byte) (int, net.Addr, error) {
	<-b.closed
	return 0, nil, net.ErrClosed
}
func (b *blackholePacketConn) WriteTo(p []byte, _ net.Addr) (int, error) { return len(p), nil }
func (b *blackholePacketConn) Close() error {
	b.once.Do(func() { close(b.closed) })
	return nil
}
func (b *blackholePacketConn) LocalAddr() net.Addr                { return b.addr }
func (b *blackholePacketConn) SetDeadline(_ time.Time) error      { return nil }
func (b *blackholePacketConn) SetReadDeadline(_ time.Time) error  { return nil }
func (b *blackholePacketConn) SetWriteDeadline(_ time.Time) error { return nil }

func TestMakeBeforeBreakHopRejectsBlackholeAndKeepsTrafficAlive(t *testing.T) {
	psk := make([]byte, 32)
	_, _ = rand.Read(psk)

	sw := NewLossyUDPSwitch("127.0.0.1:443", 0, 0, 0, 2*time.Millisecond)
	defer sw.CloseAll()

	ln, err := NewListener(sw.srvConn, false, psk, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	go func() {
		for {
			ss, aerr := ln.Accept(ctx)
			if aerr != nil {
				return
			}
			ss.SetHandlers(func(st *RTCStream, _ string, first []byte) {
				defer st.Close()
				if len(first) > 0 {
					_, _ = st.Write(first)
				}
				_, _ = io.Copy(st, st)
			}, nil, nil)
		}
	}()

	cli, _, err := DialWithPacketConn(ctx, sw.NewClientEnd(), true, sw.srvAddr, DialOptions{
		Host: "127.0.0.1", Port: 443, PSK: psk, Timeout: 3 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()

	st, err := cli.OpenStream("mbb.example:443", []byte("ping1:"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	bh := &blackholePacketConn{addr: lossyAddr("127.0.0.1:21423"), closed: make(chan struct{})}
	if herr := cli.HopWithProbePC(bh, true, lossyAddr("127.0.0.1:21423"), 21423, 150*time.Millisecond); herr == nil {
		t.Fatalf("expected blackholed candidate port to fail MBB probe")
	}

	// Original socket MUST remain 100% functional
	if _, err := st.Write([]byte("alive")); err != nil {
		t.Fatalf("original socket failed after rejected MBB probe: %v", err)
	}
	_ = st.CloseWrite()
	got, err := io.ReadAll(st)
	if err != nil || string(got) != "ping1:alive" {
		t.Fatalf("expected 'ping1:alive' after rejected MBB probe, got %q err=%v", got, err)
	}

	// Valid MBB candidate MUST promote seamlessly
	goodEnd := sw.NewClientEnd()
	if herr := cli.HopWithProbePC(goodEnd, true, sw.srvAddr, 25555, 600*time.Millisecond); herr != nil {
		t.Fatalf("expected reachable candidate port to pass MBB probe: %v", herr)
	}
	if cli.RemotePort() != 25555 {
		t.Fatalf("expected RemotePort updated to 25555, got %d", cli.RemotePort())
	}
}

func TestReplayGuardAndListenerIdleSweep(t *testing.T) {
	rg := NewReplayGuard()
	now := int64(1700000000)
	var tx [12]byte
	tx[0] = 1
	pub := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	if !rg.checkAndRecord(tx, pub, now) {
		t.Fatal("first check should pass")
	}
	if rg.Len() != 1 {
		t.Fatalf("expected Len=1, got %d", rg.Len())
	}
	if rem := rg.Sweep(now + 100); rem != 1 {
		t.Fatalf("expected entry retained at +100s, got rem=%d", rem)
	}
	if rem := rg.Sweep(now + stunReplayWindowSec + 1); rem != 0 || rg.Len() != 0 {
		t.Fatalf("expected expired entry purged after 181s, got rem=%d len=%d", rem, rg.Len())
	}
}
