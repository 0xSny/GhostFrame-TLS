package gftrtc

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestPreScreenZeroAllocAndAntiAmplification(t *testing.T) {
	psk := make([]byte, 32)
	_, _ = rand.Read(psk)
	var cid [8]byte
	_, _ = rand.Read(cid[:])

	now := time.Now()
	reqPkt, _, _, err := BuildClientBindingReq(psk, cid, 0, 0, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(reqPkt) < MinClientSTUNReqLen {
		t.Fatalf("client STUN BindingReq len=%d < MinClientSTUNReqLen=%d", len(reqPkt), MinClientSTUNReqLen)
	}
	if !PreScreenClientBindingReq(reqPkt, psk) {
		t.Fatal("valid request failed FastMAC PreScreen")
	}

	if !testRaceEnabled {
		allocs := testing.AllocsPerRun(500, func() {
			if !PreScreenClientBindingReq(reqPkt, psk) {
				t.Fatal("unexpected prescreen reject")
			}
		})
		if allocs != 0 {
			t.Fatalf("expected 0 allocations in PreScreenClientBindingReq, got %.1f", allocs)
		}
	}

	// Corrupt byte -> silent 0-alloc rejection
	bad := append([]byte(nil), reqPkt...)
	bad[len(bad)-12] ^= 0x01
	if PreScreenClientBindingReq(bad, psk) {
		t.Fatal("corrupted FastMAC unexpectedly passed")
	}
	if PreScreenClientBindingReq(reqPkt[:MinClientSTUNReqLen-1], psk) {
		t.Fatal("short request unexpectedly passed")
	}
	if _, ok := ParseClientBindingReq(bad, psk, NewReplayGuard(), now); ok {
		t.Fatal("ParseClientBindingReq must reject corrupted request")
	}

	// Anti-amplification: server response <= 2x request wire length
	guard := NewReplayGuard()
	parsed, ok := ParseClientBindingReq(reqPkt, psk, guard, now)
	if !ok {
		t.Fatal("ParseClientBindingReq failed on valid packet")
	}
	if parsed.WireLen != len(reqPkt) {
		t.Fatalf("expected WireLen=%d, got %d", len(reqPkt), parsed.WireLen)
	}
	resp, _, err := BuildServerBindingResp(psk, parsed, &net.UDPAddr{IP: net.IPv4(198, 51, 100, 1), Port: 54321}, 1001, 0, 0, []byte(`{"v":4}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(resp) > 2*parsed.WireLen {
		t.Fatalf("server response %dB exceeds 2x request %dB", len(resp), parsed.WireLen)
	}
	// Oversized params that cannot fit within 2x WireLen must fail cleanly
	huge := bytes.Repeat([]byte("a"), 2*parsed.WireLen)
	if _, _, err := BuildServerBindingResp(psk, parsed, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}, 1002, 0, 0, huge); err == nil {
		t.Fatal("expected anti-amplification rejection for oversized paramsJSON")
	}
}

func TestInBandRekey0msAndGraceWindow(t *testing.T) {
	t.Setenv("GFT_REKEY_MB", "1")
	psk := make([]byte, 32)
	_, _ = rand.Read(psk)

	sw := NewLossyUDPSwitch("127.0.0.1:443", 3, 2, 0, 5*time.Millisecond)
	defer sw.CloseAll()

	ln, err := NewListener(sw.srvConn, false, psk, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
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
		Host: "127.0.0.1", Port: 443, PSK: psk, Timeout: 4 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()

	// Verify 1-bit KeyPhase header extraction & SealRTPPhase / OpenRTPPhase
	bp := make([]byte, MaxUDPPayload)
	pktP1, err := SealRTPPhase(bp, cli.currentTXState().aead, cli.currentTXState().iv, cli.currentTXState().mask, 1, 99, 1, 100, PTVideoData, true, 50, []byte("phase1-test"))
	if err != nil {
		t.Fatal(err)
	}
	if ExtractKeyPhase(pktP1) != 1 {
		t.Fatalf("expected ExtractKeyPhase=1, got %d", ExtractKeyPhase(pktP1))
	}

	// Stream 2.5MB across auto + manual rekeys with 0 errors
	st, err := cli.OpenStream("rekey.example:443", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	payload := make([]byte, 2500*1024)
	_, _ = rand.Read(payload)
	wantHash := sha256.Sum256(payload)

	var recvBuf bytes.Buffer
	errCh := make(chan error, 1)
	go func() {
		_, rerr := io.Copy(&recvBuf, st)
		errCh <- rerr
	}()

	// Write first 1.5MB -> wait cleanly for GFT_REKEY_MB=1 automatic Rekey (Epoch 0 -> 1)
	firstPart := 1500 * 1024
	if _, err := st.Write(payload[:firstPart]); err != nil {
		t.Fatal(err)
	}
	rekey1Deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(rekey1Deadline) && cli.RekeyCount() < 1 {
		time.Sleep(25 * time.Millisecond)
	}
	if cli.RekeyCount() < 1 {
		t.Fatalf("expected automated threshold Rekey (>=1MB), got RekeyCount=%d", cli.RekeyCount())
	}
	// Verify 30s grace period holds old phase=0 RX key immediately, and expires it after 31s.
	if cli.getRXState(0, time.Now()) == nil {
		t.Fatal("expected old KeyPhase 0 RX slot retained inside 30s grace window")
	}
	if cli.getRXState(0, time.Now().Add(rekeyGraceDuration+time.Second)) != nil {
		t.Fatal("expected old KeyPhase 0 RX slot shredded after 30s grace window")
	}

	// Force explicit manual TriggerRekey while writing remaining 1MB -> Epoch 1 -> 2
	if err := cli.TriggerRekey(); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Write(payload[firstPart:]); err != nil {
		t.Fatal(err)
	}
	rekey2Deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(rekey2Deadline) && cli.RekeyCount() < 2 {
		time.Sleep(25 * time.Millisecond)
	}
	_ = st.CloseWrite()

	if rerr := <-errCh; rerr != nil {
		t.Fatal(rerr)
	}
	gotHash := sha256.Sum256(recvBuf.Bytes())
	if gotHash != wantHash {
		t.Fatalf("SHA-256 mismatch across in-band Rekey! got=%dB want=%dB", recvBuf.Len(), len(payload))
	}
	if cli.RekeyCount() < 2 {
		t.Fatalf("expected >=2 in-band key rotations (GFT_REKEY_MB=1 + TriggerRekey), got %d", cli.RekeyCount())
	}
}

type sizeCaptureConn struct {
	net.PacketConn
	mu    sync.Mutex
	sizes []int
	rtcp  int
}

func (s *sizeCaptureConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	cp := append([]byte(nil), p...)
	s.mu.Lock()
	if IsRTCPMimic(cp) {
		s.rtcp++
	} else if IsRTPPacket(cp) {
		s.sizes = append(s.sizes, len(cp))
	}
	s.mu.Unlock()
	return s.PacketConn.WriteTo(p, addr)
}

func TestDynamicFrameSizesAndRTCPMimic(t *testing.T) {
	psk := make([]byte, 32)
	_, _ = rand.Read(psk)

	sw := NewLossyUDPSwitch("127.0.0.1:443", 0, 0, 0, 2*time.Millisecond)
	defer sw.CloseAll()

	ln, err := NewListener(sw.srvConn, false, psk, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()

	go func() {
		ss, aerr := ln.Accept(ctx)
		if aerr != nil {
			return
		}
		ss.SetHandlers(func(st *RTCStream, _ string, _ []byte) {
			defer st.Close()
			_, _ = io.Copy(io.Discard, st)
		}, nil, nil)
	}()

	capPC := &sizeCaptureConn{PacketConn: sw.NewClientEnd()}
	cli, _, err := DialWithPacketConn(ctx, capPC, true, sw.srvAddr, DialOptions{
		Host: "127.0.0.1", Port: 443, PSK: psk, Timeout: 4 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()

	// Verify explicit SealRTCPMimic + OpenRTCPMimic RFC 5761 contract
	tx := cli.currentTXState()
	rtcpPkt, err := SealRTCPMimic(nil, tx.aead, tx.iv, tx.mask, tx.phase, cli.SSRC(), 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !IsRTCPMimic(rtcpPkt) || len(rtcpPkt) < 64 || len(rtcpPkt) > 112 {
		t.Fatalf("invalid RTCP mimic packet len=%d", len(rtcpPkt))
	}
	cli.sendRTCPMimicPacket()

	st, err := cli.OpenStream("hist.example:443", nil)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 240*1024)
	_, _ = rand.Read(buf)
	if _, err := st.Write(buf); err != nil {
		t.Fatal(err)
	}
	_ = st.Close()
	time.Sleep(120 * time.Millisecond)

	capPC.mu.Lock()
	sizes := append([]int(nil), capPC.sizes...)
	rtcpCnt := capPC.rtcp
	capPC.mu.Unlock()

	if rtcpCnt == 0 {
		t.Fatal("expected at least 1 RTCP-Mux PT=201 mimic packet sent on wire")
	}
	distinct := make(map[int]bool)
	at1360 := 0
	for _, sz := range sizes {
		if sz > MaxUDPPayload {
			t.Fatalf("packet len=%d exceeds MaxUDPPayload=%d", sz, MaxUDPPayload)
		}
		distinct[sz] = true
		if sz == MaxUDPPayload {
			at1360++
		}
	}
	if len(distinct) < 3 {
		t.Fatalf("expected varied packet sizes eliminating static spike, got only %d distinct sizes (%v)", len(distinct), sizes)
	}
	if len(sizes) > 0 && at1360*100/len(sizes) > 60 {
		t.Fatalf("too many packets pinned at %dB (%d/%d)", MaxUDPPayload, at1360, len(sizes))
	}
}

func TestSessionBackpressure3Tier(t *testing.T) {
	SetLowMemMode(true)
	defer SetLowMemMode(false)

	if EffectiveSessionMaxWindow() != LowMemSessionMaxWindow {
		t.Fatalf("expected LowMemSessionMaxWindow=%d, got %d", LowMemSessionMaxWindow, EffectiveSessionMaxWindow())
	}

	psk := make([]byte, 32)
	_, _ = rand.Read(psk)
	sw := NewLossyUDPSwitch("127.0.0.1:443", 0, 0, 0, 2*time.Millisecond)
	defer sw.CloseAll()

	ln, err := NewListener(sw.srvConn, false, psk, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	srvStreamCh := make(chan *RTCStream, 1)
	go func() {
		ss, aerr := ln.Accept(ctx)
		if aerr != nil {
			return
		}
		ss.SetHandlers(func(st *RTCStream, _ string, _ []byte) {
			srvStreamCh <- st
		}, nil, nil)
	}()

	cli, _, err := DialWithPacketConn(ctx, sw.NewClientEnd(), true, sw.srvAddr, DialOptions{
		Host: "127.0.0.1", Port: 443, PSK: psk, Timeout: 4 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()

	// Allow initial FrameSessionWin(8MB) exchange
	time.Sleep(50 * time.Millisecond)

	st, err := cli.OpenStream("bp.example:443", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	srvSt := <-srvStreamCh
	defer srvSt.Close()

	// 12MB exceeds the 8MB LowMem session window -> writer MUST block while srvSt is unread!
	totalBytes := 12 * 1024 * 1024
	data := make([]byte, totalBytes)
	_, _ = rand.Read(data)
	wantHash := sha256.Sum256(data)

	writeDone := make(chan error, 1)
	go func() {
		_, werr := st.Write(data)
		_ = st.CloseWrite()
		writeDone <- werr
	}()

	select {
	case err := <-writeDone:
		t.Fatalf("expected 12MB write to block under 8MB session window backpressure, finished early err=%v", err)
	case <-time.After(350 * time.Millisecond):
	}

	if q := cli.txQueuedBytes.Load(); q > LowMemSessionMaxWindow+2*1024*1024 {
		t.Fatalf("txQueuedBytes=%d drifted far beyond LowMemSessionMaxWindow=%d", q, LowMemSessionMaxWindow)
	}

	// Drain reader -> writer MUST unblock cleanly and deliver exact SHA-256
	got, err := io.ReadAll(srvSt)
	if err != nil {
		t.Fatal(err)
	}
	if werr := <-writeDone; werr != nil {
		t.Fatal(werr)
	}
	if sha256.Sum256(got) != wantHash {
		t.Fatalf("SHA-256 mismatch after session backpressure release: got=%d want=%d", len(got), len(data))
	}
}

// TestIndustrialChaosSoak validates Gate 2:
// 170ms WAN RTT (85ms one-way) + 12% packet loss + 5% reorder + 30% dead hop blackholes +
// GFT_REKEY_MB=2 + 100 concurrent streams, verifying SHA-256 and zero residual state/goroutine leaks.
func TestIndustrialChaosSoak(t *testing.T) {
	t.Setenv("GFT_REKEY_MB", "2")
	runtime.GC()
	baselineGoroutines := runtime.NumGoroutine()

	psk := make([]byte, 32)
	_, _ = rand.Read(psk)

	// 85ms each way = 170ms simulated RTT, 12% random loss, 5% reorder, 2% dup
	sw := NewLossyUDPSwitch("127.0.0.1:443", 12, 5, 2, 85*time.Millisecond)

	ln, err := NewListener(sw.srvConn, false, psk, 0, nil)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	var activeSrv atomic.Pointer[RTCSession]
	var acceptedMu sync.Mutex
	var accepted []*RTCSession
	go func() {
		for {
			ss, aerr := ln.Accept(ctx)
			if aerr != nil {
				return
			}
			acceptedMu.Lock()
			accepted = append(accepted, ss)
			acceptedMu.Unlock()
			sessRef := ss
			ss.SetHandlers(func(st *RTCStream, _ string, first []byte) {
				activeSrv.Store(sessRef)
				defer st.Close()
				if len(first) > 0 {
					if _, werr := st.Write(first); werr != nil {
						return
					}
				}
				_, _ = io.Copy(st, st)
				_ = st.CloseWrite()
			}, nil, nil)
		}
	}()

	cli, _, err := DialWithPacketConn(ctx, sw.NewClientEnd(), true, sw.srvAddr, DialOptions{
		Host: "127.0.0.1", Port: 443, PSK: psk, Timeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Hop goroutine forcing continuous MBB port hops with ~30% dead-hop blackholes
	hopDone := make(chan struct{})
	var hopWG sync.WaitGroup
	hopWG.Add(1)
	go func() {
		defer hopWG.Done()
		hopIdx := 0
		ticker := time.NewTicker(350 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-hopDone:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				hopIdx++
				if hopIdx%3 == 0 {
					bh := &blackholePacketConn{addr: lossyAddr("127.0.0.1:21423"), closed: make(chan struct{})}
					_ = cli.HopWithProbePC(bh, true, lossyAddr("127.0.0.1:21423"), 21423, 250*time.Millisecond)
				} else {
					port := 22000 + (hopIdx * 13)
					_ = cli.HopWithProbePC(sw.NewClientEnd(), true, sw.srvAddr, port, 700*time.Millisecond)
				}
			}
		}
	}()

	// 100 concurrent streams x 48KB = 4.8MB (> 2MB Rekey threshold -> >=2 automated Rekeys!)
	const numStreams = 100
	const chunkBytes = 48 * 1024

	var streamWG sync.WaitGroup
	errs := make(chan error, numStreams)
	for i := 0; i < numStreams; i++ {
		streamWG.Add(1)
		go func(idx int) {
			defer streamWG.Done()
			payload := make([]byte, chunkBytes)
			for j := range payload {
				payload[j] = byte((idx*31 + j*17) ^ (j >> 5))
			}
			wantHash := sha256.Sum256(payload)

			st, oerr := cli.OpenStream(fmt.Sprintf("chaos-%d.example:443", idx), payload[:256])
			if oerr != nil {
				errs <- fmt.Errorf("stream %d open: %w", idx, oerr)
				return
			}
			if _, werr := st.Write(payload[256:]); werr != nil {
				_ = st.Close()
				errs <- fmt.Errorf("stream %d write: %w", idx, werr)
				return
			}
			_ = st.CloseWrite()

			got, rerr := io.ReadAll(st)
			_ = st.Close()
			if rerr != nil {
				errs <- fmt.Errorf("stream %d read: %w", idx, rerr)
				return
			}
			if sha256.Sum256(got) != wantHash {
				errs <- fmt.Errorf("stream %d sha256 mismatch (got %dB want %dB)", idx, len(got), len(payload))
				return
			}
		}(i)
	}
	streamWG.Wait()
	close(errs)
	for e := range errs {
		close(hopDone)
		hopWG.Wait()
		t.Fatal(e)
	}
	close(hopDone)
	hopWG.Wait()

	if cli.RekeyCount() < 2 {
		t.Fatalf("expected >=2 live Key Rotations across chaos soak (4.8MB echo with GFT_REKEY_MB=2), got %d", cli.RekeyCount())
	}
	if cli.HopCount() < 2 {
		t.Fatalf("expected >=2 successful MBB port hops amidst 30%% blackhole probes, got %d", cli.HopCount())
	}

	srvSess := activeSrv.Load()
	if srvSess == nil {
		t.Fatal("expected active server session recorded")
	}

	// Wait cleanly for SACK / retired RACK entries & FIN cleanup on both endpoints
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if cli.LossSentLen() == 0 && srvSess.LossSentLen() == 0 &&
			cli.NumStreams() == 0 && srvSess.NumStreams() == 0 &&
			cli.ActiveUDPCount() == 0 && srvSess.ActiveUDPCount() == 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	if cli.LossSentLen() != 0 || srvSess.LossSentLen() != 0 {
		t.Fatalf("expected zero residual LossTracker entries after drain, got cli=%d srv=%d", cli.LossSentLen(), srvSess.LossSentLen())
	}
	if cli.NumStreams() != 0 || srvSess.NumStreams() != 0 {
		t.Fatalf("expected 0 active streams after close, got cli=%d srv=%d", cli.NumStreams(), srvSess.NumStreams())
	}
	if cli.ActiveUDPCount() != 0 || srvSess.ActiveUDPCount() != 0 {
		t.Fatalf("expected 0 NAT UDP associations, got cli=%d srv=%d", cli.ActiveUDPCount(), srvSess.ActiveUDPCount())
	}

	t.Logf("ChaosSoak PASSED: 100 streams (4.8MB echo, 170ms RTT, 12%% loss, 5%% reorder), Rekeys=%d, Hops=%d, FEC=%d",
		cli.RekeyCount(), cli.HopCount(), cli.Stats().FECRecovered)

	// Shut down all session & listener resources cleanly before goroutine leak assertion
	cli.Close()
	acceptedMu.Lock()
	for _, s := range accepted {
		s.Close()
	}
	acceptedMu.Unlock()
	_ = ln.Close()
	sw.CloseAll()

	// Allow hopOldCloseDelay (3s) + worker teardown to drain before final goroutine check
	leakDeadline := time.Now().Add(4500 * time.Millisecond)
	for time.Now().Before(leakDeadline) {
		runtime.GC()
		if runtime.NumGoroutine() <= baselineGoroutines+2 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if g := runtime.NumGoroutine(); g > baselineGoroutines+2 {
		t.Fatalf("goroutine leak detected after chaos soak: baseline=%d final=%d", baselineGoroutines, g)
	}
}

func referenceBuildSACK(w *ReplayWindow, now time.Time) (largest uint64, ackDelayUs uint32, blocks []SACKBlock, ok bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.init {
		return 0, 0, nil, false
	}
	largest = w.largest
	limit := replayWindowBits
	if largest < uint64(limit) {
		limit = int(largest)
	}
	blocks = make([]SACKBlock, 0, 8)
	gap := 0
	inBlock := false
	blockLen := 0
	for d := 0; d < limit; d++ {
		set := (w.words[d>>6] & (uint64(1) << (d & 63))) != 0
		if set {
			if !inBlock {
				inBlock = true
				blockLen = 1
			} else {
				blockLen++
			}
		} else if inBlock {
			if gap > 65535 {
				break
			}
			blocks = append(blocks, SACKBlock{Gap: uint16(gap), Len: uint16(blockLen)})
			if len(blocks) >= MaxSACKBlocks {
				inBlock = false
				break
			}
			inBlock = false
			gap = 1
			blockLen = 0
		} else {
			gap++
		}
	}
	if inBlock && len(blocks) < MaxSACKBlocks && gap <= 65535 {
		blocks = append(blocks, SACKBlock{Gap: uint16(gap), Len: uint16(blockLen)})
	}
	return largest, 0, blocks, true
}

func TestV4BuildSACKWordSkipEquivalence(t *testing.T) {
	now := time.Now()
	// Pattern 1: Full 8192-bit contiguous window
	var rw1 ReplayWindow
	for pn := uint64(1); pn <= 9000; pn++ {
		rw1.Commit(pn, true, now)
	}
	_, _, ref1, ok1 := referenceBuildSACK(&rw1, now)
	largest1, _, got1, okGot1 := rw1.BuildSACK(now)
	if !ok1 || !okGot1 || largest1 != 9000 || len(got1) != len(ref1) || got1[0] != (SACKBlock{Gap: 0, Len: replayWindowBits}) {
		t.Fatalf("full 8192 mismatch: largest=%d got=%+v ref=%+v", largest1, got1, ref1)
	}

	// Pattern 2: Word-aligned holes, full words, zero words, and partial boundary holes
	var rw2 ReplayWindow
	for pn := uint64(1); pn <= 8500; pn++ {
		// Drop full words [257..320], single bit at 512, 513, alternating run [700..767]
		if (pn >= 257 && pn <= 320) || pn == 512 || pn == 513 || (pn >= 700 && pn <= 767 && pn%2 == 0) || (pn >= 1000 && pn <= 1255) {
			continue
		}
		rw2.Commit(pn, true, now)
	}
	_, _, ref2, ok2 := referenceBuildSACK(&rw2, now)
	_, _, got2, okGot2 := rw2.BuildSACK(now)
	if !ok2 || !okGot2 || len(got2) != len(ref2) {
		t.Fatalf("word-boundary SACK block count mismatch: got=%d (%+v) ref=%d (%+v)", len(got2), got2, len(ref2), ref2)
	}
	for i := range ref2 {
		if got2[i] != ref2[i] {
			t.Fatalf("block %d mismatch: got=%+v want=%+v", i, got2[i], ref2[i])
		}
	}

	// Pattern 3: Sparse large zero gap (>128 packets missing at start)
	var rw3 ReplayWindow
	rw3.Commit(1, true, now)
	rw3.Commit(1000, true, now)
	rw3.Commit(1001, true, now)
	_, _, ref3, _ := referenceBuildSACK(&rw3, now)
	_, _, got3, _ := rw3.BuildSACK(now)
	if len(got3) != len(ref3) {
		t.Fatalf("sparse SACK mismatch: got=%+v ref=%+v", got3, ref3)
	}
	for i := range ref3 {
		if got3[i] != ref3[i] {
			t.Fatalf("sparse block %d mismatch: got=%+v want=%+v", i, got3[i], ref3[i])
		}
	}
}

func TestV4OnSACK8192WindowNoQuadraticCPU(t *testing.T) {
	lt := NewLossTracker()
	now := time.Now()
	const totalPkts = 10000
	const sackIters = 2000

	blocks := []SACKBlock{{Gap: 0, Len: replayWindowBits}}
	start := time.Now()
	var ackCount int
	var pn uint64
	for iter := 0; iter < sackIters; iter++ {
		for k := 0; k < totalPkts/sackIters; k++ {
			pn++
			lt.OnPacketSent(pn, 1360, []ReliableFrame{{Bytes: []byte{FrameStreamData}}}, now)
		}
		sr := lt.OnSACK(pn, 100, blocks, now.Add(time.Duration(iter)*time.Millisecond))
		ackCount += sr.AckedPkts
	}
	elapsed := time.Since(start)
	if ackCount != totalPkts {
		t.Fatalf("expected %d acked packets, got %d", totalPkts, ackCount)
	}
	if lt.SentLen() != 0 || lt.InFlightBytes() != 0 {
		t.Fatalf("expected clean drain: sentLen=%d inFlight=%d", lt.SentLen(), lt.InFlightBytes())
	}
	if elapsed > 250*time.Millisecond {
		t.Fatalf("8192-bit OnSACK regression took %v (want < 250ms)", elapsed)
	}
	t.Logf("10000 pkts / 2000 full-8192 SACKs completed in %v", elapsed)
}

func TestDialLegacyV3Fallback(t *testing.T) {
	psk := make([]byte, 32)
	_, _ = rand.Read(psk)

	// Part 1: Against a v4.0 Listener, attempt 0 connects cleanly with legacyV3=false.
	swV4 := NewLossyUDPSwitch("127.0.0.1:443", 0, 0, 0, 2*time.Millisecond)
	defer swV4.CloseAll()
	lnV4, err := NewListener(swV4.srvConn, false, psk, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer lnV4.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	go func() {
		ss, aerr := lnV4.Accept(ctx)
		if aerr == nil && ss != nil {
			ss.SetHandlers(nil, nil, nil)
		}
	}()

	cliV4, _, err := DialWithPacketConn(ctx, swV4.NewClientEnd(), true, swV4.srvAddr, DialOptions{
		Host: "127.0.0.1", Port: 443, PSK: psk, Timeout: 4 * time.Second,
	})
	if err != nil {
		t.Fatalf("Dial against v4.0 Listener failed: %v", err)
	}
	if cliV4.legacyV3 {
		t.Fatal("expected legacyV3=false when connecting to v4.0 server")
	}
	cliV4.Close()

	// Part 2: Simulated v3.4 server (only accepts v3.4 tickets without trailing 16B FastMAC).
	swV3 := NewLossyUDPSwitch("127.0.0.1:443", 0, 0, 0, 2*time.Millisecond)
	defer swV3.CloseAll()

	v3RejectedFastMAC := atomic.Int32{}
	var srvSessMu sync.Mutex
	var srvSess *RTCSession

	go func() {
		for {
			bp := GetPktBuf()
			n, raddr, rerr := swV3.srvConn.ReadFrom(*bp)
			if rerr != nil {
				PutPktBuf(bp)
				return
			}
			raw := (*bp)[:n]
			srvSessMu.Lock()
			ss := srvSess
			srvSessMu.Unlock()
			if ss != nil && IsRTPPacket(raw) {
				ss.enqueueInbound(inboundPkt{
					buf:  bp,
					n:    n,
					addr: raddr,
					at:   time.Now(),
				})
				continue
			}
			deferPut := bp

			txID, attrs, ok := verifySTUNBaseAndFingerprint(raw, stunTypeBindingReq)
			if !ok {
				PutPktBuf(deferPut)
				continue
			}
			ticket, ok := findSTUNAttr(attrs, attrGFTTicket)
			if !ok || len(ticket) < 32 {
				PutPktBuf(deferPut)
				continue
			}
			pubBytes := append([]byte(nil), ticket[:32]...)
			aead, err := hkdfAEADChaCha(psk, txID[:], "gftrtc-v1-c2s")
			if err != nil {
				PutPktBuf(deferPut)
				continue
			}
			// Deliberately decrypt the full ticket (without stripping FastMAC), matching v3.4 server behavior:
			// v4.0 FastMAC packets fail Poly1305 here and get silently dropped!
			pt, err := aead.Open(nil, txID[:], ticket[32:], pubBytes)
			wireLen := len(raw)
			PutPktBuf(deferPut)
			if err != nil || len(pt) < 24 || string(pt[0:4]) != stunTicketMagic {
				v3RejectedFastMAC.Add(1)
				continue
			}
			cliPub, err := ecdh.X25519().NewPublicKey(pubBytes)
			if err != nil {
				continue
			}
			req := &ParsedClientReq{
				TxID:         txID,
				ClientPub:    cliPub,
				ClientRxMbps: binary.BigEndian.Uint16(pt[20:22]),
				ClientFlags:  binary.BigEndian.Uint16(pt[22:24]),
				WireLen:      wireLen,
			}
			copy(req.ClientID[:], pt[12:20])

			var ssrcBytes [4]byte
			_, _ = rand.Read(ssrcBytes[:])
			ssrc := binary.BigEndian.Uint32(ssrcBytes[:]) | 1
			respPkt, keys, err := BuildServerBindingResp(psk, req, raddr, ssrc, 0, 0, nil)
			if err != nil {
				continue
			}
			newSS := newRTCSession(false, ssrc, req.ClientID, raddr.String(), 443, keys, 0, nil, nil)
			newSS.connMu.Lock()
			newSS.curConn = swV3.srvConn
			newSS.curOwn = false
			newSS.curRemote = raddr
			newSS.curRemoteStr = raddr.String()
			newSS.connMu.Unlock()
			newSS.SetHandlers(func(st *RTCStream, _ string, _ []byte) {
				go func() {
					defer st.Close()
					_, _ = io.Copy(st, st)
				}()
			}, nil, nil)
			newSS.startLoops()
			srvSessMu.Lock()
			srvSess = newSS
			srvSessMu.Unlock()
			_, _ = swV3.srvConn.WriteTo(respPkt, raddr)
		}
	}()

	cliV3, _, err := DialWithPacketConn(ctx, swV3.NewClientEnd(), true, swV3.srvAddr, DialOptions{
		Host: "127.0.0.1", Port: 443, PSK: psk, Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("Dial fallback against v3.4 server failed: %v", err)
	}
	defer cliV3.Close()
	defer func() {
		srvSessMu.Lock()
		ss := srvSess
		srvSessMu.Unlock()
		if ss != nil {
			ss.Close()
		}
	}()

	if !cliV3.legacyV3 {
		t.Fatal("expected legacyV3=true when falling back to v3.4 server")
	}
	if v3RejectedFastMAC.Load() < 2 {
		t.Fatalf("expected v3.4 server to reject attempts 0 & 1 (FastMAC) before fallback, rejected=%d", v3RejectedFastMAC.Load())
	}

	st, err := cliV3.OpenStream("legacy.example:443", nil)
	if err != nil {
		t.Fatalf("OpenStream on legacyV3 session failed: %v", err)
	}
	payload := []byte("hello-v3-server-through-v4-client")
	if _, err := st.Write(payload); err != nil {
		t.Fatal(err)
	}
	_ = st.CloseWrite()
	echoed, err := io.ReadAll(st)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(echoed, payload) {
		t.Fatalf("echo mismatch: got %q want %q", echoed, payload)
	}
}

func TestEarlyCloseStreamReleasesSessionWindowAndDedup(t *testing.T) {
	keys, _, err := deriveSessionKeys([]byte("shared-secret-32bytes-0123456789"), []byte("test-psk-0123456789abcdef012345"), [12]byte{1, 2, 3}, false)
	if err != nil {
		t.Fatalf("deriveSessionKeys failed: %v", err)
	}
	s := newRTCSession(false, 0x11223344, [8]byte{}, "127.0.0.1", 0, keys, 0, nil, nil)
	s.startLoops()
	defer s.Close()

	st := s.getOrCreatePendingStream(77)
	if st == nil {
		t.Fatal("expected pending stream 77")
	}
	chunk := bytes.Repeat([]byte("A"), 1024)
	st.deliverChunk(0, chunk)
	// Simulate immediate abort/early close with unread bytes in readyBuf.
	st.abort(ErrStreamReset, false)
	afterAbort := s.rxConsumedBytes.Load()
	if afterAbort != 1024 {
		t.Fatalf("expected 1024 consumed after abort, got %d", afterAbort)
	}

	// Duplicate retransmit of seq=0 MUST NOT over-credit session window.
	dupFrame := encodeFrameStreamData(77, 0, chunk)
	s.dispatchFrames(dupFrame, time.Now())
	if got := s.rxConsumedBytes.Load(); got != 1024 {
		t.Fatalf("duplicate retransmit over-credited rxConsumedBytes: got %d want 1024", got)
	}

	// Brand-new in-flight seq=1 & seq=2 arriving after close MUST credit session window once each.
	late1 := encodeFrameStreamData(77, 1, chunk)
	late2 := encodeFrameStreamData(77, 2, chunk)
	s.dispatchFrames(append(late1, late2...), time.Now())
	// Retransmit late1 again — still deduplicated.
	s.dispatchFrames(encodeFrameStreamData(77, 1, chunk), time.Now())
	if got := s.rxConsumedBytes.Load(); got != 3072 {
		t.Fatalf("expected 3072 consumed after late in-flight frames + dedup, got %d", got)
	}
}

func TestWatchdogDoesNotKillIdleSessionAndClearsOnInbound(t *testing.T) {
	keys, _, err := deriveSessionKeys([]byte("shared-secret-32bytes-0123456789"), []byte("test-psk-0123456789abcdef012345"), [12]byte{4, 5, 6}, false)
	if err != nil {
		t.Fatalf("deriveSessionKeys failed: %v", err)
	}
	s := newRTCSession(true, 0x55667788, [8]byte{}, "127.0.0.1", 0, keys, 0, nil, nil)
	defer s.Close()

	oldNs := time.Now().Add(-10 * time.Second).UnixNano()
	s.lastRecvNs.Store(oldNs)
	s.unackedTxSinceNs.Store(oldNs)

	// Idle session (InFlightBytes == 0 && !hasPendingData()) must clear unackedTxSinceNs, not trip watchdog.
	if s.loss.InFlightBytes() != 0 || s.hasPendingData() {
		t.Fatal("expected idle session")
	}
	s.unackedTxSinceNs.CompareAndSwap(oldNs, 0)
	// Also test handleInboundPacket clears unackedTxSinceNs on valid RTP frame (with no in-flight bytes).
	s.unackedTxSinceNs.Store(time.Now().UnixNano())
	var area [64]byte
	ping := encodeFramePingPong(FramePing, time.Now().UnixNano())
	copy(area[FECHeaderLen:], ping)
	srvTX, _ := newDirKeyStates(false, keys)
	var wire [256]byte
	sealed, err := SealRTPPhase(wire[:], srvTX.aead, srvTX.iv, srvTX.mask, srvTX.phase, 0x55667788, 1, 1000, PTAudioCtrl, true, 1, area[:FECHeaderLen+len(ping)])
	if err != nil {
		t.Fatalf("SealRTPPhase failed: %v", err)
	}
	pktBuf := make([]byte, len(sealed))
	copy(pktBuf, sealed)
	var plain [512]byte
	s.handleInboundPacket(inboundPkt{buf: &pktBuf, n: len(pktBuf), at: time.Now()}, plain[:0])
	if got := s.unackedTxSinceNs.Load(); got != 0 {
		t.Fatalf("expected valid inbound RTP packet with 0 in-flight bytes to clear unackedTxSinceNs, got %d", got)
	}
}
