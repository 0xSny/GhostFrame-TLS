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
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ghostframe/internal/netbind"
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
			ticket, ok := findSTUNAttr(attrs, attrKSLTicket)
			if !ok || len(ticket) < 32 {
				v3RejectedFastMAC.Add(1)
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

func TestNAT64DialSynthesizes64ff9b(t *testing.T) {
	restore := netbind.SetNAT64TestHooks(
		func() bool { return true },
		func(ctx context.Context, host string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("64:ff9b::192.0.0.170")}, nil
		},
		nil,
	)
	defer restore()

	psk := make([]byte, 32)
	_, _ = rand.Read(psk)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Millisecond)
	defer cancel()

	_, _, err := Dial(ctx, DialOptions{
		Host:    "198.51.100.42",
		Port:    443,
		PSK:     psk,
		Timeout: 120 * time.Millisecond,
	})
	if err == nil {
		t.Fatalf("expected dial to unroutable test IPv4 NAT64 target to fail")
	}
	if !strings.Contains(err.Error(), "64:ff9b::c633:642a") {
		t.Fatalf("expected gftrtc.Dial to synthesize 64:ff9b::c633:642a, got err=%v", err)
	}
}

func TestClientAutoProbeCapPolicingWallAndExplicitUnlimited(t *testing.T) {
	now := time.Now()

	// 1. Client Auto-Probe (targetMbps=0, isClient=true) must cap ramp at 60 Mbps.
	cliCC := NewSmartBrutalCCForRole(0, true)
	for round := 1; round <= 12; round++ {
		ts := now.Add(time.Duration(round) * 60 * time.Millisecond)
		// Deliver full current pacing rate with 0% loss and flat RTT
		cliCC.OnFeedback(2_000_000, 0.0, 40*time.Millisecond, 40*time.Millisecond, 0, ts)
	}
	cliMbps := cliCC.PacingMbps()
	if cliMbps > 60.1 || cliMbps < 50.0 {
		t.Fatalf("expected client Auto-Probe pacing capped near 60 Mbps, got %.2f Mbps", cliMbps)
	}

	// 2. Server Auto-Probe (targetMbps=0, isClient=false) keeps 600 Mbps ceiling for high-BDP downlinks.
	srvCC := NewSmartBrutalCCForRole(0, false)
	for round := 1; round <= 12; round++ {
		ts := now.Add(time.Duration(round) * 60 * time.Millisecond)
		srvCC.OnFeedback(5_000_000, 0.0, 40*time.Millisecond, 40*time.Millisecond, 0, ts)
	}
	if srvMbps := srvCC.PacingMbps(); srvMbps <= 65.0 {
		t.Fatalf("expected server Auto-Probe to ramp past 65 Mbps toward 600 Mbps, got %.2f Mbps", srvMbps)
	}

	// 3. Explicit client UpMbps > 0 (e.g. 150 Mbps) must NOT be capped at 60 Mbps.
	explicitCC := NewSmartBrutalCCForRole(150, true)
	if m := explicitCC.PacingMbps(); m < 145.0 || m > 155.0 {
		t.Fatalf("expected explicit 150 Mbps client pacing ~150 Mbps, got %.2f Mbps", m)
	}

	// 4. Hitting physical policing wall (rho=1.05 <= 1.35, lossRate=0.25 > 0.10):
	// MUST exit ccSlowStart, apply 0.75x backoff, and forbid 1/(1-loss) acceleration!
	policingCC := NewSmartBrutalCCForRole(0, true)
	policingCC.OnFeedback(200_000, 0.0, 40*time.Millisecond, 40*time.Millisecond, 0, now.Add(50*time.Millisecond))
	beforeMbps := policingCC.PacingMbps()
	policingCC.OnFeedback(150_000, 0.25, 42*time.Millisecond, 40*time.Millisecond, 0, now.Add(110*time.Millisecond))
	afterMbps := policingCC.PacingMbps()
	if policingCC.state != ccCruise {
		t.Fatalf("expected policing loss >10%% to exit ccSlowStart into ccCruise, got state=%d", policingCC.state)
	}
	if afterMbps >= beforeMbps*0.80 {
		t.Fatalf("expected 0.75x backoff with ZERO 1/(1-loss) boost: before=%.2f Mbps, after=%.2f Mbps", beforeMbps, afterMbps)
	}

	// 5. Server Auto-Probe (isClient=false) MUST NOT slash downlink under cross-border random loss with flat RTT (rho<=1.35):
	// it must preserve Zone A 1/(1-loss) compensation so server->client throughput isn't starved!
	srvLossyCC := NewSmartBrutalCCForRole(0, false)
	srvLossyCC.OnFeedback(250_000, 0.0, 100*time.Millisecond, 100*time.Millisecond, 0, now.Add(110*time.Millisecond))
	srvBefore := srvLossyCC.PacingMbps()
	srvLossyCC.OnFeedback(250_000, 0.15, 101*time.Millisecond, 100*time.Millisecond, 0, now.Add(220*time.Millisecond))
	srvAfter := srvLossyCC.PacingMbps()
	if srvAfter <= srvBefore {
		t.Fatalf("expected server Auto-Probe under 15%% flat-RTT loss to compensate/ramp upward, got before=%.2f after=%.2f", srvBefore, srvAfter)
	}
}

func TestClientSendBacklogCap8MBPreservesServer32MB(t *testing.T) {
	SetLowMemMode(false)
	if EffectiveSessionMaxWindow() != 32*1024*1024 {
		t.Fatalf("expected receive-side DefaultSessionMaxWindow=32MB untouched, got %d", EffectiveSessionMaxWindow())
	}
	if ClientMaxSendBacklog != 8*1024*1024 {
		t.Fatalf("expected ClientMaxSendBacklog=8MB, got %d", ClientMaxSendBacklog)
	}

	keys, _, err := deriveSessionKeys([]byte("shared-secret-32bytes-0123456789"), []byte("test-psk-0123456789abcdef012345"), [12]byte{7, 8, 9}, false)
	if err != nil {
		t.Fatal(err)
	}
	cli := newRTCSession(true, 0x11112222, [8]byte{}, "127.0.0.1", 443, keys, 0, nil, nil)
	defer cli.Close()
	srv := newRTCSession(false, 0x33334444, [8]byte{}, "127.0.0.1", 443, keys, 0, nil, nil)
	defer srv.Close()

	// Both start with peerSessMax=32MB, but client hits send backlog limit at 8MB while server does not.
	cli.txQueuedBytes.Store(8 * 1024 * 1024)
	srv.txQueuedBytes.Store(8 * 1024 * 1024)
	if !cli.sendBacklogLimited() {
		t.Fatal("expected client session sendBacklogLimited()=true at 8MB queued unsent backlog")
	}
	if srv.sendBacklogLimited() {
		t.Fatal("expected server session NOT to be capped at 8MB (keeps 32MB downlink window)")
	}
	// Once sendLoop drains 2MB into txStreamBytes, client unsent backlog drops to 6MB (<8MB) and unblocks.
	cli.txStreamBytes.Store(2 * 1024 * 1024)
	if cli.sendBacklogLimited() {
		t.Fatal("expected client sendBacklogLimited()=false once unsent backlog drains to 6MB")
	}
}

func TestHandshakeFlowAcctV2AndLowMemFlags(t *testing.T) {
	origLowMem := IsLowMemMode()
	t.Cleanup(func() { SetLowMemMode(origLowMem) })

	psk := make([]byte, 32)
	_, _ = rand.Read(psk)
	guard := NewReplayGuard()

	// 1. LowMem client announces FlagLowMemSession | FlagFlowAcctV2; server echoes FlagFlowAcctV2 + FlagLowMemSession.
	SetLowMemMode(true)
	reqPkt, cliPriv, txID, err := BuildClientBindingReq(psk, [8]byte{1, 2, 3, 4}, 100, 0, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	parsedReq, ok := ParseClientBindingReq(reqPkt, psk, guard, time.Now())
	if !ok {
		t.Fatal("ParseClientBindingReq failed")
	}
	if parsedReq.ClientFlags&(FlagLowMemSession|FlagFlowAcctV2) != (FlagLowMemSession | FlagFlowAcctV2) {
		t.Fatalf("expected client flags to include LowMemSession|FlowAcctV2, got 0x%x", parsedReq.ClientFlags)
	}

	SetLowMemMode(false)
	respPkt, keys, err := BuildServerBindingResp(psk, parsedReq, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 50000}, 0xCAFEBABE, 100, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	parsedResp, _, ok := ParseServerBindingResp(respPkt, psk, cliPriv, txID)
	if !ok {
		t.Fatal("ParseServerBindingResp failed")
	}
	if parsedResp.Flags&FlagFlowAcctV2 == 0 {
		t.Fatalf("expected server to echo FlagFlowAcctV2, got 0x%x", parsedResp.Flags)
	}

	// Server applying LowMem client flags starts directly with peerSessMax == LowMemSessionMaxWindow (8MB),
	// and FrameSessionWin updates remain strictly monotonically increasing.
	srv := newRTCSession(false, 0xCAFEBABE, [8]byte{}, "127.0.0.1", 50000, keys, 100, nil, nil)
	defer srv.Close()
	srv.applyPeerHandshakeFlags(parsedReq.ClientFlags)
	if !srv.flowAcctV2.Load() || srv.peerSessMax.Load() != LowMemSessionMaxWindow {
		t.Fatalf("expected server peerSessMax=8MB & flowAcctV2=true, got max=%d v2=%v", srv.peerSessMax.Load(), srv.flowAcctV2.Load())
	}

	var bigger [9]byte
	bigger[0] = FrameSessionWin
	binary.BigEndian.PutUint64(bigger[1:9], uint64(12*1024*1024))
	srv.dispatchFrames(bigger[:], time.Now())
	if srv.peerSessMax.Load() != 12*1024*1024 {
		t.Fatalf("expected monotonic FrameSessionWin increase to 12MB, got %d", srv.peerSessMax.Load())
	}
	var staleSmaller [9]byte
	staleSmaller[0] = FrameSessionWin
	binary.BigEndian.PutUint64(staleSmaller[1:9], uint64(8*1024*1024))
	srv.dispatchFrames(staleSmaller[:], time.Now())
	if srv.peerSessMax.Load() != 12*1024*1024 {
		t.Fatalf("expected stale smaller FrameSessionWin(8MB) to be ignored, got %d", srv.peerSessMax.Load())
	}
}

func TestStreamRSTFinalExactWindowConservationAndDataBlocked(t *testing.T) {
	origLowMem := IsLowMemMode()
	SetLowMemMode(true)
	t.Cleanup(func() { SetLowMemMode(origLowMem) })

	keys, _, err := deriveSessionKeys([]byte("shared-secret-32bytes-0123456789"), []byte("test-psk-0123456789abcdef012345"), [12]byte{1, 2, 3}, false)
	if err != nil {
		t.Fatal(err)
	}

	cli := newRTCSession(true, 0x10102020, [8]byte{}, "127.0.0.1", 443, keys, 0, nil, nil)
	defer cli.Close()
	cli.applyPeerHandshakeFlags(FlagFlowAcctV2 | FlagLowMemSession)

	srv := newRTCSession(false, 0x10102020, [8]byte{}, "127.0.0.1", 443, keys, 0, nil, nil)
	defer srv.Close()
	srv.applyPeerHandshakeFlags(FlagFlowAcctV2 | FlagLowMemSession)

	// TX side: queue 5 chunks, pop 2 onto wire (2200B), enqueue 1 into retransmitQ, then abort/Close().
	stTX := newRTCStream(cli, 1, "example.com:443")
	cli.mu.Lock()
	cli.streams[1] = stTX
	cli.mu.Unlock()
	cli.streamCount.Add(1)

	payload := bytes.Repeat([]byte{'A'}, 5*1100)
	if _, err := stTX.Write(payload); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		fr, dlen, _, _, ok := stTX.popSendFrame(MaxFrameArea, true)
		if !ok || dlen != 1100 {
			t.Fatalf("popSendFrame #%d failed: ok=%v dlen=%d", i, ok, dlen)
		}
		cli.txStreamBytes.Add(int64(dlen))
		cli.enqueueReliableFrame(fr) // simulate unacked chunk sitting in retransmitQ
	}
	_ = stTX.Close()

	// Dead FrameStreamData for stream 1 must be pruned, while FrameStreamRSTFinal(1, 2200) is queued.
	var foundRSTFinal bool
	var finalWire uint64
	cli.qMu.Lock()
	for _, rf := range cli.retransmitQ {
		if len(rf.Bytes) >= 5 && rf.Bytes[0] == FrameStreamData && binary.BigEndian.Uint32(rf.Bytes[1:5]) == 1 {
			t.Fatalf("expected dead stream 1 FrameStreamData pruned from retransmitQ")
		}
		if len(rf.Bytes) == 13 && rf.Bytes[0] == FrameStreamRSTFinal && binary.BigEndian.Uint32(rf.Bytes[1:5]) == 1 {
			foundRSTFinal = true
			finalWire = binary.BigEndian.Uint64(rf.Bytes[5:13])
		}
	}
	cli.qMu.Unlock()
	if !foundRSTFinal || finalWire != 2200 {
		t.Fatalf("expected FrameStreamRSTFinal(1, 2200), got found=%v finalWire=%d", foundRSTFinal, finalWire)
	}
	if cli.txQueuedBytes.Load() != cli.txStreamBytes.Load() {
		t.Fatalf("expected txQueuedBytes (%d) aligned with txStreamBytes (%d) after Close()", cli.txQueuedBytes.Load(), cli.txStreamBytes.Load())
	}

	// RX side: another stream 3 has 500B buffered; stream 1 only received chunk 0 (1100B) and lost chunk 1.
	stOther := newRTCStream(srv, 3, "other.com:443")
	stOther.deliverChunk(0, bytes.Repeat([]byte{'B'}, 500))
	stRX := newRTCStream(srv, 1, "example.com:443")
	srv.mu.Lock()
	srv.streams[3] = stOther
	srv.streams[1] = stRX
	srv.mu.Unlock()
	srv.streamCount.Add(2)
	stRX.deliverChunk(0, bytes.Repeat([]byte{'A'}, 1100))

	rstFrame := encodeFrameStreamRSTFinal(1, finalWire)
	srv.dispatchFrames(rstFrame, time.Now())
	// Duplicate RSTFinal + late duplicate chunk 1 must be completely ignored without double accounting!
	srv.dispatchFrames(rstFrame, time.Now())
	srv.dispatchFrames(encodeFrameStreamData(1, 1, bytes.Repeat([]byte{'A'}, 1100)), time.Now())

	if srv.rxConsumedBytes.Load() != int64(finalWire) {
		t.Fatalf("expected rxConsumedBytes=%d after RSTFinal + duplicates, got %d", finalWire, srv.rxConsumedBytes.Load())
	}
	if srv.rxBufferedBytes.Load() != 500 {
		t.Fatalf("expected concurrent stream 3 rxBufferedBytes preserved at 500, got %d", srv.rxBufferedBytes.Load())
	}

	// Verify FrameDataBlocked triggers immediate FrameSessionWin in ctrlQ even < 1MB step.
	srv.dispatchFrames(encodeFrameDataBlocked(1234), time.Now())
	var sawWin bool
	srv.qMu.Lock()
	for _, cf := range srv.ctrlQ {
		if len(cf) == 9 && cf[0] == FrameSessionWin {
			sawWin = true
		}
	}
	srv.qMu.Unlock()
	if !sawWin {
		t.Fatal("expected FrameDataBlocked to immediately enqueue FrameSessionWin into ctrlQ")
	}

	// Verify 15s orphan pendingStream sweep frees buffered bytes.
	orphan := srv.getOrCreatePendingStream(999)
	orphan.deliverChunk(0, bytes.Repeat([]byte{'C'}, 400))
	orphan.createdAt = time.Now().Add(-16 * time.Second)
	srv.sweepOrphanPendingStreams(time.Now())
	srv.mu.Lock()
	_, stillPending := srv.pendingStreams[999]
	srv.mu.Unlock()
	if stillPending || srv.rxBufferedBytes.Load() != 500 {
		t.Fatalf("expected 15s orphan pending stream swept & 400B released, stillPending=%v rxBuffered=%d", stillPending, srv.rxBufferedBytes.Load())
	}
}

func TestLowMemLossyConcurrentOpenRST64MBZeroDeadlock(t *testing.T) {
	origLowMem := IsLowMemMode()
	SetLowMemMode(true)
	t.Cleanup(func() { SetLowMemMode(origLowMem) })

	psk := make([]byte, 32)
	_, _ = rand.Read(psk)

	// 22% random packet loss (within 20%~30% weak-net spec) + 3% reordering + 1% duplicate + 1ms path delay.
	sw := NewLossyUDPSwitch("127.0.0.1:21443", 22, 3, 1, time.Millisecond)
	defer sw.CloseAll()

	ln, err := NewListener(sw.srvConn, false, psk, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	var srvResetAccepted atomic.Int64
	go func() {
		for {
			srvSess, aerr := ln.Accept(ctx)
			if aerr != nil {
				return
			}
			srvSess.SetHandlers(func(st *RTCStream, target string, first []byte) {
				defer st.Close()
				// Server drains all client bytes cleanly and echoes back tiny completion ack
				// so client can open/transfer >64MB through the 8MB LowMem window rapidly.
				var buf [32 * 1024]byte
				for {
					n, rerr := st.Read(buf[:])
					if n > 0 {
						srvResetAccepted.Add(int64(n))
					}
					if rerr != nil {
						return
					}
				}
			}, nil, nil)
		}
	}()

	var cli *RTCSession
	for attempt := 0; attempt < 3; attempt++ {
		ce := sw.NewClientEnd()
		cli, _, err = DialWithPacketConn(ctx, ce, true, sw.srvAddr, DialOptions{
			Host:     "127.0.0.1",
			Port:     21443,
			PSK:      psk,
			ClientID: [8]byte{7, 6, 5, 4, 3, 2, 1, 0},
			Timeout:  5 * time.Second,
		})
		if err == nil {
			break
		}
	}
	if err != nil {
		t.Fatalf("DialWithPacketConn under 25%% loss failed: %v", err)
	}
	defer cli.Close()

	if !cli.flowAcctV2.Load() || cli.peerSessMax.Load() < LowMemSessionMaxWindow {
		t.Fatalf("expected FlowAcctV2=true & LowMemSession window >=8MB, got v2=%v max=%d", cli.flowAcctV2.Load(), cli.peerSessMax.Load())
	}

	const totalStreams = 88
	const chunkPayload = 1024 * 1024 // ~60 full 1MB + ~28 RST partial streams => >64MB wire bytes under 8MB LowMem window
	const workers = 12
	jobs := make(chan int, totalStreams)
	for i := 0; i < totalStreams; i++ {
		jobs <- i
	}
	close(jobs)

	var totalSentBytes atomic.Int64
	var completedBytes atomic.Int64
	var rstCount atomic.Int64
	var wg sync.WaitGroup
	errCh := make(chan error, totalStreams)

	pattern := bytes.Repeat([]byte{0x5A, 0xA5, 0x3C, 0xC3}, 8*1024) // 32KB write block
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				st, serr := cli.OpenStream(fmt.Sprintf("stress-%d.example:443", idx), nil)
				if serr != nil {
					errCh <- fmt.Errorf("stream %d OpenStream: %w", idx, serr)
					return
				}
				abortEarly := (idx % 3) == 1 // ~33% streams randomly RST mid-transfer
				targetBytes := chunkPayload
				if abortEarly {
					targetBytes = 128*1024 + (idx%7)*48*1024
				}
				written := 0
				for written < targetBytes {
					step := len(pattern)
					if targetBytes-written < step {
						step = targetBytes - written
					}
					n, werr := st.Write(pattern[:step])
					written += n
					totalSentBytes.Add(int64(n))
					if werr != nil {
						errCh <- fmt.Errorf("stream %d Write: %w", idx, werr)
						_ = st.Close()
						return
					}
				}
				if abortEarly {
					rstCount.Add(1)
					_ = st.Close() // Triggers FrameStreamRSTFinal mid-flight!
				} else {
					_ = st.CloseWrite()
					// Wait for clean peer close after server drains FIN
					var tmp [16]byte
					_, _ = st.Read(tmp[:])
					_ = st.Close()
					completedBytes.Add(int64(written))
				}
			}
		}()
	}
	wg.Wait()
	close(errCh)

	for e := range errCh {
		t.Fatal(e)
	}
	select {
	case <-cli.Done():
		t.Fatalf("client session died unexpectedly during 64MB+ lossy RST stress test")
	default:
	}

	sentTotal := totalSentBytes.Load()
	if sentTotal <= 64*1024*1024 {
		t.Fatalf("expected >64MB transferred across 8MB LowMem window, got %.2f MB", float64(sentTotal)/(1024*1024))
	}

	// Wait briefly for in-flight sendQ / RSTFinal accounting to settle and confirm queued == stream bytes.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cli.txQueuedBytes.Load() == cli.txStreamBytes.Load() {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if cli.txQueuedBytes.Load() != cli.txStreamBytes.Load() {
		t.Fatalf("client txQueuedBytes (%d) != txStreamBytes (%d) after drain", cli.txQueuedBytes.Load(), cli.txStreamBytes.Load())
	}
	t.Logf("LowMem 22%% lossy >64MB RST stress PASSED: sent=%.2fMB completed=%.2fMB rstStreams=%d serverRead=%.2fMB peerMax=%d",
		float64(sentTotal)/(1024*1024),
		float64(completedBytes.Load())/(1024*1024),
		rstCount.Load(),
		float64(srvResetAccepted.Load())/(1024*1024),
		cli.peerSessMax.Load(),
	)
}

func TestLowMemLossyServerPushClientAbort100LoopsWindowConservation(t *testing.T) {
	origLowMem := IsLowMemMode()
	SetLowMemMode(true)
	t.Cleanup(func() { SetLowMemMode(origLowMem) })

	psk := make([]byte, 32)
	_, _ = rand.Read(psk)

	// 25% random packet loss + 2% reorder + 1% duplicate + 1ms path delay.
	sw := NewLossyUDPSwitch("127.0.0.1:21543", 25, 2, 1, time.Millisecond)
	defer sw.CloseAll()

	ln, err := NewListener(sw.srvConn, false, psk, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	var srvSessRef atomic.Pointer[RTCSession]
	srvDone := make(chan struct{})
	go func() {
		defer close(srvDone)
		srvSess, aerr := ln.Accept(ctx)
		if aerr != nil {
			return
		}
		srvSessRef.Store(srvSess)
		downPayload := bytes.Repeat([]byte{0xD4, 0x4D, 0x91, 0x19}, 8*1024) // 32KB chunk
		srvSess.SetHandlers(func(st *RTCStream, target string, first []byte) {
			defer st.Close()
			// Server pushes 256KB+ per stream so client aborts mid-download.
			for k := 0; k < 9; k++ {
				if _, werr := st.Write(downPayload); werr != nil {
					return
				}
			}
			_ = st.CloseWrite()
		}, nil, nil)
	}()

	var cli *RTCSession
	for attempt := 0; attempt < 4; attempt++ {
		ce := sw.NewClientEnd()
		cli, _, err = DialWithPacketConn(ctx, ce, true, sw.srvAddr, DialOptions{
			Host:     "127.0.0.1",
			Port:     21543,
			PSK:      psk,
			ClientID: [8]byte{9, 8, 7, 6, 5, 4, 3, 2},
			Timeout:  5 * time.Second,
		})
		if err == nil {
			break
		}
	}
	if err != nil {
		t.Fatalf("DialWithPacketConn failed under 25%% loss: %v", err)
	}
	defer cli.Close()

	<-srvDone
	srv := srvSessRef.Load()
	if srv == nil {
		t.Fatal("server session not accepted")
	}

	const iterations = 100
	var readBuf [16 * 1024]byte
	for i := 0; i < iterations; i++ {
		st, serr := cli.OpenStream(fmt.Sprintf("abort-down-%d.example:443", i), []byte("GET"))
		if serr != nil {
			t.Fatalf("iter %d OpenStream failed (window stalled?): %v", i, serr)
		}
		// Read partial server stream (~32KB..64KB), then actively abort mid-download!
		got := 0
		targetRead := 32*1024 + (i%3)*16*1024
		for got < targetRead {
			n, rerr := st.Read(readBuf[:])
			got += n
			if rerr != nil {
				break
			}
		}
		_ = st.Close()
	}

	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		cTx := cli.txStreamBytes.Load()
		sRx := srv.rxConsumedBytes.Load()
		sTx := srv.txStreamBytes.Load()
		cRx := cli.rxConsumedBytes.Load()
		cQ := cli.txQueuedBytes.Load()
		sQ := srv.txQueuedBytes.Load()
		if cTx == sRx && sTx == cRx && cTx == cQ && sTx == sQ {
			break
		}
		time.Sleep(30 * time.Millisecond)
	}

	if cli.txStreamBytes.Load() != srv.rxConsumedBytes.Load() {
		t.Fatalf("client->server byte conservation mismatch: cli.txStreamBytes=%d srv.rxConsumedBytes=%d",
			cli.txStreamBytes.Load(), srv.rxConsumedBytes.Load())
	}
	if srv.txStreamBytes.Load() != cli.rxConsumedBytes.Load() {
		t.Fatalf("server->client byte conservation mismatch (reverse RSTFinal missing?): srv.txStreamBytes=%d cli.rxConsumedBytes=%d",
			srv.txStreamBytes.Load(), cli.rxConsumedBytes.Load())
	}
	if cli.txQueuedBytes.Load() != cli.txStreamBytes.Load() || srv.txQueuedBytes.Load() != srv.txStreamBytes.Load() {
		t.Fatalf("txQueued leak detected: cliQ=%d cliTx=%d srvQ=%d srvTx=%d",
			cli.txQueuedBytes.Load(), cli.txStreamBytes.Load(), srv.txQueuedBytes.Load(), srv.txStreamBytes.Load())
	}
}

func TestStealthSTUNNoPrivateAttributesAndLegacyCompat(t *testing.T) {
	psk := make([]byte, 32)
	_, _ = rand.Read(psk)
	var cid [8]byte
	_, _ = rand.Read(cid[:])
	now := time.Now()

	// 1. New Stealth STUN Binding Request must NOT contain private 0xC057 attribute.
	reqPkt, cliPriv, txID, err := BuildClientBindingReq(psk, cid, 200, 0, now)
	if err != nil {
		t.Fatalf("BuildClientBindingReq failed: %v", err)
	}
	_, reqAttrs, ok := verifySTUNBaseAndFingerprint(reqPkt, stunTypeBindingReq)
	if !ok {
		t.Fatal("Stealth STUN request failed base/fingerprint validation")
	}
	if _, hasPriv := findSTUNAttr(reqAttrs, attrKSLTicket); hasPriv {
		t.Fatal("Stealth STUN request must NOT emit legacy private attribute 0xC057")
	}
	uVal, okU := findSTUNAttr(reqAttrs, attrUsername)
	if !okU || !strings.Contains(string(uVal), ":") {
		t.Fatalf("expected RFC 8445 USERNAME ufrag:ufrag in Stealth STUN request, got %q", string(uVal))
	}
	if macVal, okM := findSTUNAttr(reqAttrs, attrMsgIntegritySHA256); !okM || len(macVal) != FastMACLen {
		t.Fatalf("expected 16B MESSAGE-INTEGRITY-SHA256 in Stealth STUN request, ok=%v len=%d", okM, len(macVal))
	}

	guard := NewReplayGuard()
	parsed, ok := ParseClientBindingReq(reqPkt, psk, guard, now)
	if !ok || !parsed.StealthSTUN {
		t.Fatalf("ParseClientBindingReq failed or StealthSTUN=false: ok=%v parsed=%+v", ok, parsed)
	}

	// 2. Server response for Stealth STUN request must also omit 0xC057 and use NONCE (0x0015).
	respPkt, srvKeys, err := BuildServerBindingResp(psk, parsed, &net.UDPAddr{IP: net.IPv4(198, 51, 100, 2), Port: 44444}, 0x11223344, 150, 0, []byte(`{"v":4}`))
	if err != nil {
		t.Fatalf("BuildServerBindingResp failed: %v", err)
	}
	_, respAttrs, ok := verifySTUNBaseAndFingerprint(respPkt, stunTypeBindingResp)
	if !ok {
		t.Fatal("Stealth STUN response failed base/fingerprint validation")
	}
	if _, hasPriv := findSTUNAttr(respAttrs, attrKSLTicket); hasPriv {
		t.Fatal("Stealth STUN response must NOT emit legacy private attribute 0xC057")
	}
	if _, okN := findSTUNAttr(respAttrs, attrNonce); !okN {
		t.Fatal("Stealth STUN response missing standard NONCE (0x0015) attribute")
	}
	parsedResp, cliKeys, ok := ParseServerBindingResp(respPkt, psk, cliPriv, txID)
	if !ok || parsedResp.SessionSSRC != 0x11223344 || cliKeys.C2SMask != srvKeys.C2SMask {
		t.Fatalf("ParseServerBindingResp failed or key mismatch: ok=%v resp=%+v", ok, parsedResp)
	}

	// 3. Legacy v4.0-v4.2.1 0xC057 client still passes PreScreen + Parse + legacy server response.
	legReq, legPriv, legTxID, err := BuildClientBindingReqLegacyV4(psk, cid, 100, 0, now)
	if err != nil {
		t.Fatalf("BuildClientBindingReqLegacyV4 failed: %v", err)
	}
	if !PreScreenClientBindingReq(legReq, psk) {
		t.Fatal("legacy v4.x client failed PreScreenClientBindingReq")
	}
	legParsed, ok := ParseClientBindingReq(legReq, psk, guard, now)
	if !ok || legParsed.StealthSTUN {
		t.Fatalf("legacy v4.x ParseClientBindingReq mismatch: ok=%v stealth=%v", ok, legParsed != nil && legParsed.StealthSTUN)
	}
	legResp, legSrvKeys, err := BuildServerBindingResp(psk, legParsed, &net.UDPAddr{IP: net.IPv4(198, 51, 100, 3), Port: 55555}, 0x55667788, 100, 0, nil)
	if err != nil {
		t.Fatalf("legacy BuildServerBindingResp failed: %v", err)
	}
	legParsedResp, legCliKeys, ok := ParseServerBindingResp(legResp, psk, legPriv, legTxID)
	if !ok || legParsedResp.SessionSSRC != 0x55667788 || legCliKeys.C2SMask != legSrvKeys.C2SMask {
		t.Fatalf("legacy ParseServerBindingResp failed: ok=%v", ok)
	}
}
