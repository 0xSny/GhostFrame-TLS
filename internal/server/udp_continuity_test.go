package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ghostframe/internal/gft"
	"ghostframe/internal/gftrtc"
)

// udpSwitchAddr implements net.Addr for virtual multi-client packet switches.
type udpSwitchAddr string

func (a udpSwitchAddr) Network() string { return "udp" }
func (a udpSwitchAddr) String() string  { return string(a) }

type switchPkt struct {
	data []byte
	from net.Addr
}

// virtualUDPSwitch routes UDP packets between one hub PacketConn and many
// ephemeral endpoints on distinct ports, immune to Windows host WFP loopback drops.
type virtualUDPSwitch struct {
	srvAddr udpSwitchAddr
	srvConn *switchEnd

	mu       sync.RWMutex
	clients  map[string]*switchEnd
	nextPort atomic.Int32
}

func newVirtualUDPSwitch(hubAddr string, startPort int32) *virtualUDPSwitch {
	sw := &virtualUDPSwitch{
		srvAddr: udpSwitchAddr(hubAddr),
		clients: make(map[string]*switchEnd),
	}
	sw.nextPort.Store(startPort)
	sw.srvConn = &switchEnd{
		sw:     sw,
		addr:   sw.srvAddr,
		isSrv:  true,
		recv:   make(chan switchPkt, 1024),
		closed: make(chan struct{}),
	}
	return sw
}

func (sw *virtualUDPSwitch) newClientEnd() *switchEnd {
	p := sw.nextPort.Add(1)
	addr := udpSwitchAddr(fmt.Sprintf("127.0.0.1:%d", p))
	ce := &switchEnd{
		sw:     sw,
		addr:   addr,
		recv:   make(chan switchPkt, 512),
		closed: make(chan struct{}),
	}
	sw.mu.Lock()
	sw.clients[string(addr)] = ce
	sw.mu.Unlock()
	return ce
}

func (sw *virtualUDPSwitch) closeClients() {
	sw.mu.RLock()
	list := make([]*switchEnd, 0, len(sw.clients))
	for _, ce := range sw.clients {
		list = append(list, ce)
	}
	sw.mu.RUnlock()
	for _, ce := range list {
		_ = ce.Close()
	}
}

func (sw *virtualUDPSwitch) closeAll() {
	sw.srvConn.Close()
	sw.mu.Lock()
	for _, ce := range sw.clients {
		_ = ce.Close()
	}
	sw.mu.Unlock()
}

type switchEnd struct {
	sw     *virtualUDPSwitch
	addr   udpSwitchAddr
	isSrv  bool
	recv   chan switchPkt
	closed chan struct{}
	once   sync.Once
	mu     sync.Mutex
	rDead  time.Time
}

func (e *switchEnd) ReadFrom(p []byte) (int, net.Addr, error) {
	e.mu.Lock()
	dl := e.rDead
	e.mu.Unlock()
	var timer <-chan time.Time
	if !dl.IsZero() {
		d := time.Until(dl)
		if d <= 0 {
			return 0, nil, net.ErrClosed
		}
		t := time.NewTimer(d)
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

func (e *switchEnd) WriteTo(p []byte, dst net.Addr) (int, error) {
	select {
	case <-e.closed:
		return 0, net.ErrClosed
	default:
	}
	cp := make([]byte, len(p))
	copy(cp, p)
	var target *switchEnd
	if e.isSrv {
		e.sw.mu.RLock()
		target = e.sw.clients[dst.String()]
		e.sw.mu.RUnlock()
	} else {
		target = e.sw.srvConn
	}
	if target != nil {
		select {
		case target.recv <- switchPkt{data: cp, from: e.addr}:
		default:
		}
	}
	return len(p), nil
}

func (e *switchEnd) Close() error {
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

func (e *switchEnd) LocalAddr() net.Addr                { return e.addr }
func (e *switchEnd) SetDeadline(t time.Time) error      { return e.SetReadDeadline(t) }
func (e *switchEnd) SetWriteDeadline(t time.Time) error { return nil }
func (e *switchEnd) SetReadDeadline(t time.Time) error {
	e.mu.Lock()
	e.rDead = t
	e.mu.Unlock()
	return nil
}

// TestPortHoppingSeamlessUDPContinuity verifies that during rapid QUIC dynamic
// port hops (3+ migrations) followed by an abrupt UDP blackout failover to TCP-uTLS:
//  1. A continuous UDP flow experiences 0 dropped packets across all hops & failover.
//  2. The server preserves the exact same outbound NAT UDP socket/port throughout,
//     identified across distinct QUIC and TCP sessions via ClientID.
func TestPortHoppingSeamlessUDPContinuity(t *testing.T) {
	prevAllow := AllowPrivateTargets
	AllowPrivateTargets = true
	defer func() { AllowPrivateTargets = prevAllow }()

	sw := newVirtualUDPSwitch("127.0.0.1:8443", 31000)
	defer sw.closeAll()

	dir := t.TempDir()
	opts := InitOptions{
		ConfDir:  filepath.Join(dir, "conf"),
		StateDir: filepath.Join(dir, "state"),
		Host:     "127.0.0.1",
		SNI:      "ftp.jaist.ac.jp",
		Listen:   "127.0.0.1:0",
		CertMode: "self_signed_90d",
	}
	sec, err := InitWithOptions(opts)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(filepath.Join(opts.ConfDir, "server.json"))
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(cfg, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	srv.SetTestUDPConn(sw.srvConn)

	// Set up the UDP echo target (real OS loopback on Linux/macOS; in-memory port-tracking
	// switch on Windows to bypass host WFP/TUN loopback UDP filtering while still issuing
	// a unique ephemeral port per ListenPacket call).
	var echoPC net.PacketConn
	var echoAddr string
	if runtime.GOOS == "windows" {
		echoHub := newVirtualUDPSwitch("127.0.0.1:5353", 41000)
		defer echoHub.closeAll()
		echoPC = echoHub.srvConn
		echoAddr = "127.0.0.1:5353"
		srv.outbound.listenPacket = func(_, _ string) (net.PacketConn, error) {
			return echoHub.newClientEnd(), nil
		}
	} else {
		echoPC, err = net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer echoPC.Close()
		echoAddr = echoPC.LocalAddr().String()
	}

	var echoMu sync.Mutex
	seenSrcPorts := make(map[string]int)
	go func() {
		buf := make([]byte, 8192)
		for {
			n, from, err := echoPC.ReadFrom(buf)
			if err != nil {
				return
			}
			echoMu.Lock()
			seenSrcPorts[from.String()]++
			echoMu.Unlock()
			_, _ = echoPC.WriteTo(buf[:n], from)
		}
	}()

	runCtx, runCancel := context.WithCancel(context.Background())
	srvDone := make(chan struct{})
	go func() {
		defer close(srvDone)
		_ = srv.Run(runCtx)
	}()
	defer func() {
		runCancel()
		<-srvDone
	}()
	tcpAddr := waitForTCPAddr(t, srv)
	_ = os.ErrNotExist

	link, err := gft.ParseLink(sec.Link)
	if err != nil {
		t.Fatal(err)
	}
	_, tcpPortStr, _ := net.SplitHostPort(tcpAddr)
	link.Port, _ = strconv.Atoi(tcpPortStr)
	link.Transport = "auto"
	link.HopRange = "20000-20020"

	ps := gft.NewParamStore(gft.DefaultParams())
	sched := gft.NewApexScheduler(link, ps, 2, nil)
	sched.SetDialJitterForTest(0, 0, 100)
	sched.SetHopTimingsForTest(160*time.Millisecond, 160*time.Millisecond, 600*time.Millisecond, 25*time.Millisecond)

	var rtcDialCount atomic.Int32
	var rtcHopCount atomic.Int32
	var forceUDPBlackout atomic.Bool
	sched.SetRTCDialHookForTest(func(ctx context.Context, dl *gft.Link, dps *gft.ParamStore, hopPort int, timeout time.Duration, clientID [8]byte) (*gftrtc.RTCSession, time.Duration, error) {
		rtcDialCount.Add(1)
		if forceUDPBlackout.Load() {
			return nil, 0, errors.New("simulated udp blackout")
		}
		ce := sw.newClientEnd()
		rs, hs, err := gft.DialRTCWithPacketConnAndID(ctx, ce, true, sw.srvAddr, hopPort, dl, dps, timeout, clientID)
		if err != nil {
			_ = ce.Close()
			return nil, 0, err
		}
		return rs, hs, nil
	})
	sched.SetRTCHopHookForTest(func(sess *gftrtc.RTCSession, nextPort int) error {
		rtcHopCount.Add(1)
		if forceUDPBlackout.Load() {
			return errors.New("simulated udp blackout")
		}
		return sess.HopWithPacketConn(sw.newClientEnd(), true, sw.srvAddr, nextPort)
	})

	if err := sched.Start(4 * time.Second); err != nil {
		t.Fatalf("scheduler start failed: %v", err)
	}
	defer sched.Close()

	udpAssoc, err := sched.OpenUDP()
	if err != nil {
		t.Fatalf("OpenUDP failed: %v", err)
	}
	defer udpAssoc.Close()

	sendSeq := 0
	sendAndVerify := func(phase string, count int, gap time.Duration) {
		for i := 0; i < count; i++ {
			sendSeq++
			msg := fmt.Sprintf("pkt-%s-%03d", phase, sendSeq)
			if err := udpAssoc.SendTo(echoAddr, []byte(msg)); err != nil {
				t.Fatalf("phase=%s SendTo(%s) failed: %v", phase, msg, err)
			}
			select {
			case pkt := <-udpAssoc.Recv():
				if string(pkt.Data) != msg {
					t.Fatalf("phase=%s echo mismatch: got %q want %q", phase, pkt.Data, msg)
				}
			case <-time.After(2500 * time.Millisecond):
				t.Fatalf("phase=%s timeout waiting for %q (rtcDials=%d rtcHops=%d)", phase, msg, rtcDialCount.Load(), rtcHopCount.Load())
			}
			if gap > 0 {
				time.Sleep(gap)
			}
		}
	}

	// Phase 1: ~900ms over GFT-RTC spanning >= 3 dynamic 0ms socket hops (160ms hop interval).
	sendAndVerify("rtc-hop", 24, 38*time.Millisecond)

	if hops := rtcHopCount.Load(); hops < 3 {
		t.Fatalf("expected >= 3 0ms RTC socket hops during phase 1, got %d", hops)
	}

	// Phase 2: force sudden UDP blackout (close active RTC client sockets + block new RTC dials)
	// so scheduler triggers 0ms failover to TCP-uTLS.
	forceUDPBlackout.Store(true)
	sw.closeClients()
	time.Sleep(100 * time.Millisecond)

	sendAndVerify("tcp-failover", 12, 35*time.Millisecond)

	if mode := sched.Stats().Mode; mode != "TCP-Fallback" {
		t.Fatalf("expected TCP-Fallback mode after UDP blackout, got %s", mode)
	}

	echoMu.Lock()
	srcCount := len(seenSrcPorts)
	portsCopy := make(map[string]int, len(seenSrcPorts))
	for k, v := range seenSrcPorts {
		portsCopy[k] = v
	}
	echoMu.Unlock()

	if srcCount != 1 {
		t.Fatalf("expected server to preserve 1 identical outbound UDP NAT source port across hops+failover, saw %d: %v", srcCount, portsCopy)
	}
	totalEchoed := 0
	for _, c := range portsCopy {
		totalEchoed += c
	}
	if totalEchoed != 36 {
		t.Fatalf("expected 36 delivered UDP packets with 0 loss, got %d", totalEchoed)
	}
}
