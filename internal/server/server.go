package server

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/net/http2"

	"ghostframe/internal/gft"
	"ghostframe/internal/gftrtc"
)

// Version is the canonical server build identifier (overridable via -ldflags -X).
var Version = "v4.0.35-LTS"

const (
	MaxUDPAssocPerClient = 256
	maxUDPPerSession     = MaxUDPAssocPerClient
	udpDNSIdleTimeout    = 12 * time.Second
	udpIdleTimeout       = 90 * time.Second
	internalPanelHost    = "gft.internal.panel:80"
)

// Server is the GhostFrame v4.0.0-LTS Apex dual-stack server:
//   - TCP: 0ms Pre-TLS MirrorInspector -> TLS 1.3 + ClientAuth -> Ghost Frame v3 Mux
//     (probes/scanners are transparently mirrored to CamouflageTarget or fallback HTTP/H2)
//   - UDP: Kestrel-RTC (WebRTC STUN/SRTP mimicry + 0ms XOR-FEC + Smart-Brutal CC + 0ms migration)
type Server struct {
	cfg           *Config
	psk           []byte
	stego         *gft.StegoVerifier
	verifier      *gft.KnockVerifier
	outbound      *FastOutbound
	params        *gft.ParamStore
	audit         *Audit
	stats         *Stats
	panel         *Panel
	web           http.Handler
	fallback      *chanListener
	panelListener *chanListener
	started       time.Time

	testUDPPC net.PacketConn // optional injection for tests
	cfgMu     sync.RWMutex
	cfgPath   string
	rtcActive atomic.Int64
	tcpAddrMu sync.RWMutex
	tcpAddr   net.Addr
	udpAddr   net.Addr

	smu       sync.Mutex
	sessions  map[uint64]*sessEntry
	nextSess  atomic.Uint64
	udpMgrMu  sync.Mutex
	udpMgrs   map[[8]byte]*udpManager
	bondMgrMu sync.Mutex
	bondMgrs  map[[8]byte]*gft.BondGroup
	logger    *log.Logger
}

// SetConfigPath records the path of the active server.json so web panel
// updates to Kestrel-RTC settings can be atomically persisted to disk.
func (s *Server) SetConfigPath(path string) {
	s.cfgMu.Lock()
	s.cfgPath = path
	s.cfgMu.Unlock()
}

type sessEntry struct {
	ID    uint64
	IP    string
	Since time.Time
	Sess  *gft.Session
}

func New(cfg *Config, logger *log.Logger) (*Server, error) {
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}
	psk, err := base64.StdEncoding.DecodeString(cfg.PSK)
	if err != nil || len(psk) < 16 {
		return nil, errors.New("bad psk in config")
	}
	s := &Server{
		cfg:      cfg,
		psk:      psk,
		stego:    gft.NewStegoVerifier(psk),
		verifier: gft.NewKnockVerifier(psk),
		outbound: NewFastOutbound(),
		sessions: map[uint64]*sessEntry{},
		udpMgrs:  map[[8]byte]*udpManager{},
		bondMgrs: map[[8]byte]*gft.BondGroup{},
		started:  time.Now(),
		logger:   logger,
	}
	s.params = gft.NewParamStore(s.loadParams())
	s.outbound.SetDisableIPv6(cfg.DisableIPv6)
	s.audit = NewAudit(filepath.Join(cfg.StateDir, "audit.json"))
	s.stats = NewStats()
	s.fallback = newChanListener()
	s.panelListener = newChanListener()
	s.panel = newPanel(s)
	s.web = s.buildRouter()
	return s, nil
}

// TCPAddr returns the active TCP listen address once Run has started.
func (s *Server) TCPAddr() net.Addr {
	s.tcpAddrMu.RLock()
	defer s.tcpAddrMu.RUnlock()
	return s.tcpAddr
}

// UDPAddr returns the active Kestrel-RTC UDP listen address once Run has started (nil if disabled).
func (s *Server) UDPAddr() net.Addr {
	s.tcpAddrMu.RLock()
	defer s.tcpAddrMu.RUnlock()
	return s.udpAddr
}

// SetTestUDPConn injects a custom net.PacketConn for Kestrel-RTC unit tests.
func (s *Server) SetTestUDPConn(pc net.PacketConn) {
	s.testUDPPC = pc
}

func (s *Server) buildFallbackHandler() http.Handler {
	if strings.EqualFold(s.cfg.FallbackMode, "reverse_proxy") && s.cfg.FallbackTarget != "" {
		if u, err := url.Parse(s.cfg.FallbackTarget); err == nil && u.Scheme != "" && u.Host != "" {
			rp := httputil.NewSingleHostReverseProxy(u)
			origDirector := rp.Director
			rp.Director = func(req *http.Request) {
				origHost := req.Host
				origDirector(req)
				if origHost != "" {
					req.Host = origHost
				}
			}
			rp.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, _ error) {
				http.Error(w, "Bad Gateway", http.StatusBadGateway)
			}
			return rp
		}
	}
	return blogHandler()
}

func (s *Server) loadParams() gft.Params {
	p := gft.DefaultParams()
	if s.cfg.Params != nil && s.cfg.Params.Validate() == nil {
		p = *s.cfg.Params
	}
	if b, err := os.ReadFile(filepath.Join(s.cfg.StateDir, "params.json")); err == nil {
		var q gft.Params
		if json.Unmarshal(b, &q) == nil && q.Validate() == nil {
			p = q
		}
	}
	return p
}

// RuntimeSnapshot captures live telemetry persisted periodically for CLI/TUI dashboards.
type RuntimeSnapshot struct {
	UpdatedAt    int64  `json:"updated_at"`
	TotalUp      uint64 `json:"total_up"`
	TotalDown    uint64 `json:"total_down"`
	UpBps        uint64 `json:"up_bps"`
	DownBps      uint64 `json:"down_bps"`
	Sessions     int    `json:"sessions"`
	BlockedCount int    `json:"blocked_count"`
}

func (s *Server) writeRuntimeSnapshot() {
	if s.cfg.StateDir == "" {
		return
	}
	st := s.stats.Snapshot()
	s.smu.Lock()
	sc := len(s.sessions)
	s.smu.Unlock()
	snap := RuntimeSnapshot{
		UpdatedAt:    time.Now().Unix(),
		TotalUp:      st.UpTotal,
		TotalDown:    st.DownTotal,
		UpBps:        st.UpRate,
		DownBps:      st.DownRate,
		Sessions:     sc,
		BlockedCount: len(s.audit.List()),
	}
	b, _ := json.Marshal(snap)
	_ = os.WriteFile(filepath.Join(s.cfg.StateDir, "stats.json"), b, 0o600)
}

func (s *Server) saveParams(p gft.Params) {
	b, _ := json.Marshal(p)
	_ = os.WriteFile(filepath.Join(s.cfg.StateDir, "params.json"), b, 0o600)
}

type certReloader struct {
	certFile string
	keyFile  string
	mu       sync.Mutex
	modTime  time.Time
	cert     atomic.Pointer[tls.Certificate]
}

func newCertReloader(certFile, keyFile string) (*certReloader, error) {
	r := &certReloader{certFile: certFile, keyFile: keyFile}
	if err := r.reloadIfChanged(true); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *certReloader) reloadIfChanged(force bool) error {
	st, err := os.Stat(r.certFile)
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !force && !st.ModTime().After(r.modTime) {
		return nil
	}
	cert, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		return err
	}
	r.cert.Store(&cert)
	r.modTime = st.ModTime()
	return nil
}

func (r *certReloader) getCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	c := r.cert.Load()
	if c == nil {
		return nil, errors.New("no certificate loaded")
	}
	return c, nil
}

func (s *Server) buildTLSConfig(ctx context.Context) (*tls.Config, error) {
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"h2", "http/1.1"},
	}
	gft.OptimizeTLSConfigForHardware(tlsCfg)
	switch strings.ToLower(s.cfg.CertMode) {
	case "acme":
		domains := s.cfg.ACMEDomains
		if len(domains) == 0 && s.cfg.SNI != "" {
			domains = []string{s.cfg.SNI}
		}
		cacheDir := s.cfg.ACMECacheDir
		if cacheDir == "" {
			cacheDir = filepath.Join(s.cfg.StateDir, "acme")
		}
		mgr := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			Cache:      autocert.DirCache(cacheDir),
			HostPolicy: autocert.HostWhitelist(domains...),
			Email:      s.cfg.ACMEEmail,
		}
		tlsCfg.GetCertificate = mgr.GetCertificate
		return tlsCfg, nil
	default: // "file" or "self_signed_90d"
		reloader, err := newCertReloader(s.cfg.CertFile, s.cfg.KeyFile)
		if err != nil {
			return nil, err
		}
		tlsCfg.GetCertificate = reloader.getCertificate
		go func() {
			t := time.NewTicker(5 * time.Minute)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					_ = reloader.reloadIfChanged(false)
				}
			}
		}()
		return tlsCfg, nil
	}
}

// Run serves dual-stack TCP (:443) and QUIC UDP (:443) until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	tlsCfg, err := s.buildTLSConfig(ctx)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		return err
	}
	s.tcpAddrMu.Lock()
	s.tcpAddr = ln.Addr()
	s.tcpAddrMu.Unlock()

	// Optional Kestrel-RTC listener on matching UDP port (unless DisableRTC/DisableQUIC).
	var rtcLn *gftrtc.RTCListener
	var rawUDP net.PacketConn
	if !s.cfg.IsRTCDisabled() {
		pc := s.testUDPPC
		if pc == nil {
			udpBind := s.cfg.Listen
			if _, _, err := net.SplitHostPort(ln.Addr().String()); err == nil {
				if ta, ok := ln.Addr().(*net.TCPAddr); ok {
					cfgHost, cfgPort, _ := net.SplitHostPort(s.cfg.Listen)
					if cfgPort == "0" {
						udpBind = net.JoinHostPort(cfgHost, strconv.Itoa(ta.Port))
					}
				}
			}
			pc, err = net.ListenPacket("udp", udpBind)
			if err != nil {
				_ = ln.Close()
				return err
			}
			gftrtc.TuneUDPSocketBuffers(pc)
		}
		rawUDP = pc
		s.tcpAddrMu.Lock()
		s.udpAddr = pc.LocalAddr()
		s.tcpAddrMu.Unlock()

		rtcLn, err = gftrtc.NewListener(pc, s.testUDPPC == nil, s.psk, s.cfg.TxMbps, gft.MarshalParams(s.params.Get()))
		if err != nil {
			if s.testUDPPC == nil {
				_ = pc.Close()
			}
			_ = ln.Close()
			return err
		}
	}

	s.logger.Printf("Kestrel %s Apex listening tcp=%s rtc=%v (cert=%s fallback=%s target=%s)",
		Version, ln.Addr(), rtcLn != nil, s.cfg.CertMode, s.cfg.FallbackMode, s.cfg.CamouflageTarget)

	// Public HTTP/1.1 fallback server (reverse_proxy or builtin_blog)
	hs := &http.Server{
		Handler:           s.web,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       60 * time.Second,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	// Internal tunnel-only management panel server ("gft.internal.panel:80")
	panelSrv := &http.Server{
		Handler:           s.web,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       60 * time.Second,
		ErrorLog:          log.New(io.Discard, "", 0),
	}

	var wg sync.WaitGroup
	wg.Add(4)
	go func() { defer wg.Done(); _ = hs.Serve(s.fallback) }()
	go func() { defer wg.Done(); _ = panelSrv.Serve(s.panelListener) }()
	go func() {
		defer wg.Done()
		t := time.NewTicker(time.Second)
		defer t.Stop()
		n := 0
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.stats.Sample()
				n++
				if n%3 == 0 {
					s.writeRuntimeSnapshot()
				}
				if n%30 == 0 {
					s.verifier.Sweep(time.Now())
					s.audit.Flush()
					s.panel.sweep()
					s.sweepUDPMgrs(10 * time.Minute)
				}
			}
		}
	}()
	go func() {
		defer wg.Done()
		<-ctx.Done()
		_ = ln.Close()
		if rtcLn != nil {
			_ = rtcLn.Close()
		}
		if rawUDP != nil && s.testUDPPC == nil {
			_ = rawUDP.Close()
		}
		shutCtx, shutCancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = hs.Shutdown(shutCtx)
		_ = panelSrv.Shutdown(shutCtx)
		shutCancel()
		_ = hs.Close()
		_ = panelSrv.Close()
		s.fallback.Close()
		s.panelListener.Close()
		s.closeAllSessions()
	}()

	if rtcLn != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				rs, err := rtcLn.Accept(ctx)
				if err != nil {
					return
				}
				go s.serveRTC(ctx, rs)
			}
		}()
	}

	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				break
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}
		if tcpC, ok := c.(*net.TCPConn); ok {
			_ = tcpC.SetNoDelay(true)
		}
		go s.handleTCP(ctx, c, tlsCfg)
	}
	wg.Wait()
	s.audit.Flush()
	return nil
}

func (s *Server) serveRTC(ctx context.Context, rs *gftrtc.RTCSession) {
	s.rtcActive.Add(1)
	defer s.rtcActive.Add(-1)
	cid := rs.ClientID()
	s.logger.Printf("rtc session opened ssrc=%08x cipher=%s", rs.SSRC(), rs.Stats().Cipher)
	rs.SetOnBytes(s.stats.Add)
	mgr, shared := s.getOrCreateUDPManager(cid, rs)

	rs.SetHandlers(
		func(st *gftrtc.RTCStream, target string, first []byte) {
			s.handleDataStream(st, target, first)
		},
		func(sink gft.UDPReplySink, id uint16, target string, data []byte) {
			mgr.handleDatagramSink(sink, id, target, data)
		},
		func(_ gft.UDPReplySink, id uint16) {
			mgr.handleClose(id)
		},
	)

	select {
	case <-rs.Done():
	case <-ctx.Done():
		rs.Close()
	}
	if !shared {
		mgr.closeAll()
	}
}

func (s *Server) getOrCreateUDPManager(clientID [8]byte, fallbackSink gft.UDPReplySink) (*udpManager, bool) {
	if clientID == ([8]byte{}) {
		return newUDPManager(fallbackSink, true, s.outbound, s.logger), false
	}
	s.udpMgrMu.Lock()
	defer s.udpMgrMu.Unlock()
	m, ok := s.udpMgrs[clientID]
	if !ok {
		m = newUDPManager(fallbackSink, false, s.outbound, s.logger)
		s.udpMgrs[clientID] = m
	} else {
		m.lastUsed.Store(time.Now().UnixNano())
	}
	return m, true
}

func (s *Server) sweepUDPMgrs(idleTTL time.Duration) {
	cutoff := time.Now().Add(-idleTTL).UnixNano()
	var expired []*udpManager
	s.udpMgrMu.Lock()
	for k, m := range s.udpMgrs {
		if m.lastUsed.Load() < cutoff {
			expired = append(expired, m)
			delete(s.udpMgrs, k)
		}
	}
	s.udpMgrMu.Unlock()
	for _, m := range expired {
		m.closeAll()
	}
}

func (s *Server) closeAllSessions() {
	s.smu.Lock()
	for _, e := range s.sessions {
		e.Sess.Close()
	}
	s.smu.Unlock()
	s.udpMgrMu.Lock()
	for k, m := range s.udpMgrs {
		delete(s.udpMgrs, k)
		m.closeAll()
	}
	s.udpMgrMu.Unlock()
	s.bondMgrMu.Lock()
	for k, bg := range s.bondMgrs {
		delete(s.bondMgrs, k)
		bg.CloseAll(gft.ErrSessionClosed)
	}
	s.bondMgrMu.Unlock()
}

func (s *Server) attachBondSession(clientID [8]byte, sess *gft.Session) *gft.BondGroup {
	if clientID == ([8]byte{}) || sess == nil {
		return nil
	}
	s.bondMgrMu.Lock()
	bg, ok := s.bondMgrs[clientID]
	if !ok {
		bg = gft.NewBondGroup(func(st gft.DataStream, target string, first []byte) {
			s.handleDataStream(st, target, first)
		})
		s.bondMgrs[clientID] = bg
	}
	bg.AddSession(sess)
	s.bondMgrMu.Unlock()
	return bg
}

func (s *Server) releaseBondSession(clientID [8]byte, bg *gft.BondGroup, sess *gft.Session) {
	if bg == nil || sess == nil {
		return
	}
	rem := bg.RemoveSession(sess, true)
	if rem == 0 {
		s.bondMgrMu.Lock()
		if cur := s.bondMgrs[clientID]; cur == bg {
			if bg.NumStreams() == 0 {
				delete(s.bondMgrs, clientID)
			}
		}
		s.bondMgrMu.Unlock()
	}
}

func addrIP(a net.Addr) string {
	h, _, err := net.SplitHostPort(a.String())
	if err != nil {
		return a.String()
	}
	return h
}

func (s *Server) handleTCP(ctx context.Context, raw net.Conn, tlsCfg *tls.Config) {
	ip := addrIP(raw.RemoteAddr())
	if s.audit.IsBanned(ip) {
		_ = raw.Close()
		return
	}

	// Pre-TLS zero-characteristic inspection (0ms RewindConn)
	rc := gft.NewRewindConn(raw)
	if !gft.MirrorInspector(rc, s.stego) {
		s.audit.Record(ip, "pre_tls_probe")
		if strings.EqualFold(s.cfg.FallbackMode, "mirror") && s.cfg.CamouflageTarget != "" {
			s.logger.Printf("pre-tls fail ip=%s -> transparent mirror %s", ip, s.cfg.CamouflageTarget)
			s.mirrorBridge(rc, s.cfg.CamouflageTarget)
			return
		}
		s.logger.Printf("pre-tls fail ip=%s -> local tls fallback", ip)
		tc := tls.Server(rc, tlsCfg)
		_ = tc.SetDeadline(time.Now().Add(10 * time.Second))
		if err := tc.HandshakeContext(ctx); err != nil {
			_ = raw.Close()
			return
		}
		_ = tc.SetDeadline(time.Time{})
		s.serveHTTPFallback(ctx, tc)
		return
	}

	// Validated stego ClientHello -> proceed to TLS 1.3 handshake
	tc := tls.Server(rc, tlsCfg)
	_ = tc.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tc.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return
	}
	_ = tc.SetDeadline(time.Time{})

	// Post-TLS ClientAuthFrame verification (defense-in-depth)
	authRC := gft.NewRewindConn(tc)
	if salt, clientID, err := s.stego.VerifyClientAuthFrameWithID(authRC); err == nil {
		authRC.StopRecording()
		ack, aerr := gft.BuildServerAuthAck(s.psk, salt, s.params.Get())
		if aerr == nil {
			_, _ = authRC.Write(ack)
		}
		s.serveTCPSession(ctx, authRC, ip, clientID)
		return
	}

	// Backwards-compatible fallback to v2 Knock if someone speaks v2 after stego hello
	authRC.Rewind()
	salt2, _, res := s.verifier.VerifyFirstRead(authRC, time.Now())
	if res != gft.KnockOK {
		s.audit.Record(ip, res.String())
		_ = authRC.SetReadDeadline(time.Time{})
		authRC.Rewind()
		s.serveHTTPFallback(ctx, &tlsRewindConn{Conn: authRC, proto: tc.ConnectionState().NegotiatedProtocol})
		return
	}
	ack, err := gft.BuildServerAck(s.psk, salt2, s.params.Get())
	if err == nil {
		_, _ = authRC.Write(ack)
	}
	s.serveTCPSession(ctx, authRC, ip, [8]byte{})
}

type tlsRewindConn struct {
	net.Conn
	proto string
}

func (s *Server) serveHTTPFallback(ctx context.Context, conn net.Conn) {
	proto := ""
	if tc, ok := conn.(*tls.Conn); ok {
		proto = tc.ConnectionState().NegotiatedProtocol
	} else if trc, ok := conn.(*tlsRewindConn); ok {
		proto = trc.proto
	}
	if proto == "h2" {
		h2srv := &http2.Server{}
		h2srv.ServeConn(conn, &http2.ServeConnOpts{
			Context: ctx,
			Handler: s.web,
		})
		_ = conn.Close()
		return
	}
	if !s.fallback.push(conn) {
		_ = conn.Close()
	}
}

func (s *Server) mirrorBridge(clientConn net.Conn, target string) {
	defer clientConn.Close()
	d := net.Dialer{Timeout: 6 * time.Second}
	upstream, err := d.Dial("tcp", target)
	if err != nil {
		return
	}
	defer upstream.Close()
	if tc, ok := upstream.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(upstream, clientConn)
		if cw, ok := upstream.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(clientConn, upstream)
		if cw, ok := clientConn.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()
	wg.Wait()
}

func (s *Server) serveTCPSession(_ context.Context, conn net.Conn, ip string, clientID [8]byte) {
	sess := gft.NewSession(conn, false, s.params, func(st *gft.Stream, target string, first []byte) {
		s.handleDataStream(st, target, first)
	})
	sess.OnBytes = s.stats.Add

	udpMgr, shared := s.getOrCreateUDPManager(clientID, sess)
	sess.SetUDPHandler(func(_ *gft.Session, id uint16, target string, data []byte) {
		udpMgr.handleDatagramSink(sess, id, target, data)
	}, func(_ *gft.Session, id uint16) {
		udpMgr.handleClose(id)
	})
	if bondGrp := s.attachBondSession(clientID, sess); bondGrp != nil {
		defer s.releaseBondSession(clientID, bondGrp, sess)
		_ = sess.SendBondCap()
	}

	id := s.nextSess.Add(1)
	s.smu.Lock()
	s.sessions[id] = &sessEntry{ID: id, IP: ip, Since: time.Now(), Sess: sess}
	s.smu.Unlock()
	s.logger.Printf("tcp session %d opened from %s", id, ip)
	_ = sess.Run()
	if !shared {
		udpMgr.closeAll()
	}
	sess.Close()
	s.smu.Lock()
	delete(s.sessions, id)
	s.smu.Unlock()
	s.logger.Printf("tcp session %d closed", id)
}

var errBlockedTarget = errors.New("blocked target")

// AllowPrivateTargets disables the loopback/private-address egress block (tests only).
var AllowPrivateTargets bool

func blockedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified() || ip.IsMulticast() {
		return true
	}
	if ip4 := ip.To4(); ip4 != nil {
		// Block RFC 2544 benchmark / client Fake-IP (198.18.0.0/15) & RFC 6598 CGNAT (100.64.0.0/10).
		if ip4[0] == 198 && (ip4[1]&0xfe) == 18 {
			return true
		}
		if ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127 {
			return true
		}
	}
	return false
}

func (s *Server) handleDataStream(st gft.DataStream, target string, first []byte) {
	if strings.EqualFold(target, internalPanelHost) {
		c := newStreamNetConn(st, first)
		if !s.panelListener.push(c) {
			_ = c.Close()
		}
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	c, err := s.outbound.DialTCP(ctx, target)
	cancel()
	if err != nil {
		s.logger.Printf("handleConnect dial %s failed: %v", target, err)
		_ = st.Close()
		return
	}
	if len(first) > 0 {
		if _, err := c.Write(first); err != nil {
			_ = c.Close()
			_ = st.Close()
			return
		}
	}
	gft.Relay(st, c, 15*time.Minute)
}

// streamNetConn wraps a DataStream (plus optional 0-RTT initial bytes) as net.Conn
// so internal HTTP requests (e.g. gft.internal.panel:80) run through standard http.Server.
type streamNetConn struct {
	st    gft.DataStream
	first []byte
	off   int
}

func newStreamNetConn(st gft.DataStream, first []byte) *streamNetConn {
	return &streamNetConn{st: st, first: first}
}

func (c *streamNetConn) Read(p []byte) (int, error) {
	if c.off < len(c.first) {
		n := copy(p, c.first[c.off:])
		c.off += n
		if c.off >= len(c.first) {
			c.first = nil
		}
		return n, nil
	}
	return c.st.Read(p)
}

func (c *streamNetConn) Write(p []byte) (int, error)        { return c.st.Write(p) }
func (c *streamNetConn) Close() error                       { return c.st.Close() }
func (c *streamNetConn) LocalAddr() net.Addr                { return dummyAddr{} }
func (c *streamNetConn) RemoteAddr() net.Addr               { return dummyAddr{} }
func (c *streamNetConn) SetDeadline(t time.Time) error      { return nil }
func (c *streamNetConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *streamNetConn) SetWriteDeadline(t time.Time) error { return nil }

// ---- fallback listener --------------------------------------------------------

type chanListener struct {
	ch   chan net.Conn
	done chan struct{}
	once sync.Once
}

func newChanListener() *chanListener {
	return &chanListener{ch: make(chan net.Conn, 256), done: make(chan struct{})}
}

func (l *chanListener) push(c net.Conn) bool {
	select {
	case l.ch <- c:
		return true
	default:
		return false
	}
}

func (l *chanListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *chanListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

type dummyAddr struct{}

func (dummyAddr) Network() string { return "tcp" }
func (dummyAddr) String() string  { return "fallback" }

func (l *chanListener) Addr() net.Addr { return dummyAddr{} }
